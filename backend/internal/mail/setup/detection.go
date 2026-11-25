package setup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"sort"
	"strings"
	"sync"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

type Options struct {
	Detector   detect.Source
	Cloudflare CloudflareClient
	// Directory reads what the sealed Cloudflare token can see (sign-in).
	Directory CloudDirectory
	Relay     Relay
	MailPlus  MailPlus
	Verifier  Verifier
	Timeout   time.Duration // whole read-only detection deadline, at most DetectBudget
	// Background runs detection and plan preparation under the worker's
	// lifetime (canceled on stop or when nobody polls). nil: untracked.
	Background *core.Background
	// Inbound is the mailbox sync of receiving through Cloudflare (whole
	// domain or per address). nil: only the per-address mode, no sync token.
	Inbound InboundSync
}

// DetectBudget bounds one read-only detection job in the background: the whole
// MailPlus DSM pass (detect.DSMPassBudget, every call at its full per-call
// budget) plus the DNS record checks that follow it. The browser polls; no HTTP
// request waits for the job.
const DetectBudget = detect.DSMPassBudget + 3*time.Minute

// detectRetention keeps a job (running or finished) findable by its poller.
const detectRetention = DetectBudget + 5*time.Minute

type detectionJob struct {
	started time.Time
	done    chan struct{}
	state   detect.State
	job     *core.Job
}

// Wizard holds the setup rules, the in-memory detection jobs and the
// background transactions. Its flow API (flow.go) is what the UI calls.
type Wizard struct {
	options Options
	mu      sync.Mutex
	jobs    map[string]*detectionJob
	// previews are background plan preparations, one per flow (mu).
	previews map[string]*previewJob
	// previewWait overrides PreviewWait (tests only).
	previewWait time.Duration
	// domainReads are the zone step's MailPlus domain reads, one per flow (mu).
	domainReads map[string]*domainRead
	// domainWait overrides MailDomainsWait (tests only).
	domainWait time.Duration
	flowMu     sync.Mutex
	running    map[string]bool
	wg         sync.WaitGroup
}

func New(options Options) *Wizard { return &Wizard{options: options, jobs: map[string]*detectionJob{}} }

type form struct {
	AccountID    string `json:"accountId,omitempty"`
	ZoneID       string `json:"zoneId,omitempty"`
	TokenRef     string `json:"tokenRef,omitempty"`
	SMTPTokenRef string `json:"smtpTokenRef,omitempty"`
	Addresses    string `json:"addresses,omitempty"`
	Members      string `json:"members,omitempty"`
	Tunnel       string `json:"tunnel,omitempty"`
	Receive      string `json:"receive,omitempty"`
}
type storedPlan struct {
	Fingerprint string `json:"fingerprint"`
	// Basis is planBasis of the flow the plan was prepared for: the plan is
	// stored and applied only while the flow still decides the same way.
	Basis       string        `json:"basis"`
	Request     PlanRequest   `json:"request"`
	Changes     []core.Change `json:"changes"`
	Permissions []Permission  `json:"permissions"`
	Warnings    []core.Fact   `json:"warnings,omitempty"`
}

func digest(v any) string {
	b, _ := json.Marshal(v)
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	var canonical any
	if decoder.Decode(&canonical) == nil {
		b, _ = json.Marshal(canonical)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// pollDetection starts or polls the detection job of key. zone (optional)
// reads the zone fact alongside the detection (see zonefact.go).
func (w *Wizard) pollDetection(ctx context.Context, env core.Env, key string, req detect.Request, zone func(context.Context) string) (detect.State, bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.jobs == nil {
		w.jobs = map[string]*detectionJob{}
	}
	for k, j := range w.jobs {
		if time.Since(j.started) > detectRetention {
			delete(w.jobs, k)
		}
	}
	j := w.jobs[key]
	if j != nil && j.job.Interrupted() {
		// Abandoned (nobody polled) or stopped: its facts are incomplete.
		select {
		case <-j.done:
			delete(w.jobs, key)
			j = nil
		default:
		}
	}
	if j == nil {
		if len(w.jobs) >= 64 {
			return detect.State{}, false, ErrUnavailable
		}
		j = &detectionJob{started: time.Now(), done: make(chan struct{})}
		w.jobs[key] = j
		timeout := w.options.Timeout
		if timeout <= 0 || timeout > DetectBudget {
			timeout = DetectBudget
		}
		// The poll request may end; the job survives it, but not the worker
		// or the poller going away.
		job, err := w.options.Background.Go(timeout, func(c context.Context) {
			defer close(j.done)
			fact, read := "", make(chan struct{})
			if zone != nil {
				go func() { defer close(read); fact = zone(c) }()
			} else {
				close(read)
			}
			j.state = w.options.Detector.Detect(c, env, req)
			<-read
			applyZoneFact(&j.state, fact)
		})
		if err != nil {
			delete(w.jobs, key)
			return detect.State{}, false, ErrUnavailable // the worker is stopping
		}
		j.job = job
		return detect.State{}, false, nil
	}
	j.job.Touch()
	select {
	case <-j.done:
		if j.job.Interrupted() {
			// Cut short just now: never use its facts; the next poll reads again.
			delete(w.jobs, key)
			return detect.State{}, false, nil
		}
		return j.state, true, nil
	default:
		return detect.State{}, false, nil
	}
}

// maxMailboxes caps the exact Email Routing rules one setup creates.
const maxMailboxes = 100

// MaxMailboxes is maxMailboxes for the mailbox sync.
const MaxMailboxes = maxMailboxes

// Mailboxes are the addresses that receive through Cloudflare: every address
// of an enabled MailPlus account of the selected domain, read from MailPlus
// Server (Domain.User list). Only addresses of exactly that domain, with a
// plain local part and no "*", in a stable order, each once
// (case-insensitively), spelled with the domain as MailPlus names it.
func Mailboxes(s detect.State) []string {
	ac := s.Accounts[s.Domain]
	if !ac.IsKnown() {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, u := range ac.Value {
		if !u.Active {
			continue
		}
		for _, a := range u.Addresses {
			a = strings.TrimSpace(a)
			parsed, err := mail.ParseAddress(a)
			local, domain, ok := strings.Cut(a, "@")
			if err != nil || parsed.Address != a || !ok || local == "" || len(a) > 254 ||
				strings.ContainsAny(a, "*%!\"\r\n ") || detect.NormalizeDomain(domain) != s.Domain || seen[strings.ToLower(local+"@"+s.Domain)] {
				continue
			}
			a = local + "@" + s.Domain
			seen[strings.ToLower(a)] = true
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

func splitValues(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
}
func secretReference(s string) bool {
	return strings.HasPrefix(s, "secret:") && len(s) > 7 && len(s) < 256 && !strings.ContainsAny(s, " \r\n\t")
}
func makeRequest(session string, s detect.State, i Intent, d Decision, f form) (PlanRequest, error) {
	r := PlanRequest{SessionID: session, Intent: i, Domain: s.Domain, Decision: d, State: s, AccountID: strings.TrimSpace(f.AccountID), ZoneID: strings.TrimSpace(f.ZoneID), TokenRef: f.TokenRef, SMTPTokenRef: f.SMTPTokenRef, Tunnel: f.Tunnel}
	if f.Tunnel != "" && (d.Receive != RoutingReceive || !tunnelID(f.Tunnel)) {
		return r, ErrInvalid
	}
	if d.Gate != Minimal {
		if !identifier(r.AccountID) || !identifier(r.ZoneID) || !secretReference(f.TokenRef) {
			return r, ErrInvalid
		}
		if d.Send == RelaySend && !secretReference(f.SMTPTokenRef) {
			return r, ErrInvalid
		}
		if d.Send != RelaySend && f.SMTPTokenRef != "" {
			return r, ErrInvalid
		}
	} else if f.TokenRef != "" || f.SMTPTokenRef != "" || r.AccountID != "" || r.ZoneID != "" {
		return r, ErrInvalid
	}
	if d.Receive != RoutingReceive && f.Receive != "" {
		return r, ErrInvalid
	}
	if d.Receive != RoutingReceive && !hasNeed(d, "mailplus.members") && (f.Addresses != "" || f.Members != "") {
		return r, ErrInvalid
	}
	if d.Receive == RoutingReceive && d.Gate != Minimal {
		// Receiving through Cloudflare takes the domain's mailboxes from
		// MailPlus Server itself (SYNO.MailPlusServer.Domain.User list, read
		// by the detection): nobody types or picks a list. The relay guard
		// is the domain (the Worker hands on only @domain recipients).
		if f.Addresses != "" || f.Members != "" {
			return r, ErrInvalid
		}
		switch f.Receive {
		case "", ReceiveAddresses:
			r.ReceiveMode = ReceiveAddresses
		case ReceiveDomain:
			r.ReceiveMode = ReceiveDomain
		default:
			return r, ErrInvalid
		}
		r.Addresses = Mailboxes(s)
		if len(r.Addresses) == 0 {
			return r, ErrInvalid
		}
		if len(r.Addresses) > maxMailboxes {
			if r.ReceiveMode != ReceiveDomain {
				return r, ErrRulesLimit
			}
			// The whole domain needs no rule per mailbox; the addresses only
			// name the check mail's recipient.
			r.Addresses = r.Addresses[:maxMailboxes]
		}
		return r, nil
	}
	seen := map[string]bool{}
	for _, a := range splitValues(f.Addresses) {
		a = strings.TrimSpace(a)
		parsed, e := mail.ParseAddress(a)
		if e != nil || parsed.Address != a || strings.ContainsAny(a, "*\r\n") {
			return r, ErrInvalid
		}
		local, domain, ok := strings.Cut(a, "@")
		// Mailbox addresses compare case-insensitively (one rule each).
		if !ok || local == "" || detect.NormalizeDomain(domain) != s.Domain || len(a) > 254 || seen[strings.ToLower(a)] {
			return r, ErrInvalid
		}
		seen[strings.ToLower(a)] = true
		if d.Gate != Minimal {
			active := false
			for _, u := range s.Accounts[s.Domain].Value {
				for _, address := range u.Addresses {
					active = active || u.Active && address == a
				}
			}
			if !active {
				return r, ErrInvalid
			}
		}
		r.Addresses = append(r.Addresses, a)
	}
	if len(r.Addresses) > 100 || ((d.Receive == RoutingReceive || hasNeed(d, "mailplus.members")) && len(r.Addresses) == 0) {
		return r, ErrInvalid
	}
	if hasNeed(d, "mailplus.members") {
		names := splitValues(f.Members)
		if len(names) != len(r.Addresses) {
			return r, ErrInvalid
		}
		for index, n := range names {
			n = strings.TrimSpace(n)
			if n == "" || len(n) > 256 || strings.ContainsAny(n, "\r\n") {
				return r, ErrInvalid
			}
			r.Members = append(r.Members, Mailbox{Username: n, Address: r.Addresses[index]})
		}
	} else if f.Members != "" {
		return r, ErrInvalid
	}
	return r, nil
}

// tunnelID is a Cloudflare Tunnel UUID.
func tunnelID(v string) bool {
	if len(v) != 36 {
		return false
	}
	for i, c := range v {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case c >= '0' && c <= '9' || c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
func identifier(v string) bool {
	if len(v) != 32 {
		return false
	}
	_, e := hex.DecodeString(v)
	return e == nil
}

// ManualRecords is explanation-only. Its external.dns target is not executable.
func ManualRecords(s detect.State, d Decision) []core.Change {
	out := []core.Change{}
	for _, need := range d.Needs {
		var after, target string
		target = s.Domain
		switch need {
		case "dns.spf":
			after = "TXT v=spf1 ip4:" + s.Network.EgressIPv4.Value + " ~all"
		case "dns.dmarc":
			target = "_dmarc." + s.Domain
			after = "TXT v=DMARC1; p=none"
		case "dns.dkim":
			sign := s.Signing[s.Domain].Value
			target = sign.Selector + "._domainkey." + s.Domain
			after = "TXT v=DKIM1; k=rsa; p=" + sign.PublicKey
		case "dns.a":
			target = "mail." + s.Domain
			after = "A " + s.Network.EgressIPv4.Value + " (DNS only)"
		case "dns.mx":
			after = "MX 10 mail." + s.Domain
		default:
			continue
		}
		before := "missing"
		// Detection does not enumerate arbitrary SMTP host A records; do not claim
		// this proposed hostname is absent or invite overwriting an existing record
		if need == "dns.a" {
			before = "unknown"
		}
		out = append(out, core.Change{ID: need, Target: "external.dns", ActionKey: "mail.setup.change." + need, Params: map[string]string{"name": target}, Before: before, After: after})
	}
	return out
}

// publicError keeps a typed permission refusal (a missing DSM authority
// profile, or a caller who is not an administrator) so the engine can show the
// user the one decision that removes it. The refusal is rebuilt from its code
// and profile only, so no wrapped provider text travels with it. Every other
// provider error becomes the generic ErrUnavailable: no secret or raw DSM reply.
func publicError(err error) error {
	if err == nil {
		return nil
	}
	var authority core.AuthorityRequired
	var mailplus detect.MailPlusUnavailable
	switch {
	case errors.As(err, &authority):
		return core.AuthorityRequired{Profile: authority.Profile}
	case errors.Is(err, core.ErrNoAdmin):
		return core.ErrNoAdmin
	case errors.As(err, &mailplus):
		// The MailPlus Server precondition (detect.Gate): typed, never DSM's code.
		return detect.MailPlusUnavailable{State: mailplus.State, Detail: mailplus.Detail}
	case errors.Is(err, core.ErrDSMSlotTimeout):
		return ErrNotStarted // never sent: the state is known (unchanged)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, core.ErrDSMWriteUncertain):
		return ErrUnconfirmed
	}
	// Fixed inbound refusals keep their key; a tunnel choice keeps its options
	// (IDs and names only, read from the account the token can see).
	var unsafe UnsafeReason
	if errors.As(err, &unsafe) {
		return UnsafeReason{Code: unsafe.Code}
	}
	var choice TunnelChoice
	if errors.As(err, &choice) {
		return TunnelChoice{Options: append([]TunnelOption{}, choice.Options...)}
	}
	var refused PermissionRefused
	if errors.As(err, &refused) && validPermissionCode(refused.Code) {
		return PermissionRefused{Code: refused.Code}
	}
	for _, fixed := range []error{ErrTunnelRequired, ErrLANUnknown, ErrRulesLimit, ErrRoutingConflict, ErrRoutingLeftover, ErrRoutingLeftoverDisabled, ErrSendingPlan, ErrSendingExisting, ErrCatchAllInUse, ErrSyncTokenRequired} {
		if errors.Is(err, fixed) {
			return fixed
		}
	}
	return fmt.Errorf("%w", ErrUnavailable)
}
