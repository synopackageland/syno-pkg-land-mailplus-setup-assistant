// Package diagnose supplies read-only mail checks and the mail.diagnose wizard.
// The mail module wires Dependencies to its detector and relay status provider.
package diagnose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

const prefix = "mail.diag."

type CheckID string

const (
	MailPlus    CheckID = "mail.diag.mailplus"
	Relay       CheckID = "mail.diag.relay"
	Network     CheckID = "mail.diag.network"
	DomainDNS   CheckID = "mail.diag.domain"
	Inbound     CheckID = "mail.diag.inbound"
	Certificate CheckID = "mail.diag.certificate"
	Client      CheckID = "mail.diag.client"
	Transport   CheckID = "mail.diag.transport"
	Access      CheckID = "mail.diag.access"
)

// Resolver is satisfied by net.Resolver and by in-memory test fixtures.
type Resolver interface {
	LookupTXT(context.Context, string) ([]string, error)
	LookupHost(context.Context, string) ([]string, error)
	LookupIP(context.Context, string, string) ([]net.IP, error)
	LookupAddr(context.Context, string) ([]string, error)
	LookupMX(context.Context, string) ([]*net.MX, error)
}

type NetworkProber interface {
	Egress(context.Context, string) Egress
	Outbound(context.Context, string) []Port
}

// StateSource returns only normalized, credential-free observations. A denied
// DSM call is unknown, never false/zero. Implementations must honor ctx.
type StateSource interface {
	Snapshot(context.Context, core.Env) (State, error)
}

// State is the adapter contract for mail/detect (absent on main at task start).
// Pointer nil means not visible. Never put credentials or raw log text here.
type State struct {
	Installed   *bool        `json:"installed,omitempty"`
	Running     *bool        `json:"running,omitempty"`
	SMTPEnabled *bool        `json:"smtpEnabled,omitempty"`
	Domains     []MailDomain `json:"domains,omitempty"`
	Queue       QueueState   `json:"queue"`
	Relay       RelayState   `json:"relay"`
	// TokenInvalid: mail domains of kept Cloudflare setups whose token
	// Cloudflare refused (deleted or rolled in the dashboard). The package's
	// own record says so; diagnosis makes no Cloudflare call for it.
	TokenInvalid        []string          `json:"tokenInvalid,omitempty"`
	Certificates        []MailCertificate `json:"certificates,omitempty"`
	CertificatesVisible bool              `json:"certificatesVisible"`
	// Inbound25 requires an external vantage point; a LAN connection is not evidence.
	Inbound25 *bool `json:"inbound25,omitempty"`
	// ClientReachable means a verified external client path, including a known
	// working app/tunnel path; a tunnel's mere presence is not a failure.
	IMAPEnabled     *bool `json:"imapEnabled,omitempty"`
	ClientReachable *bool `json:"clientReachable,omitempty"`
	// CSS evidence is normalized by the integration adapter, never inferred
	// from a healthy SMTP listener or from the administrator running the check.
	Transport TransportState `json:"transport"`
	Access    AccessState    `json:"access"`
}

type MailDomain struct {
	Name      string   `json:"name"`                // normalized ASCII/punycode domain
	Selectors []string `json:"selectors,omitempty"` // actual configured selectors, no guessed default
}

type QueueState struct {
	Total *int `json:"total,omitempty"`
	// Oldest is the oldest enqueue time across the COMPLETE queue, normalized
	// by a verified adapter. Do not guess units/layouts of E3's date/time fields.
	Oldest *time.Time `json:"oldest,omitempty"`
	// Reasons are allowlisted categories extracted from Queue.reason or
	// TransactionLog.status_detail; raw log strings must not be retained.
	Reasons []DeferredReason `json:"reasons,omitempty"`
}

type DeferredReason string

const (
	DeferredDNS    DeferredReason = "dns"
	DeferredAuth   DeferredReason = "auth"
	DeferredTLS    DeferredReason = "tls"
	DeferredPolicy DeferredReason = "policy"
	DeferredRemote DeferredReason = "remote"
)

type RelayState struct {
	// Enabled means this MailPlus route uses Home Keeper, not just that a
	// smarthost row exists. Do not substitute an unrelated relay's status.
	Enabled     *bool     `json:"enabled,omitempty"`
	Running     *bool     `json:"running,omitempty"`
	LastSuccess time.Time `json:"lastSuccess,omitempty"`
	// PlanRefusal is when Cloudflare last refused a recipient because the
	// account is on Workers Free, which sends only to its verified
	// destination addresses (in memory: zero after a relay restart).
	PlanRefusal time.Time `json:"planRefusal,omitempty"`
}

type MailCertificate struct {
	// Host and Service identify the actual mail assignment (postfix/dovecot).
	// No private key, PEM, account name or unrelated DSM certificate is accepted.
	Host     string    `json:"host"`
	Service  string    `json:"service"`
	NotAfter time.Time `json:"notAfter"`
}

type Dependencies struct {
	State   StateSource
	DNS     Resolver
	Network NetworkProber
	// No provider is queried by default. The integrator opts into providers
	// whose usage terms/access have been confirmed. Names match E4's adapters:
	// Spamhaus ZEN, Barracuda, SpamCop, PSBL.
	DNSBLProviders []string
	SpamhausDQSKey string // inject from Secrets; never persist this configuration
	ProbeTimeout   time.Duration
	RunTimeout     time.Duration
	// RelayStatus lets mail.diag.relay judge a stopped relay from memory
	// between full runs (disk-hibernation.md H2). Optional.
	RelayStatus RelayStatusSource
}

// CheckBudget bounds evaluating one check against a snapshot (DNS and network
// probes; ten domains of DNS checks at worst). It runs in the background, so
// no HTTP request waits for it. RunTimeout defaults to, and never exceeds, it.
const CheckBudget = 15 * time.Minute

// SnapshotBudget bounds the one DSM read of a run (every MailPlus read at its
// full per-call budget, see detect.DSMPassBudget) plus the Cloudflare selectors.
const SnapshotBudget = detect.DSMPassBudget + 3*time.Minute

// Unreadable is a snapshot that could not read MailPlus Server; Cause is a
// fixed public cause (core.Cause). Checks then report unavailable with it.
type Unreadable struct{ Cause string }

func (e Unreadable) Error() string { return "mail_unreadable: " + e.Cause }

type Diagnostics struct {
	deps Dependencies
	// relayEnabled is whether MailPlus routes through Home Keeper's relay, as
	// read by the last full run; nil until a full run has read it.
	mu           sync.Mutex
	relayEnabled *bool
}

func New(deps Dependencies) *Diagnostics {
	deps.DNSBLProviders = append([]string(nil), deps.DNSBLProviders...)
	if deps.ProbeTimeout <= 0 || deps.ProbeTimeout > 30*time.Second {
		deps.ProbeTimeout = 5 * time.Second
	}
	if deps.RunTimeout <= 0 || deps.RunTimeout > CheckBudget {
		deps.RunTimeout = CheckBudget
	}
	return &Diagnostics{deps: deps}
}

var checkOrder = []CheckID{MailPlus, Relay, Network, DomainDNS, Inbound, Certificate, Client, Transport, Access}

func (d *Diagnostics) Checks() []core.Check {
	checks := make([]core.Check, 0, len(checkOrder))
	for _, id := range checkOrder {
		checks = append(checks, scheduledCheck{d, id})
	}
	return checks
}

type scheduledCheck struct {
	d  *Diagnostics
	id CheckID
}

func (c scheduledCheck) ID() string { return string(c.id) }
func (c scheduledCheck) Interval() time.Duration {
	switch c.id {
	case MailPlus, Relay:
		return 15 * time.Minute
	case Certificate:
		return 24 * time.Hour
	case Inbound, Client, Access:
		return 0 // require externally obtained evidence / interactive context
	default:
		return 6 * time.Hour
	}
}
func (c scheduledCheck) Run(ctx context.Context, env core.Env) ([]core.Finding, error) {
	return c.d.Run(ctx, env, c.id)
}

// ForgetRelayRoute drops the MailPlus route read by the last full run. Home
// Keeper's relay setup calls it whenever it applies or rolls back the relay,
// so a relay stopped by a rollback is never judged from a stale route; the
// next full run reads the route again.
func (d *Diagnostics) ForgetRelayRoute() {
	d.mu.Lock()
	d.relayEnabled = nil
	d.mu.Unlock()
}

// MemoryInterval is set only for mail.diag.relay: the relay service's state
// is in this process, so a stopped relay is found without DSM or disk I/O.
func (c scheduledCheck) MemoryInterval() time.Duration {
	if c.id == Relay && c.d.deps.RelayStatus != nil {
		return 15 * time.Minute
	}
	return 0
}

// Judge is final only when the last full run saw MailPlus routed through the
// relay and the relay is not running now: checkRelay's verdict then does not
// depend on the queue, which needs DSM. Every other case waits for a full run.
func (c scheduledCheck) Judge(now time.Time) ([]core.Finding, bool) {
	if c.id != Relay || c.d.deps.RelayStatus == nil {
		return nil, false
	}
	c.d.mu.Lock()
	enabled := c.d.relayEnabled
	c.d.mu.Unlock()
	if enabled == nil || !*enabled {
		return nil, false
	}
	running := c.d.deps.RelayStatus.Status().Running
	if running {
		return nil, false
	}
	return checkRelay(State{Relay: RelayState{Enabled: enabled, Running: &running}}, now), true
}

// Run runs a bounded, sequential batch using one snapshot and one DNS cache.
// Probe errors become explicit informational findings; caller cancellation is
// returned so it cannot be persisted as a successful empty check.
func (d *Diagnostics) Run(ctx context.Context, env core.Env, ids ...CheckID) ([]core.Finding, error) {
	for _, id := range ids {
		if !validCheck(id) {
			return nil, errors.New("unknown mail diagnostic check")
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snapshot, err := d.Snapshot(ctx, env)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return d.Evaluate(ctx, env, snapshot, err, ids...)
}

// Snapshot reads the state once; a run shares it across all its checks. An
// error is Unreadable (or another refusal) and makes checks unavailable.
func (d *Diagnostics) Snapshot(ctx context.Context, env core.Env) (State, error) {
	if d.deps.State == nil {
		return State{}, Unreadable{Cause: core.CauseUnavailable}
	}
	ctx, cancel := context.WithTimeout(ctx, SnapshotBudget)
	defer cancel()
	state, err := d.deps.State.Snapshot(ctx, env)
	if err != nil {
		var unreadable Unreadable
		if !errors.As(err, &unreadable) {
			err = Unreadable{Cause: core.Cause(err)}
		}
		return State{}, err
	}
	d.mu.Lock()
	if state.Relay.Enabled != nil {
		enabled := *state.Relay.Enabled
		d.relayEnabled = &enabled
	} else {
		d.relayEnabled = nil
	}
	d.mu.Unlock()
	return state, nil
}

// Evaluate judges the checks against one snapshot. snapshotErr is the
// snapshot's error: every check is then unavailable, with its cause.
func (d *Diagnostics) Evaluate(ctx context.Context, env core.Env, state State, snapshotErr error, ids ...CheckID) ([]core.Finding, error) {
	for _, id := range ids {
		if !validCheck(id) {
			return nil, errors.New("unknown mail diagnostic check")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, d.deps.RunTimeout)
	defer cancel()
	now := time.Now()
	if env.Now != nil {
		now = env.Now()
	}
	c := &checker{ctx: ctx, r: d.deps.DNS, timeout: d.deps.ProbeTimeout,
		key: d.deps.SpamhausDQSKey, enabledProviders: d.deps.DNSBLProviders,
		txtCache: map[string]ProbeResult{}, controls: map[string]ProbeResult{}}
	out := []core.Finding{}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if snapshotErr != nil {
			out = append(out, unreadable(id, snapshotErr))
			continue
		}
		var fs []core.Finding
		switch id {
		case MailPlus:
			fs = checkMailPlus(state, now)
		case Relay:
			fs = checkRelay(state, now)
		case Network:
			fs = d.checkNetwork(ctx, c, state)
		case DomainDNS:
			fs = checkDomains(c, state)
		case Inbound:
			fs = observedPath(Inbound, "inbound", state.Inbound25, "receive")
		case Certificate:
			fs = checkCertificates(state, now)
		case Client:
			fs = checkClient(state)
		case Transport:
			fs = checkTransport(state)
		case Access:
			fs = checkAccess(state)
		}
		out = append(out, fs...)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// unreadable is a check that has no snapshot. A known DSM cause replaces the
// generic why/fix with the exact reason (mail.setup.unreadable.*).
func unreadable(id CheckID, err error) core.Finding {
	cause := core.CauseUnavailable
	var u Unreadable
	if errors.As(err, &u) && u.Cause != "" {
		cause = u.Cause
	}
	f := finding(id, "unavailable", "", core.SeverityInfo, "", struct {
		Cause string `json:"cause"`
	}{cause})
	if cause != core.CauseUnavailable {
		key, params := detect.CauseKey(cause)
		f.WhyKey = "mail.setup.unreadable." + strings.TrimPrefix(key, "mail.setup.cause.")
		f.FixKey = ""
		for k, v := range params {
			if k == "code" {
				continue // a DSM code never reaches the page
			}
			f.Params[k] = v
		}
	}
	return f
}

func validCheck(id CheckID) bool {
	for _, known := range checkOrder {
		if id == known {
			return true
		}
	}
	return false
}

// Finding IDs use check+cause+subject, so queue counts and changing ages never
// create duplicate issues. Evidence is restricted to typed observations.
func finding(check CheckID, cause, subject string, severity core.Severity, intent string, evidence any) core.Finding {
	id := string(check) + "." + cause
	if subject != "" {
		id += "." + subject
	}
	params := map[string]string{"subject": subject, "cause": cause}
	if intent != "" {
		params["intent"] = intent
	}
	family := cause
	switch cause {
	case "missing", "stopped", "smtp":
		family = "mailplus"
	case "queue", "queue_stale", "queue_age":
		family = "queue"
	case "relay_stopped", "relay_stale", "relay_history":
		family = "relay"
	case "token_invalid":
		family = "token"
	case "inbound_unknown":
		family = "inbound"
	case "client_unknown", "imap":
		family = "client"
	case "cert_soon", "cert_expired":
		family = "certificate"
	}
	f := core.Finding{ID: id, Module: "mail", Check: string(check), Severity: severity,
		TitleKey: prefix + cause + ".title", WhyKey: prefix + family + ".why",
		FixKey: prefix + family + ".fix", Params: params}
	if cause == "unavailable" {
		f.TitleKey = prefix + "unavailable." + strings.TrimPrefix(string(check), prefix) + ".title"
		if evidence == nil {
			evidence = struct {
				Observation string `json:"observation,omitempty"`
			}{subject}
		}
	}
	if intent != "" {
		f.FixWizard = "mail.setup"
	}
	if evidence != nil {
		f.Evidence = plainEvidence(evidence)
	}
	return f
}

// plainEvidence marshals a finding's evidence (shown folded under "Show
// details") with every raw DSM cause (dsm_<code>) replaced by its plain cause
// key (detect.CauseKey), which the page shows in words: no DSM code is ever
// shown to the user. The code was logged when the read failed.
func plainEvidence(evidence any) json.RawMessage {
	raw, err := json.Marshal(evidence)
	if err != nil {
		return nil
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return raw
	}
	out, err := json.Marshal(plainCauses(v))
	if err != nil {
		return raw
	}
	return out
}

func plainCauses(v any) any {
	switch t := v.(type) {
	case string:
		if isDSMCause(t) || detect.IsExecutorCause(t) {
			key, _ := detect.CauseKey(t)
			return key
		}
	case map[string]any:
		for k, e := range t {
			t[k] = plainCauses(e)
		}
	case []any:
		for i, e := range t {
			t[i] = plainCauses(e)
		}
	}
	return v
}

// isDSMCause: exactly "dsm_" and digits.
func isDSMCause(s string) bool {
	code, ok := strings.CutPrefix(s, "dsm_")
	if !ok || code == "" {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Precondition is the MailPlus Server gate of a run, judged from its one
// snapshot: not installed (cause missing), installed but not running or broken
// (stopped), or not readable (unavailable, with the snapshot's cause). Then
// that finding is the run's first and only cause and stop is true: every other
// check reads MailPlus Server's state, so none of them runs. Its fix is in
// Package Center, not in the setup wizard (which stops at the same gate).
func Precondition(s State, snapshotErr error) (core.Finding, bool) {
	var f core.Finding
	switch {
	case snapshotErr != nil:
		f = unreadable(MailPlus, snapshotErr)
	case s.Installed == nil:
		return core.Finding{}, false
	case !*s.Installed:
		f = finding(MailPlus, "missing", "", core.SeverityCritical, "", nil)
	case isFalse(s.Running):
		f = finding(MailPlus, "stopped", "", core.SeverityCritical, "", nil)
	default:
		return core.Finding{}, false
	}
	return f, true
}

func isFalse(b *bool) bool { return b != nil && !*b }
func isTrue(b *bool) bool  { return b != nil && *b }

func checkMailPlus(s State, now time.Time) []core.Finding {
	if s.Installed == nil {
		return []core.Finding{finding(MailPlus, "unavailable", "", core.SeverityInfo, "", nil)}
	}
	if !*s.Installed {
		return []core.Finding{finding(MailPlus, "missing", "", core.SeverityCritical, "both", nil)}
	}
	out := []core.Finding{}
	if isFalse(s.Running) {
		out = append(out, finding(MailPlus, "stopped", "", core.SeverityCritical, "both", nil))
	} else if s.Running == nil {
		out = append(out, finding(MailPlus, "unavailable", "running", core.SeverityInfo, "", nil))
	}
	if isFalse(s.SMTPEnabled) {
		out = append(out, finding(MailPlus, "smtp", "", core.SeverityWarning, "both", nil))
	} else if s.SMTPEnabled == nil && !isFalse(s.Running) {
		out = append(out, finding(MailPlus, "unavailable", "smtp", core.SeverityInfo, "", nil))
	}
	q := s.Queue
	if q.Total == nil || *q.Total < 0 {
		out = append(out, finding(MailPlus, "unavailable", "queue", core.SeverityInfo, "", nil))
		return out
	}
	if *q.Total == 0 {
		return out
	}
	ageKnown := q.Oldest != nil && !q.Oldest.IsZero() && !q.Oldest.After(now)
	evidence := map[string]any{"count": *q.Total, "oldestKnown": ageKnown}
	cause, severity := "queue", core.SeverityInfo
	if ageKnown {
		evidence["oldestAgeSeconds"] = int64(now.Sub(*q.Oldest).Seconds())
		if now.Sub(*q.Oldest) >= time.Hour {
			cause, severity = "queue_stale", core.SeverityWarning
		}
	}
	out = append(out, finding(MailPlus, cause, "", severity, "send", evidence))
	if !ageKnown {
		out = append(out, finding(MailPlus, "queue_age", "", core.SeverityInfo, "", nil))
	}
	seen := map[DeferredReason]bool{}
	for _, reason := range q.Reasons {
		switch reason {
		case DeferredDNS, DeferredAuth, DeferredTLS, DeferredPolicy, DeferredRemote:
			if !seen[reason] {
				f := finding(MailPlus, "deferred_"+string(reason), "", core.SeverityWarning, "send", nil)
				if s.Transport.Send == PathProvider || s.Transport.Send == PathHomeKeeper {
					f.FixWizard = ""
					f.WhyKey, f.FixKey = prefix+"provider_relay.why", prefix+"provider_relay.fix"
				}
				out = append(out, f)
				seen[reason] = true
			}
		}
	}
	return out
}

// checkRelay: a refused Cloudflare token first (sending through the relay
// and the kept setup's sync and removal stop until a new one is entered),
// then the relay service itself.
func checkRelay(s State, now time.Time) []core.Finding {
	out := []core.Finding{}
	for _, domain := range s.TokenInvalid {
		f := finding(Relay, "token_invalid", domain, core.SeverityCritical, "", nil)
		f.Params["target"] = domain
		out = append(out, f)
	}
	return append(out, checkRelayService(s, now)...)
}

func checkRelayService(s State, now time.Time) []core.Finding {
	r := s.Relay
	if r.Enabled == nil {
		return []core.Finding{finding(Relay, "unavailable", "", core.SeverityInfo, "", nil)}
	}
	if !*r.Enabled {
		return nil
	}
	if isFalse(r.Running) {
		return []core.Finding{finding(Relay, "relay_stopped", "", core.SeverityCritical, "send", nil)}
	}
	if r.Running == nil {
		return []core.Finding{finding(Relay, "unavailable", "running", core.SeverityInfo, "", nil)}
	}
	out := []core.Finding{}
	// A refused message goes back to its sender, so the queue says nothing:
	// a Workers Free refusal in the last day is named on its own.
	if !r.PlanRefusal.IsZero() && !r.PlanRefusal.After(now) && now.Sub(r.PlanRefusal) < planRefusalWindow {
		out = append(out, finding(Relay, "recipient_plan", "", core.SeverityWarning, "send",
			map[string]any{"refusedAgeSeconds": int64(now.Sub(r.PlanRefusal).Seconds())}))
	}
	if s.Queue.Total == nil || *s.Queue.Total < 0 {
		return append(out, finding(Relay, "unavailable", "queue", core.SeverityInfo, "", nil))
	}
	if *s.Queue.Total == 0 {
		return out // idle does not mean broken
	}
	if r.LastSuccess.IsZero() || r.LastSuccess.After(now) {
		return append(out, finding(Relay, "relay_history", "", core.SeverityInfo, "", nil))
	}
	if now.Sub(r.LastSuccess) >= time.Hour {
		return append(out, finding(Relay, "relay_stale", "", core.SeverityWarning, "send",
			map[string]any{"lastSuccessAgeSeconds": int64(now.Sub(r.LastSuccess).Seconds()), "queueCount": *s.Queue.Total}))
	}
	return out
}

// planRefusalWindow is how long a Workers Free recipient refusal stays a
// finding. After an upgrade to Workers Paid it fades on its own.
const planRefusalWindow = 24 * time.Hour

func checkDomains(c *checker, s State) []core.Finding {
	if c.r == nil || len(s.Domains) == 0 {
		return []core.Finding{finding(DomainDNS, "unavailable", "domains", core.SeverityInfo, "", nil)}
	}
	out := []core.Finding{}
	seen := map[string]bool{}
	for i, input := range s.Domains {
		if i >= 10 {
			out = append(out, finding(DomainDNS, "bounded", "", core.SeverityInfo, "", nil))
			break
		}
		name := strings.ToLower(strings.TrimSuffix(input.Name, "."))
		if !validDomain(name) {
			// Do not echo malformed/untrusted state into evidence.
			out = append(out, finding(DomainDNS, "unavailable", "domain-"+strconv.Itoa(i), core.SeverityInfo, "", nil))
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		selectors := []string{}
		for j, selector := range input.Selectors {
			if j >= 10 {
				out = append(out, finding(DomainDNS, "bounded", name, core.SeverityInfo, "", nil))
				break
			}
			// Selectors can contain multiple DNS labels; underscore is permitted.
			if validSelector(selector) {
				selectors = append(selectors, selector)
			}
		}
		d := c.domain(name, selectors)
		probes := []struct {
			cause, status string
			evidence      any
		}{
			{"mx", d.MX.Status, d.MX}, {"spf", d.SPF.Status, d.SPF},
			{"dmarc", d.DMARC.Status, d.DMARC}, {"mtasts", d.MTASTS.Status, d.MTASTS},
			{"tlsrpt", d.TLSRPT.Status, d.TLSRPT},
		}
		if len(d.DKIM) == 0 {
			probes = append(probes, struct {
				cause, status string
				evidence      any
			}{"dkim", "unknown", nil})
		}
		for _, dk := range d.DKIM {
			if dk.Status != "present" {
				f := finding(DomainDNS, "dkim", name+"."+dk.Selector, dnsSeverity(dk.Status), "send", dk)
				f.Params["target"] = name
				out = append(out, f)
			}
		}
		for _, p := range probes {
			if p.status == "pass" || p.status == "present" {
				continue
			}
			intent := "send"
			if p.cause == "mx" || p.cause == "mtasts" || p.cause == "tlsrpt" {
				intent = "receive"
			}
			severity := dnsSeverity(p.status)
			if p.cause == "mtasts" || p.cause == "tlsrpt" || p.cause == "dmarc" && p.status == "missing" || p.cause == "mx" && p.status == "missing" {
				severity = core.SeverityInfo // optional / inherited / implicit fallback
			}
			f := finding(DomainDNS, p.cause, name, severity, intent, p.evidence)
			f.Params["target"] = name
			f.Params["status"] = p.status
			out = append(out, f)
		}
	}
	return out
}

func dnsSeverity(status string) core.Severity {
	if status == "unknown" {
		return core.SeverityInfo
	}
	return core.SeverityWarning
}

func validSelector(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
				return false
			}
		}
	}
	return true
}

func observedPath(check CheckID, cause string, observed *bool, intent string) []core.Finding {
	if isTrue(observed) {
		return nil
	}
	if observed == nil {
		cause += "_unknown"
		return []core.Finding{finding(check, cause, "", core.SeverityInfo, "", nil)}
	}
	return []core.Finding{finding(check, cause, "", core.SeverityWarning, intent, nil)}
}

func checkClient(s State) []core.Finding {
	if isFalse(s.IMAPEnabled) {
		return []core.Finding{finding(Client, "imap", "", core.SeverityWarning, "", nil)}
	}
	out := observedPath(Client, "client", s.ClientReachable, "")
	if s.IMAPEnabled == nil {
		out = append(out, finding(Client, "unavailable", "imap", core.SeverityInfo, "", nil))
	}
	return out
}

func checkCertificates(s State, now time.Time) []core.Finding {
	if !s.CertificatesVisible || len(s.Certificates) == 0 {
		return []core.Finding{finding(Certificate, "unavailable", "", core.SeverityInfo, "", nil)}
	}
	out := []core.Finding{}
	seen := map[string]bool{}
	for _, cert := range s.Certificates {
		if cert.Service != "postfix" && cert.Service != "dovecot" {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(cert.Host, "."))
		subject := cert.Service
		if validDomain(host) {
			subject = host + "." + cert.Service
		}
		if seen[subject] {
			continue
		}
		seen[subject] = true
		if cert.NotAfter.IsZero() {
			out = append(out, finding(Certificate, "unavailable", subject, core.SeverityInfo, "", nil))
			continue
		}
		if cert.NotAfter.After(now.Add(30 * 24 * time.Hour)) {
			continue
		}
		severity := core.SeverityWarning
		cause := "cert_soon"
		if !cert.NotAfter.After(now) {
			cause, severity = "cert_expired", core.SeverityCritical
		}
		f := finding(Certificate, cause, subject, severity, "",
			map[string]any{"notAfter": cert.NotAfter.UTC(), "service": cert.Service})
		if validDomain(host) {
			f.Params["target"] = host
		}
		out = append(out, f)
	}
	if len(seen) == 0 {
		out = append(out, finding(Certificate, "unavailable", "mail-assignment", core.SeverityInfo, "", nil))
	}
	return out
}

// Rank is deterministic and symptom-specific: actionable causes precede unknown
// observations, then data-table priority, severity and stable ID break ties.
func Rank(symptom Symptom, findings []core.Finding) []core.Finding {
	out := append([]core.Finding(nil), findings...)
	plan, ok := PlanFor(symptom)
	if !ok {
		return out
	}
	weight := func(f core.Finding) int {
		for i, cause := range plan.Causes {
			if f.Params["cause"] == cause {
				return i
			}
		}
		for i, check := range plan.Checks {
			if f.Check == string(check) {
				return len(plan.Causes) + i
			}
		}
		return 1000
	}
	severity := map[core.Severity]int{core.SeverityCritical: 0, core.SeverityWarning: 1, core.SeverityInfo: 2, core.SeverityOK: 3}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		// Explain the chosen hops before presenting changes to those hops.
		ap, bp := a.Check == string(Transport) && strings.HasPrefix(a.Params["cause"], "path_"), b.Check == string(Transport) && strings.HasPrefix(b.Params["cause"], "path_")
		if ap != bp {
			return ap
		}
		aa, bb := severity[a.Severity] < 2, severity[b.Severity] < 2
		if aa != bb {
			return aa
		}
		if weight(a) != weight(b) {
			return weight(a) < weight(b)
		}
		if severity[a.Severity] != severity[b.Severity] {
			return severity[a.Severity] < severity[b.Severity]
		}
		return a.ID < b.ID
	})
	return out
}

func (d *Diagnostics) String() string {
	// Prevent fmt logging the dependency struct (which can contain a DQS key).
	return fmt.Sprintf("mail diagnostics (%d checks)", len(checkOrder))
}
