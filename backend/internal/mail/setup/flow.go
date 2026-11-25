package setup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

// The setup flow.
//
// The browser owns the step flow (the UI SDK Wizard: intent → domain → detect
// → facts → branch → account → configuration → preview → apply → decision).
// The worker owns what must not live in a browser tab: the read-only
// detection job, the exact previewed plan, the write-ahead apply journal and
// the keep/rollback decision. One flow per administrator is kept in KV; a flow
// with applied changes that were neither kept nor rolled back is resumed, never
// discarded, so a closed window cannot strand a half-applied change.
//
// Home Keeper ran the same rules as a server-driven wizard (core.Wizard.Next
// over a WizardSession). Every branch rule, validation and adapter contract is
// unchanged; only the "which step comes next" decision moved to the browser.

// Phase is where a flow's transaction stands.
type Phase string

const (
	PhaseNew         Phase = ""            // collecting answers; no write yet
	PhaseApplying    Phase = "applying"    // snapshot + apply, change by change
	PhaseVerifying   Phase = "verifying"   // reading back what was applied
	PhaseDecision    Phase = "decision"    // applied and verified (or not): keep or roll back
	PhaseRollingBack Phase = "rollingBack" // restoring snapshots, newest first
	PhaseRolledBack  Phase = "rolledBack"  // every applied change restored
	PhaseKept        Phase = "kept"        // the administrator kept the changes
	PhaseFailed      Phase = "failed"      // a rollback stopped (drift or error): changes remain
	PhaseInterrupted Phase = "interrupted" // the worker stopped mid-transaction
)

// AppliedChange is one journal entry. The entry is written before the change
// is dispatched, so a lost reply is still offered for rollback.
type AppliedChange struct {
	Change   core.Change     `json:"change"`
	Snapshot json.RawMessage `json:"snapshot"`
	At       time.Time       `json:"at"`
}

// Flow is the persisted transaction state of one administrator's setup.
type Flow struct {
	ID        string `json:"id"`
	Owner     string `json:"owner"`
	Intent    Intent `json:"intent,omitempty"`
	Domain    string `json:"domain,omitempty"`
	DetectKey string `json:"detectKey,omitempty"`
	// Answers are the administrator's replies about the connection (fixed
	// IP, port 25). They change the decision, not the detection.
	Answers Answers       `json:"answers"`
	State   *detect.State `json:"state,omitempty"`
	Account *form         `json:"account,omitempty"`
	// Cloud is the Cloudflare sign-in (cloud.go): the sealed token's
	// reference and the accounts and zones it can see.
	Cloud    *cloudLink      `json:"cloud,omitempty"`
	Plan     *storedPlan     `json:"plan,omitempty"`
	Applied  []AppliedChange `json:"applied,omitempty"`
	Phase    Phase           `json:"phase"`
	Done     int             `json:"done"`
	Total    int             `json:"total"`
	Verified *verifyResult   `json:"verified,omitempty"`
	Error    string          `json:"error,omitempty"`
	// FailedStep: the ID of the plan change whose apply (or rollback)
	// failed, so the page names the step.
	FailedStep string `json:"failedStep,omitempty"`
}

// Configuration is the branch-specific form. It carries no credential: the
// Cloudflare token was sealed once at sign-in (Connect) and the plan uses its
// reference, for the setup calls and as the relay's SMTP password alike.
type Configuration struct {
	Addresses string `json:"addresses,omitempty"`
	Members   string `json:"members,omitempty"`
	// Tunnel is the inbound tunnel picked from PreviewView.Tunnels.
	Tunnel string `json:"tunnel,omitempty"`
	// Receive is the receiving mode through Cloudflare: ReceiveDomain or
	// ReceiveAddresses (default).
	Receive string `json:"receive,omitempty"`
}

// FlowView is what the browser sees of a flow.
type FlowView struct {
	ID       string         `json:"id"`
	Intent   Intent         `json:"intent,omitempty"`
	Source   Source         `json:"source,omitempty"`
	Domain   string         `json:"domain,omitempty"`
	Phase    Phase          `json:"phase"`
	Done     int            `json:"done"`
	Total    int            `json:"total"`
	Changes  []core.Change  `json:"changes"`
	Findings []core.Finding `json:"findings"`
	Verified bool           `json:"verified"`
	// Outcome of a finished flow: ok, failed (kept unverified, or a stopped
	// rollback) or rolledBack. Empty while the flow is open.
	Outcome string `json:"outcome,omitempty"`
	Error   string `json:"error,omitempty"`
	// FailedStep: the change (Changes[].id) that failed, when one did.
	FailedStep string `json:"failedStep,omitempty"`
	// Resume is true when Start returned an unfinished transaction.
	Resume bool `json:"resume"`
}

// BranchView tells the browser which steps follow the facts step.
type BranchView struct {
	// Kind: configureMailPlus (hand off to MailPlus Server, then check
	// again; also a licence shortfall), blocked (explain; optional manual DNS records), diagnose (hand
	// off to the diagnose wizard), already (nothing to change), unavailable
	// (an integration this build lacks) or configure (account → form → preview).
	Kind         string            `json:"kind"`
	Reason       string            `json:"reason,omitempty"`
	TitleKey     string            `json:"titleKey"`
	BodyKey      string            `json:"bodyKey,omitempty"`
	Params       map[string]string `json:"params,omitempty"`
	Records      []core.Change     `json:"records,omitempty"` // manual DNS records, explanation only
	Outcome      string            `json:"outcome,omitempty"` // already: ok, or failed for DNS presence only
	NeedsAccount bool              `json:"needsAccount"`
	Fields       []core.Field      `json:"fields,omitempty"`
	Warnings     []core.Fact       `json:"warnings,omitempty"`
	// Paths: the path chosen for each decided direction and why, so the
	// administrator sees what the recommendation rests on.
	Paths []PathView `json:"paths,omitempty"`
	// ReceivePending: the intent includes receiving but the domain has no
	// enabled mailbox yet; this branch covers sending only, and receiving
	// waits until MailPlus Server has a mailbox (Decision.ReceivePending).
	ReceivePending bool `json:"receivePending,omitempty"`
	// CreatesDomain: MailPlus Server is set up but has no mail domain for the
	// domain; the plan creates it (need mailplus.domain).
	CreatesDomain bool `json:"createsDomain,omitempty"`
	// Mailboxes: receiving through Cloudflare, the domain's addresses read
	// from MailPlus Server that get a routing rule (Mailboxes). Shown, never
	// asked for.
	Mailboxes []string `json:"mailboxes,omitempty"`
}

// PathView is one direction's path and the reasons for it (catalog keys
// mail.setup.why.<code>).
type PathView struct {
	Direction string   `json:"direction"` // send | receive
	Branch    Branch   `json:"branch"`
	TitleKey  string   `json:"titleKey"`
	Why       []string `json:"why"`
}

// DetectView is one poll of the read-only detection.
type DetectView struct {
	Done   bool        `json:"done"`
	Facts  []core.Fact `json:"facts,omitempty"`
	Branch *BranchView `json:"branch,omitempty"`
}

// PreviewView is the exact plan, shown before anything is written.
type PreviewView struct {
	Changes     []core.Change `json:"changes"`
	Permissions []core.Fact   `json:"permissions"`
	Warnings    []core.Fact   `json:"warnings"`
	// Pending: the plan is still prepared in the background; poll again.
	Pending bool `json:"pending,omitempty"`
	// Tunnels: no single tunnel is certain for inbound mail. Nothing was
	// planned; the administrator picks one and previews again.
	Tunnels []TunnelOption `json:"tunnels,omitempty"`
	// ReceiveMode is the planned receiving mode through Cloudflare.
	ReceiveMode string `json:"receiveMode,omitempty"`
}

var (
	// ErrNoFlow means the flow ID is not the caller's current flow.
	ErrNoFlow = errors.New("mail.setup.noFlow")
	// ErrBusy means a transaction is running or the phase does not allow it.
	ErrBusy = errors.New("mail.setup.busy")
)

const flowModule = "mail.setup"

// FlowKey is the KV key (namespace mail.setup) of owner's flow.
func FlowKey(owner string) string { return "flow." + digest(owner) }

func outstanding(f *Flow) bool {
	return len(f.Applied) > 0 && f.Phase != PhaseKept && f.Phase != PhaseRolledBack
}

func (w *Wizard) load(ctx context.Context, env core.Env, owner, id string) (*Flow, error) {
	if env.KV == nil || owner == "" {
		return nil, ErrUnavailable
	}
	var f Flow
	ok, err := env.KV.Get(ctx, flowModule, FlowKey(owner), &f)
	if err != nil {
		return nil, ErrUnavailable
	}
	if !ok || f.Owner != owner || (id != "" && f.ID != id) {
		return nil, ErrNoFlow
	}
	return &f, nil
}

func (w *Wizard) save(ctx context.Context, env core.Env, f *Flow) error {
	if err := env.KV.Put(ctx, flowModule, FlowKey(f.Owner), f); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (w *Wizard) view(f *Flow) FlowView {
	v := FlowView{ID: f.ID, Intent: f.Intent, Source: f.Answers.Source, Domain: f.Domain, Phase: f.Phase, Done: f.Done, Total: f.Total,
		Changes: []core.Change{}, Findings: []core.Finding{}, Error: f.Error, FailedStep: f.FailedStep}
	if f.Plan != nil {
		v.Changes = append(v.Changes, f.Plan.Changes...)
	}
	if f.Verified != nil {
		v.Findings = append(v.Findings, f.Verified.Findings...)
		v.Verified = f.Verified.OK
	}
	switch f.Phase {
	case PhaseKept:
		v.Outcome = "ok"
		if !v.Verified {
			v.Outcome = "failed"
		}
	case PhaseRolledBack:
		v.Outcome = "rolledBack"
	case PhaseFailed:
		v.Outcome = "failed"
	}
	return v
}

func newFlowID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", ErrUnavailable
	}
	return hex.EncodeToString(b), nil
}

// Start returns the caller's unfinished transaction (Resume), the caller's
// open flow with its detection cleared, or a new flow.
func (w *Wizard) Start(ctx context.Context, env core.Env, owner string) (FlowView, error) {
	w.flowMu.Lock()
	defer w.flowMu.Unlock()
	f, err := w.load(ctx, env, owner, "")
	if err != nil && !errors.Is(err, ErrNoFlow) {
		return FlowView{}, err
	}
	if f != nil && (outstanding(f) || w.running[f.ID]) {
		w.markInterrupted(f)
		v := w.view(f)
		v.Resume = true
		return v, nil
	}
	// An open flow with nothing applied is reused, so reading the overview
	// writes nothing. Its detection is dropped: a new wizard reads fresh facts.
	if f != nil && f.Phase == PhaseNew && len(f.Applied) == 0 {
		if f.State != nil || f.Plan != nil || f.Account != nil || f.Cloud != nil || f.DetectKey != "" {
			w.mu.Lock()
			delete(w.jobs, f.DetectKey)
			w.mu.Unlock()
			// The Cloudflare sign-in goes too, its sealed token included: the
			// page forgot the token, and a new wizard signs in again.
			dropToken(ctx, env, f)
			f.DetectKey, f.State, f.Plan, f.Account, f.Cloud = "", nil, nil, nil, nil
			if err := w.save(ctx, env, f); err != nil {
				return FlowView{}, err
			}
		}
		return w.view(f), nil
	}
	id, err := newFlowID()
	if err != nil {
		return FlowView{}, err
	}
	if f != nil {
		// The finished flow this one replaces: its token can need nothing more
		// (outstanding flows were resumed above).
		dropToken(ctx, env, f)
	}
	f = &Flow{ID: id, Owner: owner}
	if err := w.save(ctx, env, f); err != nil {
		return FlowView{}, err
	}
	return w.view(f), nil
}

// markInterrupted turns a transaction phase nobody runs any more (the worker
// restarted) into PhaseInterrupted. The journal still holds every change
// that may have been sent, so rollback stays available.
func (w *Wizard) markInterrupted(f *Flow) {
	switch f.Phase {
	case PhaseApplying, PhaseVerifying, PhaseRollingBack:
		if !w.running[f.ID] {
			f.Phase = PhaseInterrupted
			if f.Verified != nil && f.Plan != nil && len(f.Applied) == len(f.Plan.Changes) && f.Error == "" {
				// A check-again that stopped: every change was applied and
				// verified once, so the keep/rollback decision stands.
				f.Phase = PhaseDecision
			}
		}
	}
}

// Detect starts or polls the read-only detection for intent and domain.
// Changing either, the domain's source, or (Cloudflare source) the chosen account or zone
// discards the previous detection, account and plan. Changing the answers
// keeps the detection but discards the account and plan: the decision may
// differ. The Cloudflare source needs a complete sign-in (cloud.go) and a
// domain that is the chosen zone or one name under it.
func (w *Wizard) Detect(ctx context.Context, env core.Env, owner, id string, intent Intent, domain string, answers Answers, refresh bool) (DetectView, error) {
	if intent != Send && intent != Receive && intent != Both || !answers.Valid() {
		return DetectView{}, ErrInvalid
	}
	answers = answers.For(intent)
	domain = detect.NormalizeDomain(domain)
	if !detect.ValidDomain(domain) {
		return DetectView{}, ErrInvalid
	}
	w.flowMu.Lock()
	defer w.flowMu.Unlock()
	f, err := w.load(ctx, env, owner, id)
	if err != nil {
		return DetectView{}, err
	}
	if outstanding(f) || w.running[f.ID] || f.Phase != PhaseNew {
		return DetectView{}, ErrStale
	}
	var zone CloudZone
	if answers.Cloudflare() {
		ready := false
		if zone, ready = f.Cloud.ready(); !ready {
			return DetectView{}, ErrStale
		}
		// The zone itself or a name under it (label boundary), once
		// MailPlus Server's domains were read when the zone was chosen; an
		// unread list allows nothing: the zone step checks again. One of
		// those domains, or a new one when the setup sends: the
		// decision then plans creating it (mailplus.domain). Receiving alone
		// needs mailboxes a new domain does not have.
		known := slices.Contains(f.Cloud.MailDomains, domain)
		if !inZone(domain, zone.Name) || f.Cloud.MailDomainsReading || f.Cloud.MailDomainsCause != "" || !known && !intent.Sends() {
			return DetectView{}, ErrInvalid
		}
	}
	if w.options.Detector == nil {
		return DetectView{Done: true, Branch: unavailableBranch()}, nil
	}
	req := detect.Request{Domain: domain, Receive: intent.Receives()}
	account := ""
	if answers.Cloudflare() {
		account = f.Cloud.AccountID
	}
	key := digest(struct {
		ID      string
		Intent  Intent
		Request detect.Request
		Source  Source
		Account string
		Zone    string
	}{f.ID, intent, req, answers.Source, account, zone.ID})
	if refresh {
		w.mu.Lock()
		delete(w.jobs, key)
		w.mu.Unlock()
		f.State = nil
	}
	changed := f.Answers != answers
	if changed {
		f.Answers = answers
		f.Account, f.Plan, f.Verified = nil, nil, nil
	}
	if changed || f.DetectKey != key || f.State == nil {
		// A plan being prepared for the old answers or facts must never be
		// stored: cancel and forget it.
		w.dropPreview(f.ID)
	}
	if f.DetectKey != key || f.State == nil {
		f.Intent, f.Domain, f.DetectKey, f.State = intent, domain, key, nil
		f.Account, f.Plan, f.Verified = nil, nil, nil
		var zoneRead func(context.Context) string
		if answers.Cloudflare() {
			ref := f.Cloud.TokenRef
			zoneRead = func(c context.Context) string { return w.zoneFact(c, env, ref, account, domain) }
		}
		state, done, err := w.pollDetection(ctx, env, key, req, zoneRead)
		if err != nil {
			return DetectView{}, err
		}
		if done {
			f.State = &state
		}
		if err := w.save(ctx, env, f); err != nil {
			return DetectView{}, err
		}
		if !done {
			return DetectView{}, nil
		}
	} else if changed {
		// Only when an answer changed: polling writes nothing.
		if err := w.save(ctx, env, f); err != nil {
			return DetectView{}, err
		}
	}
	b := w.branch(*f.State, intent, f.Answers)
	if answers.Cloudflare() && b.Kind == "configure" && b.NeedsAccount {
		// The account and zone were chosen at sign-in: bind them now, so the
		// configuration step needs no account step (written once, not per poll).
		if f.Account == nil || f.Account.AccountID != account || f.Account.ZoneID != zone.ID {
			w.dropPreview(f.ID)
			f.Account, f.Plan = &form{AccountID: account, ZoneID: zone.ID}, nil
			if err := w.save(ctx, env, f); err != nil {
				return DetectView{}, err
			}
		}
		b.NeedsAccount = false
	}
	return DetectView{Done: true, Facts: annotateFacts(detect.Facts(*f.State), *f.State, intent, f.Answers), Branch: b}, nil
}

// dropPreview cancels and forgets the flow's background plan preparation.
func (w *Wizard) dropPreview(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if job := w.previews[id]; job != nil {
		job.job.Cancel()
		delete(w.previews, id)
	}
}

// planBasis is everything the flow's decision rests on: the flow, its
// detection (key and facts), intent, answers and the decision itself. A plan
// prepared under another basis is stale: never stored, never applied.
func planBasis(f *Flow, d Decision) string {
	return digest(struct {
		ID, Key  string
		Intent   Intent
		Answers  Answers
		State    *detect.State
		Decision Decision
	}{f.ID, f.DetectKey, f.Intent, f.Answers, f.State, d})
}

func unavailableBranch() *BranchView {
	return &BranchView{Kind: "unavailable", TitleKey: "mail.setup.integrationUnavailable", BodyKey: "mail.setup.integrationUnavailableBody"}
}

// branch applies the decision table (docs/mail-wizard-flow.md) to the facts.
func (w *Wizard) branch(state detect.State, intent Intent, answers Answers) *BranchView {
	d := Decide(state, intent, answers)
	b := w.decided(state, d)
	b.Paths = paths(d)
	b.ReceivePending = d.ReceivePending
	b.CreatesDomain = slices.Contains(d.Needs, "mailplus.domain") && b.Kind != "configureMailPlus"
	return b
}

// paths explains each decided direction. A direction already correct, or
// never reached, has no path to explain.
func paths(d Decision) []PathView {
	out := []PathView{}
	add := func(direction string, b Branch, why []string) {
		if len(why) == 0 {
			return
		}
		keys := make([]string, 0, len(why))
		for _, code := range why {
			keys = append(keys, "mail.setup.why."+code)
		}
		out = append(out, PathView{Direction: direction, Branch: b, TitleKey: "mail.setup.path." + string(b), Why: keys})
	}
	add("send", d.Send, d.SendWhy)
	add("receive", d.Receive, d.ReceiveWhy)
	return out
}

func (w *Wizard) decided(state detect.State, d Decision) *BranchView {
	if d.Gate == Minimal && (hasNeed(d, "mailplus.domain") || hasNeed(d, "mailplus.members")) {
		// Say exactly what MailPlus Server lacks: the domain, or (receiving)
		// an enabled mailbox on it.
		what := "noMailbox"
		if hasNeed(d, "mailplus.domain") {
			what = "noDomain"
		}
		return &BranchView{Kind: "configureMailPlus", Reason: d.Reason, TitleKey: "mail.setup.prereq." + what,
			BodyKey: "mail.setup.prereq." + what + "Body", Params: map[string]string{"domain": state.Domain}}
	}
	if d.Gate == Stop && d.Reason == "licenseShort" {
		// Fixed in MailPlus Server, so the same hand-off as a missing domain
		// or member: open MailPlus Server, then check again.
		l := state.License.Value
		return &BranchView{Kind: "configureMailPlus", Reason: d.Reason, TitleKey: "mail.setup.licenseShort",
			BodyKey: "mail.setup.licenseShortBody", Params: map[string]string{"active": strconv.Itoa(l.Active), "licensed": strconv.Itoa(l.Licensed)}}
	}
	if d.Gate == Handoff {
		return &BranchView{Kind: "diagnose", Reason: d.Reason, TitleKey: "mail.setup.intent.diagnose"}
	}
	if d.Blocked() {
		b := &BranchView{Kind: "blocked", Reason: d.Reason, TitleKey: "mail.setup." + d.Reason, BodyKey: "mail.setup." + d.Reason + "Body"}
		if d.Reason == "unknown" && d.Cause != "" {
			// Say exactly why MailPlus Server could not be read.
			key, params := detect.CauseKey(d.Cause)
			b.TitleKey = "mail.setup.unreadable"
			b.BodyKey = "mail.setup.unreadable." + strings.TrimPrefix(key, "mail.setup.cause.")
			b.Params = params
		} else if d.Reason == "unknown" && len(d.Missing) > 0 {
			// Name each fact the decision lacked, with why it is unknown. Only
			// DNS facts reach this (the path decision treats unchecked network
			// facts through the administrator's answers), so checking again
			// can always change the result.
			b.BodyKey = "mail.setup.unknownFactsBody"
			for _, m := range d.Missing {
				key, params := detect.CauseKey(m.Cause)
				b.Warnings = append(b.Warnings, core.Fact{LabelKey: "mail.setup.fact." + m.Fact, Value: key, Params: params, Status: core.SeverityWarning})
			}
		}
		if d.Reason == "manualDNS" {
			b.Records = ManualRecords(state, d)
		}
		return b
	}
	if len(d.Needs) == 0 {
		b := &BranchView{Kind: "already", Reason: d.Reason, TitleKey: "mail.setup." + d.Reason, BodyKey: "mail.setup." + d.Reason + "Body", Outcome: "ok"}
		if d.Reason == "dnsReady" {
			// DNS presence is not proof of deliverability.
			b.Outcome = "failed"
		}
		return b
	}
	if w.options.Verifier == nil || hasPrefixNeed(d, "mailplus.") && w.options.MailPlus == nil ||
		hasPrefixNeed(d, "relay.") && w.options.Relay == nil ||
		(d.Cloud() || hasPrefixNeed(d, "dns.")) && w.options.Cloudflare == nil {
		return unavailableBranch()
	}
	b := &BranchView{Kind: "configure", Reason: d.Reason, TitleKey: "mail.setup.configuration", NeedsAccount: d.Gate != Minimal,
		Fields: configurationFields(d), Warnings: warnings(state, d)}
	if d.Receive == RoutingReceive {
		b.Mailboxes = Mailboxes(state)
	}
	if d.Gate == Minimal {
		b.BodyKey = "mail.setup.minimalBody"
	}
	return b
}

func warnings(state detect.State, d Decision) []core.Fact {
	out := []core.Fact{}
	if d.Send == RelaySend {
		out = append(out, core.Fact{LabelKey: "mail.setup.globalDelivery", Value: state.Domain, Status: core.SeverityWarning})
	}
	if d.Receive == RoutingReceive {
		// Stated as limits and unknowns, never as claims.
		for _, key := range []string{"mail.setup.inbound.direct", "mail.setup.inbound.rollback", "mail.setup.inbound.spf", "mail.setup.inbound.plan"} {
			out = append(out, core.Fact{LabelKey: key, Value: state.Domain, Status: core.SeverityWarning})
		}
	}
	return out
}

// configurationFields are the branch's form fields. A secret field is typed by
// the administrator; the operation layer seals it and passes a reference.
func configurationFields(d Decision) []core.Field {
	out := []core.Field{}
	if d.Gate == Minimal {
		if hasNeed(d, "mailplus.members") {
			out = append(out, core.Field{Name: "members", Kind: "text", LabelKey: "mail.setup.members", HintKey: "mail.setup.membersHint", Required: true},
				core.Field{Name: "addresses", Kind: "text", LabelKey: "mail.setup.addresses", HintKey: "mail.setup.addressesHint", Required: true})
		}
		return out
	}
	// No token field: the Cloudflare sign-in (cloud.go) holds the one token.
	// No address field either: receiving through Cloudflare takes the
	// domain's mailboxes from MailPlus Server (Mailboxes).
	return out
}

// detected returns the flow's finished detection and decision.
func detected(f *Flow) (detect.State, Decision, error) {
	if f.State == nil || !f.Intent.Valid() || f.Intent == Diagnose || f.Intent == Check {
		return detect.State{}, Decision{}, ErrStale
	}
	return *f.State, Decide(*f.State, f.Intent, f.Answers), nil
}

// Permissions records the Cloudflare account and zone and returns the exact
// permission inventory to show before any credential is asked for. It is
// local: no network or credential access.
func (w *Wizard) Permissions(ctx context.Context, env core.Env, owner, id, accountID, zoneID string) ([]Permission, error) {
	w.flowMu.Lock()
	defer w.flowMu.Unlock()
	f, err := w.load(ctx, env, owner, id)
	if err != nil {
		return nil, err
	}
	if outstanding(f) || w.running[f.ID] || f.Phase != PhaseNew {
		return nil, ErrStale
	}
	state, d, err := detected(f)
	if err != nil {
		return nil, err
	}
	if b := w.branch(state, f.Intent, f.Answers); b.Kind != "configure" || !b.NeedsAccount {
		return nil, ErrInvalid
	}
	if !identifier(accountID) || !identifier(zoneID) {
		return nil, ErrInvalid
	}
	// Only the account and zone chosen at sign-in, from Cloudflare's own
	// lists, and only a zone that holds the domain.
	zone, ready := f.Cloud.ready()
	if !ready || f.Cloud.AccountID != accountID || zone.ID != zoneID || !inZone(state.Domain, zone.Name) {
		return nil, ErrInvalid
	}
	required, err := w.options.Cloudflare.RequiredPermissions(PlanRequest{SessionID: f.ID, Intent: f.Intent, Domain: state.Domain,
		State: state, Decision: d, AccountID: accountID, ZoneID: zoneID})
	if err != nil || !validPermissions(required, accountID, zoneID, d) {
		return nil, ErrUnavailable
	}
	if f.Account == nil || f.Account.AccountID != accountID || f.Account.ZoneID != zoneID {
		f.Account, f.Plan = &form{AccountID: accountID, ZoneID: zoneID}, nil
		if err := w.save(ctx, env, f); err != nil {
			return nil, err
		}
	}
	return required, nil
}

func permissionFacts(ps []Permission) []core.Fact {
	out := []core.Fact{}
	for _, p := range ps {
		out = append(out, core.Fact{LabelKey: "mail.setup.permissions", Value: p.Scope + " / " + p.Resource + " / " + p.Name})
	}
	return out
}

// PreviewWait is how long one preview call waits for the background plan
// before it answers with Pending (far below DSM's and nginx's HTTP timeouts).
const PreviewWait = 12 * time.Second

// previewJob prepares one flow's plan in the background: it reads MailPlus
// Server through delegated calls, which can take minutes on a loaded NAS.
type previewJob struct {
	fingerprint string
	basis       string // planBasis when the preparation started
	done        chan struct{}
	plan        storedPlan
	err         error
	job         *core.Job
	// request and env restart the preparation if it was cut short: the typed
	// tokens stay sealed in the flow's secret references.
	request PlanRequest
	env     core.Env
}

// startPreview prepares job's plan in the background. Called with w.mu held.
func (w *Wizard) startPreview(job *previewJob) error {
	bg, err := w.options.Background.Go(PrepareBudget, func(c context.Context) {
		defer close(job.done)
		job.plan, job.err = w.prepare(c, job.env, job.request)
		job.plan.Fingerprint, job.plan.Basis = job.fingerprint, job.basis
	})
	if err != nil {
		return ErrUnavailable // the worker is stopping
	}
	job.job = bg
	return nil
}

// Preview builds (or returns the unchanged) exact plan. Nothing is written
// remotely; the plan's change records are journaled as "planned". The plan
// is prepared in the background: the reply is Pending until it is ready, and
// PollPreview fetches it.
func (w *Wizard) Preview(ctx context.Context, env core.Env, owner, id string, cfg Configuration) (PreviewView, error) {
	w.flowMu.Lock()
	f, err := w.load(ctx, env, owner, id)
	if err != nil {
		w.flowMu.Unlock()
		return PreviewView{}, err
	}
	if outstanding(f) || w.running[f.ID] || f.Phase != PhaseNew {
		// No new preview over partial application: roll back or keep first.
		w.flowMu.Unlock()
		return PreviewView{}, ErrStale
	}
	state, d, err := detected(f)
	if err != nil {
		w.flowMu.Unlock()
		return PreviewView{}, err
	}
	// The MailPlus Server precondition, as the detection read it.
	if err := detect.StatusOf(state.Package).Err(); err != nil {
		w.flowMu.Unlock()
		return PreviewView{}, err
	}
	if b := w.branch(state, f.Intent, f.Answers); b.Kind != "configure" {
		w.flowMu.Unlock()
		return PreviewView{}, ErrInvalid
	}
	answers := form{Addresses: cfg.Addresses, Members: cfg.Members, Tunnel: cfg.Tunnel, Receive: cfg.Receive}
	if d.Gate != Minimal {
		zone, ready := f.Cloud.ready()
		if f.Account == nil || !ready || f.Account.AccountID != f.Cloud.AccountID || f.Account.ZoneID != zone.ID {
			w.flowMu.Unlock()
			return PreviewView{}, ErrStale
		}
		answers.AccountID, answers.ZoneID = f.Account.AccountID, f.Account.ZoneID
		// One token, pasted once: it also authenticates the relay to
		// Cloudflare's SMTP service (Email Sending: Edit).
		answers.TokenRef = f.Cloud.TokenRef
		if d.Send == RelaySend {
			answers.SMTPTokenRef = f.Cloud.TokenRef
		}
	}
	request, err := makeRequest(f.ID, state, f.Intent, d, answers)
	if err != nil {
		w.flowMu.Unlock()
		return PreviewView{}, err
	}
	basis := planBasis(f, d)
	fp := digest(struct {
		ID, Key, Basis string
		Answers        form
	}{f.ID, f.DetectKey, basis, answers})
	if f.Plan != nil && f.Plan.Fingerprint == fp {
		w.flowMu.Unlock()
		return w.previewView(f, state, d), nil
	}
	w.mu.Lock()
	if w.previews == nil {
		w.previews = map[string]*previewJob{}
	}
	job := w.previews[f.ID]
	if job == nil || job.fingerprint != fp {
		if job != nil {
			job.job.Cancel() // replaced by new answers
		}
		job = &previewJob{fingerprint: fp, basis: basis, done: make(chan struct{}), request: request, env: env}
		if err := w.startPreview(job); err != nil {
			w.mu.Unlock()
			w.flowMu.Unlock()
			return PreviewView{}, err
		}
		w.previews[f.ID] = job
	}
	w.mu.Unlock()
	w.flowMu.Unlock()
	return w.awaitPreview(ctx, env, owner, id, job)
}

// PollPreview returns the flow's plan, or Pending while it is still prepared.
func (w *Wizard) PollPreview(ctx context.Context, env core.Env, owner, id string) (PreviewView, error) {
	w.mu.Lock()
	job := w.previews[id]
	w.mu.Unlock()
	if job == nil {
		w.flowMu.Lock()
		defer w.flowMu.Unlock()
		f, err := w.load(ctx, env, owner, id)
		if err != nil {
			return PreviewView{}, err
		}
		state, d, err := detected(f)
		if err != nil {
			return PreviewView{}, err
		}
		if f.Plan == nil {
			return PreviewView{}, ErrStale
		}
		return w.previewView(f, state, d), nil
	}
	return w.awaitPreview(ctx, env, owner, id, job)
}

// awaitPreview waits at most PreviewWait for job, then stores its plan in
// the flow (unless the flow moved on) and returns it.
func (w *Wizard) awaitPreview(ctx context.Context, env core.Env, owner, id string, job *previewJob) (PreviewView, error) {
	job.job.Touch()
	wait := PreviewWait
	if w.previewWait > 0 {
		wait = w.previewWait
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-job.done:
	case <-timer.C:
		return pendingPreview(), nil
	case <-ctx.Done():
		return PreviewView{}, ctx.Err()
	}
	w.flowMu.Lock()
	defer w.flowMu.Unlock()
	w.mu.Lock()
	current := w.previews[id] == job
	if current && job.job.Interrupted() {
		// Cut short (nobody polled, or the worker stops): prepare again from
		// the same sealed answers, so nothing has to be typed again.
		again := &previewJob{fingerprint: job.fingerprint, basis: job.basis, done: make(chan struct{}), request: job.request, env: job.env}
		err := w.startPreview(again)
		if err == nil {
			w.previews[id] = again
		} else {
			delete(w.previews, id)
		}
		w.mu.Unlock()
		if err != nil {
			return PreviewView{}, err
		}
		return pendingPreview(), nil
	}
	if current {
		delete(w.previews, id)
	}
	w.mu.Unlock()
	if !current {
		// A newer preview replaced this one; its caller polls for that.
		return pendingPreview(), nil
	}
	var choice TunnelChoice
	if errors.As(job.err, &choice) {
		view := pendingPreview()
		view.Pending, view.Tunnels = false, choice.Options
		return view, nil
	}
	if job.err != nil {
		return PreviewView{}, job.err
	}
	f, err := w.load(ctx, env, owner, id)
	if err != nil {
		return PreviewView{}, err
	}
	if outstanding(f) || w.running[f.ID] || f.Phase != PhaseNew {
		return PreviewView{}, ErrStale
	}
	state, d, err := detected(f)
	if err != nil {
		return PreviewView{}, err
	}
	if job.basis != planBasis(f, d) {
		// Prepared for answers or facts the flow no longer has: discard it.
		return PreviewView{}, ErrPlanChanged
	}
	plan := job.plan
	f.Plan = &plan
	if err := w.save(ctx, env, f); err != nil {
		return PreviewView{}, err
	}
	return w.previewView(f, state, d), nil
}

func pendingPreview() PreviewView {
	return PreviewView{Pending: true, Changes: []core.Change{}, Permissions: []core.Fact{}, Warnings: []core.Fact{}}
}

func (w *Wizard) previewView(f *Flow, state detect.State, d Decision) PreviewView {
	return PreviewView{Changes: append([]core.Change{}, f.Plan.Changes...), Permissions: permissionFacts(f.Plan.Permissions),
		Warnings: append(warnings(state, d), f.Plan.Warnings...), ReceiveMode: f.Plan.Request.ReceiveMode}
}

// Apply starts the previewed plan in the background and returns at once; the
// browser polls Status. Each change is snapshotted, journaled, then applied.
// A failure rolls back what was applied, newest first.
func (w *Wizard) Apply(ctx context.Context, env core.Env, owner, id string) (FlowView, error) {
	w.flowMu.Lock()
	defer w.flowMu.Unlock()
	f, err := w.load(ctx, env, owner, id)
	if err != nil {
		return FlowView{}, err
	}
	if f.Plan == nil || f.Phase != PhaseNew || len(f.Applied) > 0 || w.running[f.ID] {
		return FlowView{}, ErrBusy
	}
	// The plan must still match what the flow decides now (answers, facts,
	// decision). Otherwise refuse without writing anything.
	state, d, err := detected(f)
	if err != nil {
		return FlowView{}, err
	}
	if err := detect.StatusOf(state.Package).Err(); err != nil {
		return FlowView{}, err
	}
	if f.Plan.Basis != planBasis(f, d) {
		return FlowView{}, ErrPlanChanged
	}
	if w.otherRunning(f.ID) {
		return FlowView{}, ErrOtherTransaction
	}
	f.Phase, f.Done, f.Total, f.Error, f.Verified = PhaseApplying, 0, len(f.Plan.Changes), "", nil
	if err := w.save(ctx, env, f); err != nil {
		return FlowView{}, err
	}
	w.launch(ctx, env, f.ID, applyBudget(len(f.Plan.Changes)), func(run context.Context) { w.applyAll(run, env, owner, id) })
	return w.view(f), nil
}

// otherRunning reports another flow's transaction (applying, verifying or
// rolling back) in this package. MailPlus settings are shared: one
// transaction at a time, whoever started it. flowMu held.
func (w *Wizard) otherRunning(id string) bool {
	for other := range w.running {
		if other != id {
			return true
		}
	}
	return false
}

// launch runs a transaction detached from the request that started it,
// bounded by budget (applyBudget or rollbackBudget).
func (w *Wizard) launch(ctx context.Context, env core.Env, id string, budget time.Duration, work func(context.Context)) {
	if w.running == nil {
		w.running = map[string]bool{}
	}
	w.running[id] = true
	w.wg.Add(1)
	run, cancel := context.WithTimeout(context.WithoutCancel(ctx), budget)
	go func() {
		defer w.wg.Done()
		defer cancel()
		defer func() {
			w.flowMu.Lock()
			delete(w.running, id)
			w.flowMu.Unlock()
		}()
		work(run)
	}()
}

// Wait blocks until every background transaction has returned.
func (w *Wizard) Wait() { w.wg.Wait() }

// update loads the flow, lets f change it and saves it, under the flow lock.
func (w *Wizard) update(ctx context.Context, env core.Env, owner, id string, change func(*Flow) error) (*Flow, error) {
	w.flowMu.Lock()
	defer w.flowMu.Unlock()
	f, err := w.load(ctx, env, owner, id)
	if err != nil {
		return nil, err
	}
	if err := change(f); err != nil {
		return f, err
	}
	return f, w.save(ctx, env, f)
}

// MailPlusReason is the catalog key of the MailPlus Server precondition
// refusal (mail.mailplus.{notInstalled,stopped,unknown}).
func MailPlusReason(state detect.MailPlusState) string {
	switch state {
	case detect.MailPlusNotInstalled:
		return "mail.mailplus.notInstalled"
	case detect.MailPlusStopped:
		return "mail.mailplus.stopped"
	}
	return "mail.mailplus.unknown"
}

func publicCode(err error) string {
	var authority core.AuthorityRequired
	var mailplus detect.MailPlusUnavailable
	switch {
	case err == nil:
		return ""
	case errors.As(err, &authority):
		return "authority_required:" + authority.Profile
	case errors.As(err, &mailplus):
		return MailPlusReason(mailplus.State)
	case errors.Is(err, core.ErrNoAdmin):
		return "admin_required"
	case errors.As(err, new(UnsafeReason)):
		var unsafe UnsafeReason
		errors.As(err, &unsafe)
		return unsafe.Error()
	case errors.Is(err, ErrUnsafe):
		return ErrUnsafe.Error()
	case errors.As(err, new(PermissionRefused)):
		var refused PermissionRefused
		errors.As(err, &refused)
		if validPermissionCode(refused.Code) {
			return refused.Error()
		}
	case errors.Is(err, ErrStale):
		return ErrStale.Error()
	case errors.Is(err, ErrTokenInvalid):
		// Cloudflare refused the token itself (deleted or rolled): a new
		// token on the decision step lets the rollback go on.
		return ErrTokenInvalid.Error()
	case errors.Is(err, ErrSendingPlan):
		// Email Sending refused by the Cloudflare plan while applying.
		return ErrSendingPlan.Error()
	case errors.Is(err, ErrNotStarted), errors.Is(err, core.ErrDSMSlotTimeout):
		return ErrNotStarted.Error()
	case errors.Is(err, ErrUnconfirmed), errors.Is(err, context.DeadlineExceeded), errors.Is(err, core.ErrDSMWriteUncertain):
		// A step ran out of time: what MailPlus now holds is not known.
		return ErrUnconfirmed.Error()
	}
	return ErrUnavailable.Error()
}

func (w *Wizard) applyAll(ctx context.Context, env core.Env, owner, id string) {
	f, err := w.update(ctx, env, owner, id, func(*Flow) error { return nil })
	if err != nil {
		return
	}
	for index, c := range f.Plan.Changes {
		step := func(err error) error { return failedStep{id: c.ID, err: err} }
		snap, err := w.Snapshot(ctx, env, c)
		if err != nil {
			w.failAndRollback(ctx, env, owner, id, step(err))
			return
		}
		// Write-ahead: journal the change before dispatch, so a lost reply
		// is still rolled back from its snapshot.
		if _, err := w.update(ctx, env, owner, id, func(f *Flow) error {
			f.Applied = append(f.Applied, AppliedChange{Change: c, Snapshot: snap, At: time.Now().UTC()})
			return nil
		}); err != nil {
			w.failAndRollback(ctx, env, owner, id, err)
			return
		}
		if err := w.ApplyChange(ctx, env, c); err != nil {
			w.failAndRollback(ctx, env, owner, id, step(err))
			return
		}
		if _, err := w.update(ctx, env, owner, id, func(f *Flow) error { f.Done = index + 1; return nil }); err != nil {
			w.failAndRollback(ctx, env, owner, id, err)
			return
		}
	}
	f, err = w.update(ctx, env, owner, id, func(f *Flow) error { f.Phase = PhaseVerifying; return nil })
	if err != nil {
		return
	}
	result, err := w.verify(ctx, env, f)
	if err != nil {
		w.failAndRollback(ctx, env, owner, id, err)
		return
	}
	_, _ = w.update(ctx, env, owner, id, func(f *Flow) error {
		f.Verified, f.Phase = &result, PhaseDecision
		return nil
	})
}

func (w *Wizard) failAndRollback(ctx context.Context, env core.Env, owner, id string, cause error) {
	// The apply's own budget may be what ran out: the rollback gets its own,
	// so a timed-out apply is still undone (or ends failed), never left half
	// applied in a running phase.
	applied := 0
	if f, err := w.update(context.WithoutCancel(ctx), env, owner, id, func(*Flow) error { return nil }); err == nil {
		applied = len(f.Applied)
	}
	rb, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackBudget(applied))
	defer cancel()
	_, _ = w.update(rb, env, owner, id, func(f *Flow) error {
		f.Phase, f.Error, f.FailedStep = PhaseRollingBack, publicCode(cause), ""
		var at failedStep
		if errors.As(cause, &at) {
			f.FailedStep = at.id
		}
		return nil
	})
	w.rollbackAll(rb, env, owner, id)
}

// rollbackAll restores the journal newest first. External drift or an error
// stops the rollback (PhaseFailed) instead of overwriting someone's work.
func (w *Wizard) rollbackAll(ctx context.Context, env core.Env, owner, id string) {
	for {
		var next *AppliedChange
		_, err := w.update(ctx, env, owner, id, func(f *Flow) error {
			if len(f.Applied) > 0 {
				c := f.Applied[len(f.Applied)-1]
				next = &c
			}
			return nil
		})
		if err != nil {
			return
		}
		if next == nil {
			_, _ = w.update(ctx, env, owner, id, func(f *Flow) error {
				f.Phase = PhaseRolledBack
				dropToken(ctx, env, f) // everything restored: nothing needs it
				if f.Plan != nil {
					// Nor the plan's sealed operations; a failed delete only leaves a value nothing reads.
					_ = DropOperationSecrets(ctx, env, f.Plan.Changes)
				}
				return nil
			})
			return
		}
		if err := w.RollbackChange(ctx, env, next.Change, next.Snapshot); err != nil {
			_, _ = w.update(context.WithoutCancel(ctx), env, owner, id, func(f *Flow) error {
				f.Phase = PhaseFailed
				// A rollback that could not read or write in time leaves the
				// setting unknown; say so even if the apply failed otherwise.
				if code := publicCode(err); f.Error == "" || code == ErrUnconfirmed.Error() || strings.HasPrefix(code, "authority_required:") {
					f.Error, f.FailedStep = code, next.Change.ID
				}
				return nil
			})
			return
		}
		_, _ = w.update(ctx, env, owner, id, func(f *Flow) error {
			if n := len(f.Applied); n > 0 && digest(f.Applied[n-1].Change) == digest(next.Change) {
				f.Applied = f.Applied[:n-1]
			}
			return nil
		})
	}
}

// Status returns the flow; an orphaned transaction phase becomes interrupted.
func (w *Wizard) Status(ctx context.Context, env core.Env, owner, id string) (FlowView, error) {
	w.flowMu.Lock()
	defer w.flowMu.Unlock()
	f, err := w.load(ctx, env, owner, id)
	if err != nil {
		return FlowView{}, err
	}
	before := f.Phase
	w.markInterrupted(f)
	if f.Phase != before {
		if err := w.save(ctx, env, f); err != nil {
			return FlowView{}, err
		}
	}
	return w.view(f), nil
}

// Decide records keep, or starts a rollback. Keep is offered only after
// verification; rollback also after a failure or an interruption.
func (w *Wizard) Decide(ctx context.Context, env core.Env, owner, id, choice string) (FlowView, error) {
	w.flowMu.Lock()
	defer w.flowMu.Unlock()
	f, err := w.load(ctx, env, owner, id)
	if err != nil {
		return FlowView{}, err
	}
	w.markInterrupted(f)
	if w.running[f.ID] {
		return FlowView{}, ErrBusy
	}
	switch choice {
	case "keep":
		if f.Phase != PhaseDecision {
			return FlowView{}, ErrBusy
		}
		f.Phase = PhaseKept
		// Kept: the setup is recorded for the Overview (mailbox sync,
		// removal) and the sign-in token goes with it, sealed. A failure
		// there is logged; the setup itself stays kept and the token is
		// dropped as before.
		if w.options.Inbound != nil && f.Cloud != nil && f.Cloud.TokenRef != "" && f.Account != nil {
			kept := KeptSetup{FlowID: f.ID, Domain: f.Domain, Intent: f.Intent, AccountID: f.Account.AccountID,
				ZoneID: f.Account.ZoneID, TokenRef: f.Cloud.TokenRef, Applied: append([]AppliedChange{}, f.Applied...)}
			if err := w.options.Inbound.Kept(ctx, env, kept); err != nil {
				if !errors.Is(err, core.ErrNotFound) && env.Log != nil {
					env.Log.Warn("kept setup not recorded", "cause", err.Error())
				}
			} else {
				f.Cloud.TokenRef = "" // the record owns the sealed token now
			}
		}
		dropToken(ctx, env, f)
		if err := w.save(ctx, env, f); err != nil {
			return FlowView{}, err
		}
		return w.view(f), nil
	case "rollback":
		if f.Phase != PhaseDecision && f.Phase != PhaseFailed && f.Phase != PhaseInterrupted {
			return FlowView{}, ErrBusy
		}
		if w.otherRunning(f.ID) {
			return FlowView{}, ErrOtherTransaction
		}
		f.Phase = PhaseRollingBack
		if err := w.save(ctx, env, f); err != nil {
			return FlowView{}, err
		}
		owner := f.Owner
		w.launch(ctx, env, f.ID, rollbackBudget(len(f.Applied)), func(run context.Context) { w.rollbackAll(run, env, owner, id) })
		return w.view(f), nil
	case "verify":
		// Check again (for example after the administrator sent the inbound
		// check mail). Reads only; a failure leaves the decision as it is.
		if f.Phase != PhaseDecision || f.Verified == nil || f.Verified.OK {
			return FlowView{}, ErrBusy
		}
		if w.otherRunning(f.ID) {
			return FlowView{}, ErrOtherTransaction
		}
		f.Phase = PhaseVerifying
		if err := w.save(ctx, env, f); err != nil {
			return FlowView{}, err
		}
		owner := f.Owner
		w.launch(ctx, env, f.ID, VerifyBudget, func(run context.Context) { w.reverify(run, env, owner, id) })
		return w.view(f), nil
	}
	return FlowView{}, ErrInvalid
}

// reverify runs verification again from the decision phase. Unlike the
// first verification after apply, an error never starts a rollback.
func (w *Wizard) reverify(ctx context.Context, env core.Env, owner, id string) {
	f, err := w.update(ctx, env, owner, id, func(*Flow) error { return nil })
	if err != nil {
		return
	}
	result, err := w.verify(ctx, env, f)
	if err != nil {
		result = verifyResult{Findings: []core.Finding{{ID: "mail.setup.verification", Module: "mail", Check: "mail.setup", Severity: core.SeverityWarning,
			TitleKey: "mail.setup.verificationFailed", WhyKey: "mail.setup.verificationFailedBody", FixWizard: "mail.diagnose"}}}
		if f.Verified != nil {
			result.Findings = f.Verified.Findings // keep what the last check said
		}
	}
	_, _ = w.update(context.WithoutCancel(ctx), env, owner, id, func(f *Flow) error {
		f.Verified, f.Phase = &result, PhaseDecision
		return nil
	})
}

// failedStep carries the ID of the plan change an error stopped at.
type failedStep struct {
	id  string
	err error
}

func (e failedStep) Error() string { return e.err.Error() }
func (e failedStep) Unwrap() error { return e.err }
