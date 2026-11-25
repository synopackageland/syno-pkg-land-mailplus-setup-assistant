package setup

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

// The Cloudflare sign-in.
//
// The administrator pastes one API token, once. The operation layer seals it
// at once (Env.Secrets) and only its reference reaches this file. The flow then
// keeps what the token can see: its accounts, the chosen account's zones and
// the chosen zone. Nobody types an Account ID or a Zone ID: both are picked
// from these lists, and the worker accepts only an ID it listed itself.
//
// Missing permissions are decided from Cloudflare's own refusals (HTTP 403) on
// read calls the mail path needs: no refusal is not proof of the write
// permission, which only the apply itself can show (Cloudflare does not let a
// token read its own policy without an extra permission). Anything other than
// a clear refusal is unknown and stops the step with "unavailable".

// CloudAccount is one Cloudflare account the token can see.
type CloudAccount struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// CloudZone is one zone (domain) of the chosen account. Status is
// Cloudflare's: only "active" can be chosen ("pending" waits for the
// nameserver change at the registrar). Type is Cloudflare's setup ("full",
// "partial", "secondary"); only the zone fact reads it.
type CloudZone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Type   string `json:"type,omitempty"`
}

// Permission codes, localized as mail.setup.cloudflare.permission.<code>.
const (
	PermZoneRead    = "zoneRead"
	PermDNSEdit     = "dnsEdit"
	PermSendingEdit = "sendingEdit"
	// Inbound (InboundPermissions).
	PermZoneSettingsEdit = "zoneSettingsEdit"
	PermRoutingRulesEdit = "routingRulesEdit"
	PermWorkersEdit      = "workersEdit"
	PermVPCAdmin         = "vpcAdmin"
	PermTunnelRead       = "tunnelRead"
)

func validPermissionCode(code string) bool {
	for _, c := range PermissionCodes {
		if c == code {
			return true
		}
	}
	return false
}

// PermissionCodes lists every code (for catalog checks).
var PermissionCodes = []string{PermZoneRead, PermDNSEdit, PermSendingEdit,
	PermZoneSettingsEdit, PermRoutingRulesEdit, PermWorkersEdit, PermVPCAdmin, PermTunnelRead}

// ErrTokenInvalid: Cloudflare refused the token itself (unknown, expired or
// revoked). Nothing about it was kept.
var ErrTokenInvalid = errors.New("mail.setup.tokenInvalid")

// ErrCloudflareUnavailable: Cloudflare's answer was unclear (a server error,
// no answer, an unexpected reply). Nothing is concluded from it; trying again
// later may work. Not ErrUnavailable, whose text is about this build.
var ErrCloudflareUnavailable = errors.New("mail.setup.cloudflareUnavailable")

// CloudDirectory reads what one token can see. Accounts takes the pasted
// token itself (held in memory only), because it is the verify step: nothing
// is sealed before a verify endpoint accepted the token. Zones and Probe run
// after that, on the sealed reference, resolved through Env.Secrets.
// Implementations never return, store or log the value.
// missing holds permission codes Cloudflare clearly refused; any other
// failure is an error (ErrTokenInvalid or ErrUnavailable).
type CloudDirectory interface {
	// Accounts verifies the token and lists its accounts. It succeeds only
	// after a Cloudflare verify endpoint answered that the token is active;
	// otherwise ErrTokenInvalid, or ErrCloudflareUnavailable when unclear.
	Accounts(ctx context.Context, env core.Env, token string) (CloudAccess, error)
	// Zones lists one account's zones.
	Zones(ctx context.Context, env core.Env, tokenRef, accountID string) (zones []CloudZone, missing []string, err error)
	// Probe reads the zone the way the plan will (DNS, and Email Sending when
	// the decision takes the Cloudflare relay) and names what was refused.
	// inbound adds the reads of the Cloudflare inbound path (Email Routing
	// settings and rules, Workers, VPC Services, tunnels).
	Probe(ctx context.Context, env core.Env, tokenRef, accountID, zoneID string, relay, inbound bool) (missing []string, err error)
}

// CloudAccess is what a sign-in found.
type CloudAccess struct {
	Accounts []CloudAccount
	// Missing permission codes Cloudflare refused (HTTP 403).
	Missing []string
	// AccountUnknown: a verify endpoint accepted the token (a user token),
	// but no account could be named (GET /accounts refused and the token has
	// no zone yet). The account becomes known with its first zone: register,
	// then check again.
	AccountUnknown bool
}

// maxCloudItems bounds the lists kept in the flow record.
const maxCloudItems = 1000

// cloudLink is the flow's Cloudflare sign-in: references and public IDs only.
type cloudLink struct {
	// Gen changes with every sign-in, so a slow zone read for an older token
	// is never stored over a newer one (the reference name stays the same).
	Gen       string         `json:"gen"`
	TokenRef  string         `json:"tokenRef"`
	Accounts  []CloudAccount `json:"accounts"`
	AccountID string         `json:"accountId,omitempty"`
	Zones     []CloudZone    `json:"zones,omitempty"`
	ZoneID    string         `json:"zoneId,omitempty"`
	Missing   []string       `json:"missing,omitempty"`
	// AccountUnknown: see CloudAccess.
	AccountUnknown bool `json:"accountUnknown,omitempty"`
	// MailDomains (Cloudflare source): MailPlus Server's domains that are
	// the chosen zone or under it, read when the zone was chosen.
	MailDomains []string `json:"mailDomains,omitempty"`
	// MailDomainsCause: why they could not be read ("" when read).
	MailDomainsCause string `json:"mailDomainsCause,omitempty"`
	// MailDomainsReading: the read runs in the background; poll.
	MailDomainsReading bool `json:"mailDomainsReading,omitempty"`
}

// MailDomainSource lists MailPlus Server's mail domains (one DSM read,
// SYNO.MailPlusServer.Domain list v1, mail-read), normalized. An error means
// unknown, never "none".
type MailDomainSource interface {
	MailDomains(ctx context.Context, env core.Env) ([]string, error)
}

// The zone step's domain read runs in the background, like the detection: a
// delegated DSM read is sent only with its full per-call budget left
// (core.DSMReadTimeout; core.Authority refuses a shorter deadline with
// ErrDSMSlotTimeout, never sending it) and may first wait for an executor
// slot. The read is two calls one after another: the MailPlus Server
// precondition (package list), then the domain list. MailDomainsBudget is
// that whole wall (slot wait + call, twice); a reply
// waits at most MailDomainsWait and then answers "reading" (poll again).
const (
	MailDomainsBudget = 2 * core.DSMCallWall
	MailDomainsWait   = 8 * time.Second
)

// CauseNotStarted: the read was never sent (no executor slot within the
// slot wait). Distinct from core.CauseTimeout, which only a DSM call that
// was sent and did not answer in time can give.
const CauseNotStarted = detect.CauseNotStarted

type domainRead struct {
	gen, zoneID string
	done        chan struct{}
	names       []string
	cause       string
	// err is a refusal the page must turn into the approval prompt
	// (core.AuthorityRequired, core.ErrNoAdmin), never "unknown".
	err error
	job *core.Job
}

// CloudView is what the browser sees of the sign-in.
type CloudView struct {
	Accounts []CloudAccount `json:"accounts"`
	// AccountID is the chosen account; with exactly one account it is chosen
	// at once.
	AccountID string      `json:"accountId,omitempty"`
	Zones     []CloudZone `json:"zones"`
	ZoneID    string      `json:"zoneId,omitempty"`
	// Match (own-domain source) is the zone that holds the flow's domain, the
	// longest matching name; empty when no zone of the account holds it.
	Match string `json:"match,omitempty"`
	// Missing permission codes; the token must be replaced (no upgrade flow).
	Missing []string `json:"missing"`
	// AccountUnknown: the token works but has no zone yet, and Cloudflare
	// does not name its account: register a domain, then check again
	// (mail.setup.zones with an empty accountId).
	AccountUnknown bool `json:"accountUnknown,omitempty"`
	// MailDomains (Cloudflare source, once a zone is chosen): MailPlus
	// Server's domains that are the zone or under it, to pick the mail
	// domain from; empty means MailPlus Server has none there. Never the apex
	// by default.
	MailDomains []string `json:"mailDomains"`
	// MailDomainsState: "" (no zone chosen), "read", or "unknown" (the read
	// failed; check again), with MailDomainsCause (a mail.setup.cause key).
	MailDomainsState string `json:"mailDomainsState,omitempty"`
	MailDomainsCause string `json:"mailDomainsCause,omitempty"`
	// MailDomainsCauseKey (with MailDomainsCauseParams) names the cause in
	// the catalog (mail.setup.cause.*).
	MailDomainsCauseKey    string            `json:"mailDomainsCauseKey,omitempty"`
	MailDomainsCauseParams map[string]string `json:"mailDomainsCauseParams,omitempty"`
}

func (l *cloudLink) zone(id string) (CloudZone, bool) {
	for _, z := range l.Zones {
		if z.ID == id {
			return z, true
		}
	}
	return CloudZone{}, false
}

// ready returns the chosen zone when the sign-in is complete: an account and
// an active zone chosen from the lists, and nothing refused.
func (l *cloudLink) ready() (CloudZone, bool) {
	if l == nil || l.TokenRef == "" || l.AccountID == "" || l.ZoneID == "" || len(l.Missing) > 0 {
		return CloudZone{}, false
	}
	z, ok := l.zone(l.ZoneID)
	return z, ok && z.Status == "active"
}

// inZone reports whether domain is the zone itself or a name under it.
func inZone(domain, zone string) bool {
	return zone != "" && (domain == zone || strings.HasSuffix(domain, "."+zone))
}

func cleanAccounts(in []CloudAccount) ([]CloudAccount, error) {
	out, seen := []CloudAccount{}, map[string]bool{}
	for _, a := range in {
		if !identifier(a.ID) || len(a.Name) > 256 {
			return nil, ErrCloudflareUnavailable
		}
		if !seen[a.ID] {
			seen[a.ID] = true
			out = append(out, a)
		}
	}
	if len(out) > maxCloudItems {
		return nil, ErrUnavailable
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func cleanZones(in []CloudZone) ([]CloudZone, error) {
	out, seen := []CloudZone{}, map[string]bool{}
	for _, z := range in {
		name := detect.NormalizeDomain(z.Name)
		if !identifier(z.ID) || !detect.ValidDomain(name) || len(z.Status) > 32 || len(z.Type) > 32 {
			return nil, ErrCloudflareUnavailable
		}
		if !seen[z.ID] {
			seen[z.ID] = true
			out = append(out, CloudZone{ID: z.ID, Name: name, Status: z.Status, Type: z.Type})
		}
	}
	if len(out) > maxCloudItems {
		return nil, ErrUnavailable
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func cleanMissing(in []string) []string {
	out := []string{}
	for _, code := range PermissionCodes {
		for _, m := range in {
			if m == code {
				out = append(out, code)
				break
			}
		}
	}
	return out
}

// openFlow loads the caller's flow when it may still change its answers.
func (w *Wizard) openFlow(ctx context.Context, env core.Env, owner, id string) (*Flow, error) {
	w.flowMu.Lock()
	defer w.flowMu.Unlock()
	return w.newPhase(ctx, env, owner, id)
}

// newPhase loads the flow and refuses unless it is still collecting answers.
// flowMu held.
func (w *Wizard) newPhase(ctx context.Context, env core.Env, owner, id string) (*Flow, error) {
	f, err := w.load(ctx, env, owner, id)
	if err != nil {
		return nil, err
	}
	if outstanding(f) || w.running[f.ID] || f.Phase != PhaseNew {
		return nil, ErrStale
	}
	return f, nil
}

// forgetSelection drops what rests on the Cloudflare sign-in: the account
// binding and the plan always; on the Cloudflare source also the detection,
// which was read for the chosen zone. flowMu held.
func (w *Wizard) forgetSelection(f *Flow) {
	w.dropPreview(f.ID)
	f.Account, f.Plan, f.Verified = nil, nil, nil
	if f.Answers.Cloudflare() {
		w.mu.Lock()
		delete(w.jobs, f.DetectKey)
		w.mu.Unlock()
		f.State, f.DetectKey = nil, ""
	}
}

func cloudView(f *Flow) CloudView {
	v := CloudView{Accounts: []CloudAccount{}, Zones: []CloudZone{}, Missing: []string{}, MailDomains: []string{}}
	l := f.Cloud
	if l == nil {
		return v
	}
	v.Accounts = append(v.Accounts, l.Accounts...)
	v.Zones = append(v.Zones, l.Zones...)
	v.Missing = append(v.Missing, l.Missing...)
	v.AccountID, v.ZoneID, v.AccountUnknown = l.AccountID, l.ZoneID, l.AccountUnknown
	if l.ZoneID != "" {
		switch {
		case l.MailDomainsReading:
			v.MailDomainsState = "reading"
		case l.MailDomainsCause != "":
			v.MailDomainsState, v.MailDomainsCause = "unknown", l.MailDomainsCause
			v.MailDomainsCauseKey, v.MailDomainsCauseParams = detect.CauseKey(l.MailDomainsCause)
		default:
			v.MailDomains = append(v.MailDomains, l.MailDomains...)
			v.MailDomainsState = "read"
		}
	}
	if !f.Answers.Cloudflare() && f.Domain != "" {
		v.Match = matchZone(f.Domain, l.Zones)
	}
	return v
}

// readMailDomains reads MailPlus Server's domains and keeps those that are
// the zone or under it (label boundary), sorted. The cause is a fixed DSM
// cause when the read failed.
func (w *Wizard) readMailDomains(ctx context.Context, env core.Env, zone string) ([]string, string, error) {
	src, ok := w.options.Detector.(MailDomainSource)
	if !ok {
		return nil, core.CauseUnavailable, nil
	}
	names, err := src.MailDomains(ctx, env)
	var authority core.AuthorityRequired
	switch {
	case errors.As(err, &authority):
		return nil, core.CauseAuthority, core.AuthorityRequired{Profile: authority.Profile}
	case errors.Is(err, core.ErrNoAdmin):
		return nil, core.CauseAuthority, core.ErrNoAdmin
	case errors.Is(err, core.ErrDSMSlotTimeout):
		return nil, CauseNotStarted, nil
	case err != nil:
		return nil, core.Cause(err), nil
	}
	out := []string{}
	for _, n := range names {
		if inZone(n, zone) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, "", nil
}

// startDomainRead replaces the flow's domain read with a new one for the
// chosen zone. Called with w.mu held.
func (w *Wizard) startDomainRead(env core.Env, flowID, gen, zoneID, zone string) (*domainRead, error) {
	if w.domainReads == nil {
		w.domainReads = map[string]*domainRead{}
	}
	w.cancelDomainRead(flowID)
	r := &domainRead{gen: gen, zoneID: zoneID, done: make(chan struct{})}
	job, err := w.options.Background.Go(MailDomainsBudget, func(c context.Context) {
		defer close(r.done)
		r.names, r.cause, r.err = w.readMailDomains(c, env, zone)
	})
	if err != nil {
		return nil, ErrUnavailable // the worker is stopping
	}
	r.job = job
	w.domainReads[flowID] = r
	return r, nil
}

// cancelDomainRead cancels and forgets the flow's domain read, if any: its
// context ends (an executor slot wait or a call gives up at once) and, no
// longer the flow's current read, it can never store. Called with w.mu held.
func (w *Wizard) cancelDomainRead(flowID string) {
	if old := w.domainReads[flowID]; old != nil {
		if old.job != nil {
			old.job.Cancel()
		}
		delete(w.domainReads, flowID)
	}
}

// awaitDomainRead waits at most MailDomainsWait for the flow's read, then
// stores its result in the sign-in (only for the same sign-in and zone) and
// returns the view; still running, the view says "reading".
func (w *Wizard) awaitDomainRead(ctx context.Context, env core.Env, owner, id string, r *domainRead) (CloudView, error) {
	r.job.Touch()
	wait := MailDomainsWait
	if w.domainWait > 0 {
		wait = w.domainWait
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	finished := false
	select {
	case <-r.done:
		finished = true
	case <-timer.C:
	case <-ctx.Done():
		return CloudView{}, ctx.Err()
	}
	w.flowMu.Lock()
	defer w.flowMu.Unlock()
	f, err := w.newPhase(ctx, env, owner, id)
	if err != nil {
		return CloudView{}, err
	}
	if !finished && r.job.Interrupted() {
		// Nobody polled for a while, or the worker stops: unknown, check again.
		finished, r.names, r.cause = true, nil, core.CauseUnavailable
	}
	// Only the flow's current read may store: choosing the same zone again
	// starts a new read with the same sign-in and zone, and the replaced one
	// (canceled, or finished late) must not end the new one's "reading".
	w.mu.Lock()
	current := w.domainReads[id] == r
	w.mu.Unlock()
	if finished && current && f.Cloud != nil && f.Cloud.Gen == r.gen && f.Cloud.ZoneID == r.zoneID && f.Cloud.MailDomainsReading {
		f.Cloud.MailDomains, f.Cloud.MailDomainsCause, f.Cloud.MailDomainsReading = r.names, r.cause, false
		if err := w.save(ctx, env, f); err != nil {
			return CloudView{}, err
		}
		w.mu.Lock()
		if w.domainReads[id] == r {
			delete(w.domainReads, id)
		}
		w.mu.Unlock()
	}
	if finished && current && r.err != nil {
		// The same approval prompt as at detection (publicError/publicCode).
		return CloudView{}, r.err
	}
	return cloudView(f), nil
}

// PollZone returns the sign-in with the zone step's domain read, waiting at
// most MailDomainsWait for it. It reads nothing from Cloudflare.
func (w *Wizard) PollZone(ctx context.Context, env core.Env, owner, id string) (CloudView, error) {
	w.mu.Lock()
	r := w.domainReads[id]
	w.mu.Unlock()
	if r == nil {
		f, err := w.openFlow(ctx, env, owner, id)
		if err != nil {
			return CloudView{}, err
		}
		if f.Cloud != nil && f.Cloud.MailDomainsReading {
			// The read was lost (the worker restarted): unknown, check again.
			w.flowMu.Lock()
			defer w.flowMu.Unlock()
			if f, err = w.newPhase(ctx, env, owner, id); err != nil {
				return CloudView{}, err
			}
			if f.Cloud != nil && f.Cloud.MailDomainsReading {
				f.Cloud.MailDomainsReading, f.Cloud.MailDomainsCause = false, core.CauseUnavailable
				if err := w.save(ctx, env, f); err != nil {
					return CloudView{}, err
				}
			}
		}
		return cloudView(f), nil
	}
	return w.awaitDomainRead(ctx, env, owner, id, r)
}

// matchZone returns the ID of the zone holding domain (the longest name).
func matchZone(domain string, zones []CloudZone) string {
	best := CloudZone{}
	for _, z := range zones {
		if inZone(domain, z.Name) && len(z.Name) > len(best.Name) {
			best = z
		}
	}
	return best.ID
}

// tokenRef is where one sign-in's token is sealed. Each sign-in gets its own
// reference, so a refused new token never replaces the sealed one in use.
func tokenRef(flow, gen string) string { return "secret:mail.setup." + flow + ".token." + gen }

// dropToken deletes the flow's sealed sign-in token once nothing can need it
// any more (a new sign-in, a new wizard, a kept or rolled-back transaction).
// The relay keeps its own copy. flowMu held; the flow is saved by the caller.
func dropToken(ctx context.Context, env core.Env, f *Flow) {
	if f.Cloud == nil || f.Cloud.TokenRef == "" || env.Secrets == nil {
		return
	}
	if err := env.Secrets.Delete(ctx, f.Cloud.TokenRef); err == nil {
		f.Cloud.TokenRef = ""
	}
}

// verified checks the token with Cloudflare (the directory's Accounts is
// the verify step) and returns its accounts. Nothing is sealed yet.
func (w *Wizard) verified(ctx context.Context, env core.Env, token string) (CloudAccess, []CloudAccount, error) {
	access, err := w.options.Directory.Accounts(ctx, env, token)
	if err != nil {
		return CloudAccess{}, nil, directoryError(err)
	}
	accounts, err := cleanAccounts(access.Accounts)
	if err != nil {
		return CloudAccess{}, nil, err
	}
	return access, accounts, nil
}

// link builds the sign-in for a verified token sealed at ref: with exactly
// one account and nothing refused, that account's zones are listed at once.
func (w *Wizard) link(ctx context.Context, env core.Env, access CloudAccess, accounts []CloudAccount, ref, gen string) (*cloudLink, error) {
	link := &cloudLink{Gen: gen, TokenRef: ref, Accounts: accounts, Missing: cleanMissing(access.Missing),
		AccountUnknown: access.AccountUnknown && len(accounts) == 0}
	if len(accounts) == 1 && len(link.Missing) == 0 {
		zones, missing, err := w.options.Directory.Zones(ctx, env, ref, accounts[0].ID)
		if err != nil {
			return nil, directoryError(err)
		}
		if link.Zones, err = cleanZones(zones); err != nil {
			return nil, err
		}
		link.AccountID, link.Missing = accounts[0].ID, cleanMissing(missing)
	}
	return link, nil
}

// Connect signs in with a pasted token. Only a flow still collecting answers
// may sign in: nothing is written for any other. The token is verified first,
// held in memory only: a token no Cloudflare verify endpoint accepted is never
// sealed, and no permission is reported missing for it. Once accepted, it is
// sealed under a fresh reference and replaces the flow's sign-in; if anything
// fails after that, the new secret is deleted. The old
// sign-in's token is deleted when the new one takes its place. With exactly
// one account (and nothing refused) the account is chosen and its zones are
// listed at once. A new sign-in discards what rested on the old one
// (account, zone, plan and, for a Cloudflare domain, the detection).
func (w *Wizard) Connect(ctx context.Context, env core.Env, owner, id, token string) (CloudView, error) {
	if token == "" || len(token) > 512 || strings.ContainsAny(token, " \r\n\t") {
		return CloudView{}, ErrInvalid
	}
	// A flow with applied changes whose token Cloudflare refused takes a new
	// token in place (reconnect.go).
	w.flowMu.Lock()
	cur, err := w.load(ctx, env, owner, id)
	again := err == nil && !w.running[cur.ID] && reconnectable(cur)
	w.flowMu.Unlock()
	if again {
		return w.reconnect(ctx, env, owner, id, token)
	}
	// The flow first: another owner's or a non-new flow gets no secret write.
	if _, err := w.openFlow(ctx, env, owner, id); err != nil {
		return CloudView{}, err
	}
	if w.options.Directory == nil || env.Secrets == nil {
		return CloudView{}, ErrUnavailable
	}
	access, accounts, err := w.verified(ctx, env, token)
	if err != nil {
		return CloudView{}, err
	}
	gen, err := newFlowID()
	if err != nil {
		return CloudView{}, err
	}
	ref := tokenRef(id, gen)
	if err := env.Secrets.Put(ctx, ref, token); err != nil {
		return CloudView{}, ErrUnavailable
	}
	promoted := false
	defer func() {
		if !promoted {
			_ = env.Secrets.Delete(context.WithoutCancel(ctx), ref)
		}
	}()
	link, err := w.link(ctx, env, access, accounts, ref, gen)
	if err != nil {
		return CloudView{}, err
	}
	w.flowMu.Lock()
	defer w.flowMu.Unlock()
	f, err := w.newPhase(ctx, env, owner, id)
	if err != nil {
		return CloudView{}, err
	}
	w.forgetSelection(f)
	old := f.Cloud
	f.Cloud = link
	if err := w.save(ctx, env, f); err != nil {
		f.Cloud = old
		return CloudView{}, err
	}
	promoted = true
	if old != nil && old.TokenRef != "" && old.TokenRef != ref {
		_ = env.Secrets.Delete(ctx, old.TokenRef)
	}
	return cloudView(f), nil
}

// Zones chooses an account of the sign-in and lists its zones again (the
// "Check again" after registering a domain reads the same way). With zoneID,
// it also chooses that zone: only an active zone from the fresh list, read
// the way the plan will. DNS is always read (every automated plan writes
// DNS); Email Sending only once the flow's decision takes the Cloudflare
// relay, so a direct path never asks for it. Choosing another account or zone
// discards what rested on the old one.
func (w *Wizard) Zones(ctx context.Context, env core.Env, owner, id, accountID, zoneID string) (CloudView, error) {
	if w.options.Directory == nil {
		return CloudView{}, ErrUnavailable
	}
	if accountID == "" && zoneID == "" {
		return w.recheckAccount(ctx, env, owner, id)
	}
	if !identifier(accountID) || zoneID != "" && !identifier(zoneID) {
		return CloudView{}, ErrInvalid
	}
	f, err := w.openFlow(ctx, env, owner, id)
	if err != nil {
		return CloudView{}, err
	}
	relay, inbound := false, false
	if _, d, err := detected(f); err == nil {
		relay, inbound = d.Send == RelaySend, d.Receive == RoutingReceive
	}
	if f.Cloud == nil {
		return CloudView{}, ErrStale
	}
	gen, tokenRef := f.Cloud.Gen, f.Cloud.TokenRef
	known := false
	for _, a := range f.Cloud.Accounts {
		known = known || a.ID == accountID
	}
	if !known {
		return CloudView{}, ErrInvalid
	}
	zones, missing, err := w.options.Directory.Zones(ctx, env, tokenRef, accountID)
	if err != nil {
		return CloudView{}, directoryError(err)
	}
	if zones, err = cleanZones(zones); err != nil {
		return CloudView{}, err
	}
	if zoneID != "" {
		// Only a zone of the list just read, and only an active one.
		z, ok := (&cloudLink{Zones: zones}).zone(zoneID)
		if !ok || z.Status != "active" {
			return CloudView{}, ErrInvalid
		}
	}
	if zoneID != "" && len(missing) == 0 {
		if missing, err = w.options.Directory.Probe(ctx, env, tokenRef, accountID, zoneID, relay, inbound); err != nil {
			return CloudView{}, directoryError(err)
		}
	}

	view, read, err := w.storeZone(ctx, env, owner, id, gen, accountID, zoneID, zones, missing)
	if err != nil || read == nil {
		return view, err
	}
	// The flow lock is released: the read runs in the background.
	return w.awaitDomainRead(ctx, env, owner, id, read)
}

// storeZone records the chosen account and zone under the flow lock and
// starts the zone's MailPlus domain read (nil without a zone).
func (w *Wizard) storeZone(ctx context.Context, env core.Env, owner, id, gen, accountID, zoneID string, zones []CloudZone, missing []string) (CloudView, *domainRead, error) {
	w.flowMu.Lock()
	defer w.flowMu.Unlock()
	f, err := w.newPhase(ctx, env, owner, id)
	if err != nil {
		return CloudView{}, nil, err
	}
	if f.Cloud == nil || f.Cloud.Gen != gen {
		// Signed in again meanwhile: this read was for the older token.
		return CloudView{}, nil, ErrStale
	}
	before := digest(f.Cloud)
	if f.Cloud.AccountID != accountID || f.Cloud.ZoneID != zoneID {
		w.forgetSelection(f)
	}
	f.Cloud.AccountID, f.Cloud.Zones, f.Cloud.ZoneID, f.Cloud.Missing = accountID, zones, zoneID, cleanMissing(missing)
	f.Cloud.AccountUnknown = false
	// The Cloudflare source picks the mail domain from MailPlus Server's
	// domains in the chosen zone, never the apex by default. The flow learns
	// its source only at detection, so the list is read for every chosen zone
	// (a new read each time: choosing the zone again is the Check again).
	f.Cloud.MailDomains, f.Cloud.MailDomainsCause, f.Cloud.MailDomainsReading = nil, "", false
	var read *domainRead
	if zoneID == "" {
		// No zone chosen (another account, or the same account listed
		// again): the read for the old zone must never store and must not
		// hold an executor slot until its budget ends.
		w.mu.Lock()
		w.cancelDomainRead(f.ID)
		w.mu.Unlock()
	} else {
		z, _ := (&cloudLink{Zones: zones}).zone(zoneID)
		w.mu.Lock()
		read, err = w.startDomainRead(env, f.ID, gen, zoneID, z.Name)
		w.mu.Unlock()
		if err != nil {
			return CloudView{}, nil, err
		}
		f.Cloud.MailDomainsReading = true
	}
	if digest(f.Cloud) != before || read != nil {
		if err := w.save(ctx, env, f); err != nil {
			return CloudView{}, nil, err
		}
	}
	return cloudView(f), read, nil
}

// recheckAccount reads the sign-in's accounts again with the sealed token:
// the "Check again" of a token whose account was unknown (no zone yet).
func (w *Wizard) recheckAccount(ctx context.Context, env core.Env, owner, id string) (CloudView, error) {
	f, err := w.openFlow(ctx, env, owner, id)
	if err != nil {
		return CloudView{}, err
	}
	if f.Cloud == nil || f.Cloud.TokenRef == "" || !f.Cloud.AccountUnknown {
		return CloudView{}, ErrStale
	}
	gen, ref := f.Cloud.Gen, f.Cloud.TokenRef
	if env.Secrets == nil {
		return CloudView{}, ErrUnavailable
	}
	token, err := env.Secrets.Get(ctx, ref)
	if err != nil || token == "" {
		return CloudView{}, ErrUnavailable
	}
	access, accounts, err := w.verified(ctx, env, token)
	if err != nil {
		return CloudView{}, err
	}
	link, err := w.link(ctx, env, access, accounts, ref, gen)
	if err != nil {
		return CloudView{}, err
	}
	w.flowMu.Lock()
	defer w.flowMu.Unlock()
	if f, err = w.newPhase(ctx, env, owner, id); err != nil {
		return CloudView{}, err
	}
	if f.Cloud == nil || f.Cloud.Gen != gen {
		return CloudView{}, ErrStale
	}
	if digest(link) != digest(f.Cloud) {
		w.forgetSelection(f)
		f.Cloud = link
		if err := w.save(ctx, env, f); err != nil {
			return CloudView{}, err
		}
	}
	return cloudView(f), nil
}

// directoryError keeps the fixed codes only.
func directoryError(err error) error {
	switch {
	case errors.Is(err, ErrTokenInvalid):
		return ErrTokenInvalid
	case errors.Is(err, ErrCloudflareUnavailable):
		return ErrCloudflareUnavailable
	case errors.Is(err, ErrSendingPlan):
		return ErrSendingPlan
	case errors.Is(err, context.Canceled):
		return err
	}
	return ErrUnavailable
}
