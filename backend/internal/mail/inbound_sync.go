package mail

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/cloudflare"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

// Kept Cloudflare setups and the mailbox sync (owner decisions
// 2026-11-13). Receiving through Cloudflare has two modes, chosen in the
// setup:
//
//   - whole domain: the apex zone's unused catch-all points at the Worker;
//     adding or removing MailPlus users needs nothing, and nothing syncs;
//   - per address: one exact rule per mailbox. The Overview's "Sync
//     mailboxes" (mail.inbound.sync) re-reads MailPlus's users, adds the
//     missing rules and removes this setup's rules for users that are gone.
//     Only the administrator's click starts it: no run on opening the
//     Overview, no polling, no schedule, no watcher (hibernation).
//
// A kept setup is recorded (KV mail.kept/<flow>) with what it applied and
// the setup's sealed Cloudflare token, which the record owns from then on:
// the sync and the removal of the setup use it. The token never reaches a
// record, a reply or a log; forgetting the token or removing the setup
// deletes it.

const keptModule = "mail.kept"

// syncMaxWrites bounds the Cloudflare writes of one sync run.
const syncMaxWrites = 100

// SyncWait is how long one mail.inbound.sync call waits for its run.
const SyncWait = 8 * time.Second

// SyncBudget bounds one run: the MailPlus account read and the rule writes.
const SyncBudget = detect.DSMPassBudget + 2*time.Minute

// keptRecord is one kept setup. Public values, the journal of what was
// applied (with snapshots), and the token's reference only.
type keptRecord struct {
	ID        string                `json:"id"`
	Domain    string                `json:"domain"`
	Intent    setup.Intent          `json:"intent,omitempty"`
	AccountID string                `json:"accountId"`
	ZoneID    string                `json:"zoneId"`
	TokenRef  string                `json:"tokenRef,omitempty"`
	Applied   []setup.AppliedChange `json:"applied,omitempty"`
	// Inbound: the setup receives through Cloudflare.
	Inbound *keptInbound `json:"inbound,omitempty"`
	// Legacy: adopted from a build ≤40 inbound record (mail.wiring), which
	// has no journal and may have been rolled back; it syncs only while the
	// zone still holds at least one of its rules.
	Legacy bool `json:"legacy,omitempty"`
	// RoutingOwned: this setup enabled Email Routing on the zone apex (its
	// journal has the routing step); only then may removal turn it off.
	RoutingOwned bool `json:"routingOwned,omitempty"`
	// RoutingDNS: the domain's receiving DNS ledger (routing_dns.go) holds
	// records this App created or changed when it enabled Email Routing on
	// the subdomain; removal deletes or restores exactly those.
	RoutingDNS bool `json:"routingDns,omitempty"`
	// TokenInvalid: Cloudflare refused the kept token (deleted or rolled in
	// the dashboard), seen by the relay's login or a Cloudflare call and
	// confirmed by the verify endpoint. Cleared by a replacement or a call
	// that succeeds. Never a secret (token_state.go).
	TokenInvalid bool `json:"tokenInvalid,omitempty"`
	// Synced: the mailboxes the last completed sync (or the setup) left
	// receiving through this setup's rules, kept so the Overview can say how
	// many without asking Cloudflare. Per-address setups only.
	Synced *Synced `json:"synced,omitempty"`
}

// Synced is how many mailboxes receive through a per-address setup's rules
// after its last completed sync (or the setup itself), with what that sync
// added and removed (zero for the setup) and when. Counts only, no address.
type Synced struct {
	Mailboxes int   `json:"mailboxes"`
	Added     int   `json:"added,omitempty"`
	Removed   int   `json:"removed,omitempty"`
	At        int64 `json:"at,omitempty"`
	// Set: the hashed addresses (mailboxSet) that receive through the
	// setup's rules, so the automatic sync can tell a changed mailbox set
	// without Cloudflare. Never shown.
	Set []string `json:"set,omitempty"`
}

type keptInbound struct {
	Owner string `json:"owner"`
	Mode  string `json:"mode"`
}

func keptKey(id string) string { return "setup." + id }
func keptTokenRef(id string) string {
	return "secret:mail.kept." + fingerprint([]string{id, "token"})[:32]
}

// SyncRun is the outcome of the last sync run of a domain (worker memory).
type SyncRun struct {
	// State: running, done, failed.
	State   string `json:"state"`
	Added   int    `json:"added"`
	Removed int    `json:"removed"`
	// Pending: mailboxes that still cannot receive (another rule routes them,
	// the zone's rule limit, or a write that failed).
	Pending   int      `json:"pending"`
	Addresses []string `json:"addresses,omitempty"`
	// CauseKey (failed): why nothing could be decided, a catalog key.
	CauseKey string `json:"causeKey,omitempty"`
	At       int64  `json:"at,omitempty"`
}

// KeptView is what the Overview shows of one kept Cloudflare setup.
type KeptView struct {
	ID     string       `json:"id"`
	Domain string       `json:"domain"`
	Intent setup.Intent `json:"intent,omitempty"`
	// Receive: the receiving mode through Cloudflare (domain or addresses),
	// empty when this setup does not receive through Cloudflare.
	Receive string `json:"receive,omitempty"`
	// Token: a sealed Cloudflare token is kept for this setup.
	Token bool `json:"token"`
	// TokenInvalid: Cloudflare refused the kept token; sending through the
	// relay, the sync and the removal wait for a new one.
	TokenInvalid bool `json:"tokenInvalid,omitempty"`
	// Relay: this setup sends through the relay (its token is the relay's
	// SMTP login).
	Relay bool     `json:"relay,omitempty"`
	Last  *SyncRun `json:"last,omitempty"`
	// Synced: the stored count of the last completed sync (or the setup);
	// survives a worker restart, unlike Last.
	Synced *Synced `json:"synced,omitempty"`
	// Auto: the automatic sync's state (per-address setups; nil until the
	// worker checked the setup).
	Auto *AutoState `json:"auto,omitempty"`
	// Removes: what removing the setup takes away, as catalog keys.
	Removes []string `json:"removes"`
	// RoutingOwned: removal may also turn Email Routing off on the zone.
	RoutingOwned bool       `json:"routingOwned,omitempty"`
	Removal      *RemoveRun `json:"removal,omitempty"`
}

// KeptList lists the kept Cloudflare setups.
type KeptList struct {
	Setups []KeptView `json:"setups"`
}

// MailboxReader reads one domain's MailPlus accounts (State.Accounts).
type MailboxReader interface {
	ReadAccounts(ctx context.Context, env core.Env, domain string) detect.State
}

// InboundSync implements setup.InboundSync and the Overview's operations.
type InboundSync struct {
	cloud      *cloudflareAdapter
	reader     MailboxReader
	background *core.Background
	wait       time.Duration
	// undo is the setup's rollback of one journal step
	// (setup.Wizard.RollbackChange); relayOff turns the relay off.
	undo     func(context.Context, core.Env, core.Change, json.RawMessage) error
	relayOff func(context.Context, core.Env) error

	mu       sync.Mutex
	runs     map[string]*syncJob
	removals map[string]*removeJob
	// relayRefused: the relay's last reported AUTH result (nil: none yet).
	relayRefused *bool
	// tokenMu serialises the token state's read-modify-write of records.
	tokenMu sync.Mutex
	// locks: one per setup (autosync.go); autos: the automatic sync's
	// memory; wake nudges its loop.
	locks map[string]*sync.Mutex
	autos map[string]*autoMemo
	wake  chan struct{}
}

type syncJob struct {
	done chan struct{}
	run  SyncRun
}

// ---------- setup.InboundSync ----------

// ReceiveModes: the whole-domain mode needs the zone apex and an unused
// catch-all. Reads the zone and its catch-all with the sign-in token.
func (s *InboundSync) ReceiveModes(ctx context.Context, env core.Env, tokenRef, zoneID, domain string) (setup.ReceiveModes, error) {
	client, _, err := s.cloud.signInClient(ctx, env, tokenRef, "")
	if err != nil {
		return setup.ReceiveModes{}, err
	}
	zone, err := client.GetZone(ctx, zoneID)
	if err != nil {
		return setup.ReceiveModes{}, setup.ErrCloudflareUnavailable
	}
	if !strings.EqualFold(zone.Name, domain) {
		return setup.ReceiveModes{DomainReason: "mail.setup.receive.subdomain"}, nil
	}
	rule, err := client.CatchAll(ctx, zoneID)
	if err != nil {
		return setup.ReceiveModes{}, setup.ErrCloudflareUnavailable
	}
	if !cloudflare.CatchAllUnused(rule) {
		return setup.ReceiveModes{DomainReason: "mail.setup.receive.inUse"}, nil
	}
	return setup.ReceiveModes{Domain: true}, nil
}

// Kept records a kept setup (with its journal) and takes over its sealed
// token. Only a setup with a Cloudflare change is recorded.
func (s *InboundSync) Kept(ctx context.Context, env core.Env, kept setup.KeptSetup) error {
	if env.KV == nil || env.Secrets == nil {
		return core.ErrUnavailable
	}
	rec := keptRecord{ID: kept.FlowID, Domain: kept.Domain, Intent: kept.Intent, AccountID: kept.AccountID, ZoneID: kept.ZoneID,
		TokenRef: kept.TokenRef, Applied: kept.Applied}
	cloud := false
	for _, a := range kept.Applied {
		cloud = cloud || strings.HasPrefix(a.Change.Target, "cloudflare.")
		step := a.Change.Params["inbound"]
		if step == "routing" {
			op, err := cloudOp(ctx, env, a.Change)
			if err != nil || op.Inbound == nil {
				return core.ErrUnavailable
			}
			rec.RoutingOwned = op.Inbound.Subdomain == ""
			continue
		}
		if step != "rules" && step != "catchall" {
			continue
		}
		op, err := cloudOp(ctx, env, a.Change)
		if err != nil || op.Inbound == nil {
			return core.ErrUnavailable
		}
		mode := op.Inbound.Mode
		if mode == "" {
			mode = setup.ReceiveAddresses
		}
		rec.Inbound = &keptInbound{Owner: op.Owner, Mode: mode}
		if mode == setup.ReceiveAddresses {
			rec.Synced = &Synced{Mailboxes: len(op.Inbound.Addresses), At: nowOf(env).Unix(), Set: mailboxSet(op.Inbound.Addresses)}
		}
	}
	if !cloud {
		return core.ErrNotFound // nothing on Cloudflare: the flow drops its token
	}
	if _, found, err := loadLedger(ctx, env, rec.Domain); err != nil {
		return core.ErrUnavailable
	} else if found {
		rec.RoutingDNS = true
	}
	return env.KV.Put(ctx, keptModule, keptKey(rec.ID), rec)
}

// ---------- Records ----------

// records lists the kept setups: this build's records, plus build ≤40
// inbound records (mail.wiring inbound.<domain>, per address, no journal)
// that no kept record covers, adopted as legacy.
func (s *InboundSync) records(ctx context.Context, env core.Env) ([]keptRecord, error) {
	lister, ok := env.KV.(core.KeyLister)
	if env.KV == nil || !ok {
		return nil, core.ErrUnavailable
	}
	out := []keptRecord{}
	owners := map[string]bool{}
	keys, err := lister.Keys(ctx, keptModule, "setup.")
	if err != nil {
		return nil, core.ErrUnavailable
	}
	for _, k := range keys {
		var rec keptRecord
		if found, err := env.KV.Get(ctx, keptModule, k, &rec); err != nil {
			return nil, core.ErrUnavailable
		} else if found && rec.ID != "" && keptKey(rec.ID) == k {
			out = append(out, rec)
			if rec.Inbound != nil {
				owners[rec.Inbound.Owner] = true
			}
		}
	}
	legacy, err := lister.Keys(ctx, "mail.wiring", "inbound.")
	if err != nil {
		return nil, core.ErrUnavailable
	}
	for _, k := range legacy {
		var op cloudOperation
		if found, err := env.KV.Get(ctx, "mail.wiring", k, &op); err != nil || !found {
			continue
		}
		r := op.Request
		// Rolled back (this build clears it), a check record, or one a kept
		// record already covers.
		if op.Inbound == nil || r.Domain == "" || "inbound."+r.Domain != k || owners[op.Owner] || op.Inbound.Mode == setup.ReceiveDomain {
			continue
		}
		out = append(out, keptRecord{ID: legacyID(r.Domain), Domain: r.Domain, AccountID: r.AccountID, ZoneID: r.ZoneID,
			Inbound: &keptInbound{Owner: op.Owner, Mode: setup.ReceiveAddresses}, Legacy: true})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func legacyID(domain string) string { return fingerprint([]string{domain, "legacy"})[:32] }

func (s *InboundSync) record(ctx context.Context, env core.Env, id string) (keptRecord, error) {
	all, err := s.records(ctx, env)
	if err != nil {
		return keptRecord{}, err
	}
	for _, rec := range all {
		if rec.ID == id {
			return rec, nil
		}
	}
	return keptRecord{}, setup.ErrNoFlow
}

func (s *InboundSync) view(rec keptRecord) KeptView {
	v := KeptView{ID: rec.ID, Domain: rec.Domain, Intent: rec.Intent, Token: rec.TokenRef != "", Removes: removes(rec), RoutingOwned: rec.RoutingOwned,
		TokenInvalid: rec.TokenInvalid && rec.TokenRef != "", Relay: usesRelay(rec)}
	if rec.Inbound != nil {
		v.Receive = rec.Inbound.Mode
	}
	if rec.Synced != nil && v.Receive == setup.ReceiveAddresses {
		synced := *rec.Synced
		synced.Set = nil
		v.Synced = &synced
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if v.Receive == setup.ReceiveAddresses {
		v.Auto = s.autoView(rec.ID)
	}
	if job := s.runs[rec.ID]; job != nil {
		run := job.run
		v.Last = &run
	}
	if job := s.removals[rec.ID]; job != nil {
		run := job.run
		v.Removal = &run
	}
	return v
}

func (s *InboundSync) forget(id string) {
	s.mu.Lock()
	delete(s.runs, id)
	s.mu.Unlock()
}

// Status lists the kept setups with the last sync run of each. It reads
// the package's own records only: no DSM or Cloudflare call, no write.
func (s *InboundSync) Status(ctx context.Context, env core.Env) (KeptList, error) {
	all, err := s.records(ctx, env)
	if err != nil {
		return KeptList{}, err
	}
	out := KeptList{Setups: []KeptView{}}
	for _, rec := range all {
		out.Setups = append(out.Setups, s.view(rec))
	}
	// The automatic sync (if it runs) looks again in the background; this
	// call itself still reads records only.
	s.nudge()
	return out, nil
}

// SetToken replaces the Cloudflare token of a kept setup everywhere it is
// used (verified first with every permission the setup needs, held in
// memory until then): sealed under the record's own name, copied to the
// relay when this setup's relay holds a token, and the invalid state
// cleared. The removal answers the journal's sign-in token reference with
// it (tokenAlias). An empty token forgets the kept token (the relay keeps
// its copy). A legacy setup is recorded on the way, so its token has an
// owner.
func (s *InboundSync) SetToken(ctx context.Context, env core.Env, id, token string) (KeptView, error) {
	token = strings.TrimSpace(token)
	if len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return KeptView{}, setup.ErrInvalid
	}
	rec, err := s.record(ctx, env, id)
	if err != nil {
		return KeptView{}, err
	}
	if token == "" {
		if rec.TokenRef != "" {
			if err := env.Secrets.Delete(ctx, rec.TokenRef); err != nil {
				return KeptView{}, setup.ErrUnavailable
			}
		}
		rec.TokenRef, rec.TokenInvalid = "", false
	} else {
		if err := s.VerifyToken(ctx, rec, token); err != nil {
			return KeptView{}, err
		}
		ref := keptTokenRef(rec.ID)
		if err := env.Secrets.Put(ctx, ref, token); err != nil {
			return KeptView{}, setup.ErrUnavailable
		}
		if err := replaceRelayToken(ctx, env, rec, token); err != nil {
			return KeptView{}, err
		}
		if rec.TokenRef != "" && rec.TokenRef != ref {
			_ = env.Secrets.Delete(ctx, rec.TokenRef)
		}
		rec.TokenRef, rec.TokenInvalid = ref, false
		if usesRelay(rec) {
			// The relay's next login reports again.
			s.mu.Lock()
			s.relayRefused = nil
			s.mu.Unlock()
		}
	}
	s.tokenMu.Lock()
	err = env.KV.Put(ctx, keptModule, keptKey(rec.ID), rec)
	s.tokenMu.Unlock()
	if err != nil {
		return KeptView{}, setup.ErrUnavailable
	}
	if env.Log != nil {
		env.Log.Info("cloudflare token replaced", "domain", rec.Domain, "kept", rec.TokenRef != "")
	}
	s.forget(rec.ID)
	return s.view(rec), nil
}

// Sync starts one run for a per-address setup (unless one runs) and waits
// at most SyncWait for it; poll only waits for the current run.
func (s *InboundSync) Sync(ctx context.Context, env core.Env, id string, poll bool) (KeptView, error) {
	rec, err := s.record(ctx, env, id)
	if err != nil {
		return KeptView{}, err
	}
	if rec.Inbound == nil || rec.Inbound.Mode != setup.ReceiveAddresses {
		return KeptView{}, setup.ErrInvalid
	}
	s.mu.Lock()
	if s.runs == nil {
		s.runs = map[string]*syncJob{}
	}
	job := s.runs[rec.ID]
	running := job != nil && job.run.State == "running"
	if !running && !poll {
		if rec.TokenRef == "" {
			s.mu.Unlock()
			return KeptView{}, setup.ErrSyncTokenRequired
		}
		job = &syncJob{done: make(chan struct{}), run: SyncRun{State: "running"}}
		s.runs[rec.ID] = job
		if _, err := s.background.Go(SyncBudget, func(run context.Context) {
			// Never beside an automatic run or a removal of this setup.
			l := s.lock(rec.ID)
			l.Lock()
			defer l.Unlock()
			result := SyncRun{State: "failed", CauseKey: "mail.inbound.cause.gone", At: nowOf(env).Unix()}
			if fresh, err := s.record(run, env, rec.ID); err == nil && fresh.Inbound != nil {
				result = s.run(run, env, fresh)
			}
			s.manualDone(env, rec.ID, result)
			s.mu.Lock()
			job.run = result
			s.mu.Unlock()
			close(job.done)
		}); err != nil {
			delete(s.runs, rec.ID)
			s.mu.Unlock()
			return KeptView{}, setup.ErrUnavailable
		}
	}
	s.mu.Unlock()
	if job != nil {
		wait := s.wait
		if wait == 0 {
			wait = SyncWait
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-job.done:
		case <-timer.C:
		case <-ctx.Done():
			return KeptView{}, ctx.Err()
		}
		// A completed run kept its count on the record: show that one.
		if fresh, err := s.record(ctx, env, rec.ID); err == nil {
			rec = fresh
		}
	}
	return s.view(rec), nil
}

// run is one sync: read the domain's MailPlus mailboxes (the same filters
// as the setup, setup.Mailboxes), then let the client add and remove this
// setup's rules. A MailPlus read that is not definite changes nothing.
func (s *InboundSync) run(ctx context.Context, env core.Env, rec keptRecord) SyncRun {
	out := SyncRun{State: "failed", At: nowOf(env).Unix()}
	logRun := func(r SyncRun) SyncRun {
		if env.Log != nil {
			env.Log.Info("inbound mailbox sync", "domain", rec.Domain, "state", r.State, "added", r.Added,
				"removed", r.Removed, "pending", r.Pending, "cause", r.CauseKey)
		}
		return r
	}
	if s.reader == nil {
		out.CauseKey = "mail.inbound.cause.mailplus"
		return logRun(out)
	}
	state := s.reader.ReadAccounts(ctx, env, rec.Domain)
	if err := detect.StatusOf(state.Package).Err(); err != nil || !state.Accounts[rec.Domain].IsKnown() {
		out.CauseKey = "mail.inbound.cause.mailplus"
		return logRun(out)
	}
	state.Domain = rec.Domain
	want := setup.Mailboxes(state)
	extra := []string{}
	if len(want) > setup.MaxMailboxes {
		want, extra = want[:setup.MaxMailboxes], want[setup.MaxMailboxes:]
	}
	token, err := env.Secrets.Get(ctx, rec.TokenRef)
	if err != nil || token == "" || s.cloud.newClient == nil {
		out.CauseKey = "mail.inbound.cause.token"
		return logRun(out)
	}
	client, err := s.cloud.newClient(cloudflare.Config{Token: token, OwnerID: rec.Inbound.Owner})
	if err != nil {
		out.CauseKey = "mail.inbound.cause.token"
		return logRun(out)
	}
	if rec.Legacy {
		// A build ≤40 record may outlive a rollback: sync only while the
		// zone still holds this setup's rules.
		owned, err := client.OwnedRoutingRules(ctx, rec.ZoneID)
		if err != nil {
			out.CauseKey = syncCause(err)
			if tokenRefusal(err) {
				s.cloudRefused(ctx, env, rec, token)
			}
			return logRun(out)
		}
		if len(owned) == 0 {
			out.CauseKey = "mail.inbound.cause.gone"
			return logRun(out)
		}
	}
	result, err := client.SyncRoutingRules(ctx, rec.ZoneID, rec.Domain, want, syncMaxWrites)
	if err != nil {
		out.CauseKey = syncCause(err)
		if tokenRefusal(err) {
			s.cloudRefused(ctx, env, rec, token)
		}
		return logRun(out)
	}
	if rec.TokenInvalid {
		// Cloudflare accepted the token again.
		_ = s.markToken(ctx, env, func(r keptRecord) bool { return r.ID == rec.ID }, false)
	}
	out.State, out.Added, out.Removed = "done", len(result.Added), len(result.Removed)
	for _, p := range result.Pending {
		out.Addresses = append(out.Addresses, p.Address)
	}
	out.Addresses = append(out.Addresses, extra...)
	out.Pending = len(out.Addresses)
	synced := Synced{Mailboxes: len(want) - len(result.Pending), Added: out.Added, Removed: out.Removed, At: out.At,
		Set: routedSet(want, result)}
	if err := s.saveSynced(ctx, env, rec.ID, synced); err != nil && env.Log != nil {
		env.Log.Info("inbound mailbox sync count not kept", "domain", rec.Domain)
	}
	return logRun(out)
}

// saveSynced keeps a completed sync's count on the setup's record (read
// again under the records' lock, so a token mark is not lost).
func (s *InboundSync) saveSynced(ctx context.Context, env core.Env, id string, synced Synced) error {
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()
	rec, err := s.record(ctx, env, id)
	if err != nil {
		return err
	}
	if rec.Legacy {
		// A build ≤40 record lives in mail.wiring: the count stays in memory (Last).
		return nil
	}
	rec.Synced = &synced
	return env.KV.Put(ctx, keptModule, keptKey(rec.ID), rec)
}

func nowOf(env core.Env) time.Time {
	if env.Now != nil {
		return env.Now()
	}
	return time.Now()
}

func syncCause(err error) string {
	switch {
	case cloudflare.PermissionRefused(err), cloudflare.IsKind(err, cloudflare.ErrAuth):
		return "mail.inbound.cause.token"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "mail.inbound.cause.interrupted"
	}
	return "mail.inbound.cause.cloudflare"
}

var _ setup.InboundSync = (*InboundSync)(nil)
var _ MailboxReader = (*detect.Detector)(nil)
