package mail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/cloudflare"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

// Automatic mailbox sync (owner decision 2026-11-16): a per-address
// setup follows MailPlus by itself, so a new MailPlus user receives without
// anyone pressing 同步信箱 (which stays, as "sync now").
//
// Upgrade-safe by construction (owner concern 2026-11-16):
//   - It makes the same DSM read as the setup and the manual sync
//     (SYNO.MailPlusServer.Domain.User list v1, through ReadAccounts) and no
//     other; no new or private API.
//   - It fails safe: MailPlus stopped, upgrading or restarting, a read that
//     fails, times out or is not definite, or an empty mailbox list: the run
//     makes no Cloudflare call at all, logs a fixed code and tries again
//     later, backing off.
//   - A reply whose shape changed (the API no longer offered in that
//     version, an incomplete reply, a DSM reply that does not decode) stops
//     the automatic sync of that setup until the worker restarts or the
//     administrator syncs by hand; the Overview says why. It never guesses.
//   - Cloudflare is asked only when the mailbox set differs from the one the
//     last sync left (kept as hashes on the record), or for a reconcile every
//     AutoReconcile. It adds rules freely; it removes at most
//     autoRemovalLimit of this setup's rules in one run, and only after a
//     healthy read with MailPlus running. A larger removal is left for the
//     administrator: the Overview says 同步信箱 will remove N.
//   - It never overlaps a manual sync or a removal of the same setup (the
//     setup's lock), and re-reads the record under that lock, so a removed
//     setup is never synced again.

const (
	// AutoInterval is how often a healthy setup is checked.
	AutoInterval = 10 * time.Minute
	// AutoMaxBackoff caps the wait after repeated failures.
	AutoMaxBackoff = 2 * time.Hour
	// AutoReconcile: even with an unchanged mailbox set, Cloudflare is read
	// this often (a rule deleted in the dashboard comes back).
	AutoReconcile = 6 * time.Hour
	// autoStartDelay lets the worker settle before the first run.
	autoStartDelay = time.Minute
	// autoNudgeAge: opening the Overview checks a healthy setup again when
	// its last check is at least this old.
	autoNudgeAge = time.Minute
)

// Automatic sync causes (catalog keys). Token and Cloudflare failures use
// the manual sync's keys.
const (
	autoCauseMailPlus = "mail.inbound.auto.cause.mailplus"
	autoCauseStopped  = "mail.inbound.auto.cause.stopped"
	autoCauseChanged  = "mail.inbound.auto.cause.changed"
	autoCauseEmpty    = "mail.inbound.auto.cause.empty"
	autoCauseApproval = "mail.inbound.auto.cause.approval"
)

// AutoState is what the Overview shows of a setup's automatic sync.
type AutoState struct {
	// State: ok, failing (tried again later), stopped (the reply's shape
	// changed: waits for a manual sync or a worker restart).
	State    string `json:"state"`
	CauseKey string `json:"causeKey,omitempty"`
	// Unsynced: MailPlus mailboxes the last read found without this
	// setup's rule (known only once a sync kept its mailbox set).
	Unsynced int `json:"unsynced,omitempty"`
	// Held: rules a manual sync would remove that the automatic sync left.
	Held int `json:"held,omitempty"`
	// CheckedAt: the last time the automatic sync found the setup in line.
	CheckedAt int64 `json:"checkedAt,omitempty"`
}

// autoMemo is the worker's memory of one setup's automatic sync.
type autoMemo struct {
	state    AutoState
	failures int
	next     time.Time
	// cloudAt: the last time Cloudflare was asked (manual or automatic).
	cloudAt time.Time
}

// autoRemovalLimit: an automatic run removes at most two rules, or a fifth
// of the setup's rules when that is more.
func autoRemovalLimit(owned int) int { return max(2, owned/5) }

// mailboxSet hashes addresses (case-insensitive) so the record can tell a
// changed mailbox set without keeping the addresses.
func mailboxSet(addresses []string) []string {
	out := make([]string, 0, len(addresses))
	for _, a := range addresses {
		sum := sha256.Sum256([]byte(strings.ToLower(a)))
		out = append(out, hex.EncodeToString(sum[:8]))
	}
	sort.Strings(out)
	return out
}

// lock is the setup's lock: a sync (manual or automatic) and a removal of
// the same setup never overlap.
func (s *InboundSync) lock(id string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locks == nil {
		s.locks = map[string]*sync.Mutex{}
	}
	if s.locks[id] == nil {
		s.locks[id] = &sync.Mutex{}
	}
	return s.locks[id]
}

func (s *InboundSync) memo(id string) *autoMemo {
	if s.autos == nil {
		s.autos = map[string]*autoMemo{}
	}
	if s.autos[id] == nil {
		s.autos[id] = &autoMemo{}
	}
	return s.autos[id]
}

// autoView is the setup's automatic state for the Overview (nil: not
// checked yet). Callers hold s.mu.
func (s *InboundSync) autoView(id string) *AutoState {
	m := s.autos[id]
	if m == nil || m.state.State == "" {
		return nil
	}
	v := m.state
	return &v
}

// nudge asks the automatic sync to look at healthy setups now (opening the
// Overview). It never blocks and does nothing when the loop is not running.
func (s *InboundSync) nudge() {
	if s.wake == nil {
		return
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// AutoSync runs the automatic sync until ctx ends. env is the worker's own
// environment (shared background reads; no caller).
func (s *InboundSync) AutoSync(ctx context.Context, env core.Env) {
	s.mu.Lock()
	if s.wake == nil {
		s.wake = make(chan struct{}, 1)
	}
	wake := s.wake
	s.mu.Unlock()
	timer := time.NewTimer(autoStartDelay)
	defer timer.Stop()
	for {
		nudged := false
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-wake:
			nudged = true
		}
		s.AutoPass(ctx, env, nudged)
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(s.autoWait(nowOf(env)))
	}
}

// autoWait is the time until the earliest setup is due (at most
// AutoInterval).
func (s *InboundSync) autoWait(now time.Time) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	wait := AutoInterval
	for _, m := range s.autos {
		if d := m.next.Sub(now); d < wait {
			wait = max(d, time.Second)
		}
	}
	return wait
}

// AutoPass checks every per-address setup that is due (nudged: also the
// healthy ones whose last check is older than autoNudgeAge).
func (s *InboundSync) AutoPass(ctx context.Context, env core.Env, nudged bool) {
	all, err := s.records(ctx, env)
	if err != nil {
		return
	}
	now := nowOf(env)
	for _, rec := range all {
		if ctx.Err() != nil {
			return
		}
		if rec.Inbound == nil || rec.Inbound.Mode != setup.ReceiveAddresses {
			continue
		}
		s.mu.Lock()
		m := s.memo(rec.ID)
		due := !now.Before(m.next)
		if nudged && m.failures == 0 && m.state.State != "stopped" && now.Sub(time.Unix(m.state.CheckedAt, 0)) >= autoNudgeAge {
			due = true
		}
		stopped := m.state.State == "stopped"
		s.mu.Unlock()
		if !due || stopped {
			continue
		}
		run, cancel := context.WithTimeout(ctx, SyncBudget)
		s.autoRun(run, env, rec.ID)
		cancel()
	}
}

// autoRun is one automatic run of one setup.
func (s *InboundSync) autoRun(ctx context.Context, env core.Env, id string) {
	l := s.lock(id)
	if !l.TryLock() {
		return // a manual sync or a removal runs: it decides
	}
	defer l.Unlock()
	rec, err := s.record(ctx, env, id)
	if err != nil || rec.Inbound == nil || rec.Inbound.Mode != setup.ReceiveAddresses {
		return // removed meanwhile
	}
	now := nowOf(env)
	s.mu.Lock()
	m := s.memo(id)
	held, cloudAt := m.state.Held, m.cloudAt
	s.mu.Unlock()
	if cloudAt.IsZero() && rec.Synced != nil {
		// After a restart: the last sync (or the setup) asked Cloudflare.
		cloudAt = time.Unix(rec.Synced.At, 0)
	}
	result := s.autoCheck(ctx, env, rec, cloudAt, now)
	if result.state.State == "ok" && !result.asked {
		result.state.Held = held
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m = s.memo(id)
	m.state = result.state
	if result.asked {
		m.cloudAt = now
	}
	switch result.state.State {
	case "ok":
		m.failures, m.next = 0, now.Add(AutoInterval)
	case "failing":
		m.failures++
		m.next = now.Add(min(AutoInterval<<min(m.failures, 8), AutoMaxBackoff))
	case "stopped":
		m.failures++
		m.next = now.Add(AutoMaxBackoff)
	}
	if env.Log != nil && result.state.State != "ok" {
		env.Log.Info("inbound mailbox auto sync", "domain", rec.Domain, "state", result.state.State,
			"cause", result.state.CauseKey, "unsynced", result.state.Unsynced, "failures", m.failures)
	}
}

type autoResult struct {
	state AutoState
	// asked: Cloudflare was asked (the reconcile clock restarts).
	asked bool
}

// autoCheck reads MailPlus and, only when needed and safe, Cloudflare.
func (s *InboundSync) autoCheck(ctx context.Context, env core.Env, rec keptRecord, cloudAt, now time.Time) autoResult {
	fail := func(cause string, unsynced int) autoResult {
		return autoResult{state: AutoState{State: "failing", CauseKey: cause, Unsynced: unsynced}}
	}
	if s.reader == nil {
		return fail(autoCauseMailPlus, 0)
	}
	state := s.reader.ReadAccounts(ctx, env, rec.Domain)
	pkg := state.Package
	switch {
	case !pkg.IsKnown():
		return fail(readCause(pkg.Detail), 0)
	case !pkg.Value.Installed || !pkg.Value.Running || pkg.Value.Broken:
		return fail(autoCauseStopped, 0)
	}
	accounts := state.Accounts[rec.Domain]
	if !accounts.IsKnown() {
		if cause := readCause(accounts.Detail); cause == autoCauseChanged {
			return autoResult{state: AutoState{State: "stopped", CauseKey: cause}}
		} else {
			return fail(cause, 0)
		}
	}
	state.Domain = rec.Domain
	want := setup.Mailboxes(state)
	if len(want) > setup.MaxMailboxes {
		want = want[:setup.MaxMailboxes]
	}
	var kept []string
	if rec.Synced != nil {
		kept = rec.Synced.Set
	}
	if len(want) == 0 {
		// Never act on an empty list: MailPlus may be between states. A
		// manual sync would remove every rule this setup made.
		r := fail(autoCauseEmpty, 0)
		if rec.Synced != nil {
			r.state.Held = rec.Synced.Mailboxes
		}
		return r
	}
	set := mailboxSet(want)
	unsynced := -1
	if kept != nil {
		have := map[string]bool{}
		for _, h := range kept {
			have[h] = true
		}
		unsynced = 0
		for _, h := range set {
			if !have[h] {
				unsynced++
			}
		}
		if unsynced == 0 && len(kept) == len(set) && now.Sub(cloudAt) < AutoReconcile {
			return autoResult{state: AutoState{State: "ok", CheckedAt: now.Unix()}}
		}
	}
	shown := max(unsynced, 0)
	if rec.TokenRef == "" || rec.TokenInvalid || s.cloud.newClient == nil {
		return fail("mail.inbound.cause.token", shown)
	}
	token, err := env.Secrets.Get(ctx, rec.TokenRef)
	if err != nil || token == "" {
		return fail("mail.inbound.cause.token", shown)
	}
	client, err := s.cloud.newClient(cloudflare.Config{Token: token, OwnerID: rec.Inbound.Owner})
	if err != nil {
		return fail("mail.inbound.cause.token", shown)
	}
	if rec.Legacy {
		owned, err := client.OwnedRoutingRules(ctx, rec.ZoneID)
		if err != nil || len(owned) == 0 {
			if err != nil && tokenRefusal(err) {
				s.cloudRefused(ctx, env, rec, token)
			}
			return fail(syncCause(err), shown)
		}
	}
	result, err := client.SyncRoutingRulesLimited(ctx, rec.ZoneID, rec.Domain, want, syncMaxWrites, autoRemovalLimit)
	if err != nil {
		if tokenRefusal(err) {
			s.cloudRefused(ctx, env, rec, token)
		}
		r := fail(syncCause(err), shown)
		r.asked = true
		return r
	}
	if rec.TokenInvalid {
		_ = s.markToken(ctx, env, func(r keptRecord) bool { return r.ID == rec.ID }, false)
	}
	routed := routedSet(want, result)
	if len(result.Added) > 0 || len(result.Removed) > 0 || !equalSets(kept, routed) || rec.Synced == nil {
		synced := Synced{Mailboxes: len(want) - len(result.Pending), Added: len(result.Added), Removed: len(result.Removed), At: now.Unix(), Set: routed}
		if rec.Synced != nil && len(result.Added) == 0 && len(result.Removed) == 0 {
			// Nothing changed in Cloudflare: keep the last change's counts.
			synced.Added, synced.Removed = rec.Synced.Added, rec.Synced.Removed
		}
		if err := s.saveSynced(ctx, env, rec.ID, synced); err != nil && env.Log != nil {
			env.Log.Info("inbound mailbox sync count not kept", "domain", rec.Domain)
		}
	}
	if env.Log != nil && (len(result.Added) > 0 || len(result.Removed) > 0 || result.Held > 0) {
		env.Log.Info("inbound mailbox auto sync", "domain", rec.Domain, "state", "done", "added", len(result.Added),
			"removed", len(result.Removed), "held", result.Held, "pending", len(result.Pending))
	}
	return autoResult{state: AutoState{State: "ok", Held: result.Held, CheckedAt: now.Unix()}, asked: true}
}

// routedSet is the hashed set of wanted addresses that now have a rule.
func routedSet(want []string, result cloudflare.SyncResult) []string {
	pending := map[string]bool{}
	for _, p := range result.Pending {
		pending[strings.ToLower(p.Address)] = true
	}
	routed := []string{}
	for _, a := range want {
		if !pending[strings.ToLower(a)] {
			routed = append(routed, a)
		}
	}
	return mailboxSet(routed)
}

func equalSets(a, b []string) bool {
	if a == nil || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// approvalRefusals: executor refusals that wait for the administrator to
// approve the App's access again (detect.executorCauses).
var approvalRefusals = map[string]bool{"POLICY_DENIED": true, "UNKNOWN_OP": true, "DELEGATION_DENIED": true,
	"SCOPE_DENIED": true, "SCOPE_APPROVAL_STALE": true}

// readCause maps a MailPlus read that was not definite to an automatic
// sync cause: a changed reply shape stops, everything else is retried.
func readCause(detail string) string {
	switch {
	case detail == detect.CauseUnsupported, detail == detect.CauseIncomplete, detail == detect.CauseBadResponse,
		detail == detect.CauseMailPlusAPIMissing:
		return autoCauseChanged
	case detail == core.CauseAuthority, approvalRefusals[strings.TrimPrefix(detail, "executor_")] && strings.HasPrefix(detail, "executor_"):
		return autoCauseApproval
	case detail == detect.CauseMailPlusNotInstalled, detail == detect.CauseMailPlusNotRunning:
		return autoCauseStopped
	}
	return autoCauseMailPlus
}

// manualDone: a completed manual sync is the administrator's decision. It
// clears the automatic sync's failures and stop (a changed reply is tried
// again), and what it held back.
func (s *InboundSync) manualDone(env core.Env, id string, run SyncRun) {
	if run.State != "done" {
		return
	}
	now := nowOf(env)
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.memo(id)
	m.state = AutoState{State: "ok", CheckedAt: now.Unix()}
	m.failures, m.cloudAt, m.next = 0, now, now.Add(AutoInterval)
}
