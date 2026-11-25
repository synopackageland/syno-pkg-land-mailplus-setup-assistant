package mail

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

// Per-address setups sync
// by themselves, and every automatic run fails safe.

type autoFixture struct {
	t      *testing.T
	s      *InboundSync
	reader *mailboxes
	cloud  *inboundCloud
	env    core.Env
	id     string
	now    time.Time
}

func newAutoFixture(t *testing.T, addresses ...string) *autoFixture {
	t.Helper()
	cloud := newInboundCloud()
	s, reader, env, id := keptSetup(t, cloud, addresses...)
	f := &autoFixture{t: t, s: s, reader: reader, cloud: cloud, id: id, now: time.Now().Truncate(time.Second)}
	if rec, err := s.record(context.Background(), env, id); err == nil && rec.Synced != nil {
		f.now = time.Unix(rec.Synced.At, 0) // the setup's own clock
	}
	env.Now = func() time.Time { return f.now }
	f.env = env
	return f
}

// pass advances the clock and runs one automatic pass; it returns the
// Cloudflare requests and the writes among them.
func (f *autoFixture) pass(after time.Duration) (requests, writes int) {
	f.t.Helper()
	f.now = f.now.Add(after)
	before := len(f.cloud.requests)
	f.s.AutoPass(context.Background(), f.env, false)
	for _, r := range f.cloud.requests[before:] {
		requests++
		if !strings.HasPrefix(r, "GET ") {
			writes++
		}
	}
	return requests, writes
}

func (f *autoFixture) view() KeptView {
	f.t.Helper()
	list, err := f.s.Status(context.Background(), f.env)
	if err != nil || len(list.Setups) != 1 {
		f.t.Fatalf("status: %+v %v", list, err)
	}
	return list.Setups[0]
}

func TestAutoSyncAddsANewMailboxByItself(t *testing.T) {
	f := newAutoFixture(t, "alice@example.test", "bob@example.test")
	// The setup kept its mailbox set: an unchanged MailPlus needs no Cloudflare call.
	if req, _ := f.pass(time.Minute); req != 0 || f.reader.reads != 1 {
		t.Fatalf("unchanged: %d Cloudflare requests, %d reads", req, f.reader.reads)
	}
	if v := f.view(); v.Auto == nil || v.Auto.State != "ok" || v.Auto.CheckedAt != f.now.Unix() {
		t.Fatalf("auto: %+v", v.Auto)
	}
	// Not due again before AutoInterval.
	if f.pass(AutoInterval / 2); f.reader.reads != 1 {
		t.Fatal("checked before it was due")
	}
	// A new MailPlus user: the next run adds its rule, nothing else.
	f.reader.users = users("alice@example.test", "bob@example.test", "aaa@example.test")
	if _, writes := f.pass(AutoInterval / 2); writes != 1 {
		t.Fatalf("writes: %d", writes)
	}
	got := ruleAddresses(f.cloud)
	sort.Strings(got)
	if strings.Join(got, ",") != "aaa@example.test,alice@example.test,bob@example.test" {
		t.Fatalf("rules: %s", got)
	}
	v := f.view()
	if v.Synced == nil || v.Synced.Mailboxes != 3 || v.Synced.Added != 1 || v.Synced.Set != nil || v.Auto.State != "ok" {
		t.Fatalf("after: %+v %+v", v.Synced, v.Auto)
	}
	// In line again: no Cloudflare call until the reconcile is due.
	if req, _ := f.pass(AutoInterval); req != 0 {
		t.Fatalf("unchanged after a sync: %d requests", req)
	}
	if req, writes := f.pass(AutoReconcile); req == 0 || writes != 0 {
		t.Fatalf("reconcile: %d requests, %d writes", req, writes)
	}
}

func TestAutoSyncFailsSafeAndBacksOff(t *testing.T) {
	for _, c := range []struct {
		name   string
		break_ func(*mailboxes)
		cause  string
		state  string
	}{
		{"mailplus stopped", func(m *mailboxes) { m.stopped = true }, autoCauseStopped, "failing"},
		{"package unread", func(m *mailboxes) { m.unknown = true }, autoCauseMailPlus, "failing"},
		{"read timed out", func(m *mailboxes) { m.cause = core.CauseTimeout }, autoCauseMailPlus, "failing"},
		{"access to approve", func(m *mailboxes) { m.cause = core.CauseAuthority }, autoCauseApproval, "failing"},
		{"empty list", func(m *mailboxes) { m.users = nil }, autoCauseEmpty, "failing"},
		{"reply incomplete", func(m *mailboxes) { m.cause = detect.CauseIncomplete }, autoCauseChanged, "stopped"},
		{"api version gone", func(m *mailboxes) { m.cause = detect.CauseUnsupported }, autoCauseChanged, "stopped"},
		{"reply undecodable", func(m *mailboxes) { m.cause = detect.CauseBadResponse }, autoCauseChanged, "stopped"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newAutoFixture(t, "alice@example.test", "bob@example.test")
			// Even with a new user waiting, a broken read never reaches Cloudflare.
			f.reader.users = users("alice@example.test", "carol@example.test")
			c.break_(f.reader)
			if req, _ := f.pass(time.Minute); req != 0 {
				t.Fatalf("%d Cloudflare requests", req)
			}
			v := f.view()
			if v.Auto == nil || v.Auto.State != c.state || v.Auto.CauseKey != c.cause || len(f.cloud.rules) != 2 {
				t.Fatalf("auto: %+v, rules %v", v.Auto, ruleAddresses(f.cloud))
			}
			if c.cause == autoCauseEmpty && v.Auto.Held != 2 {
				t.Fatalf("an empty list holds every rule: %+v", v.Auto)
			}
			reads := f.reader.reads
			if c.state == "stopped" {
				// Stopped: no further automatic read until a manual sync.
				f.pass(AutoMaxBackoff * 2)
				if f.reader.reads != reads {
					t.Fatal("a stopped auto sync read again")
				}
				return
			}
			// Back-off: the first retry waits 2×, the next 4× the interval.
			if f.pass(AutoInterval); f.reader.reads != reads {
				t.Fatal("retried before the back-off")
			}
			if f.pass(AutoInterval); f.reader.reads != reads+1 {
				t.Fatal("no retry after the back-off")
			}
			if f.pass(3 * AutoInterval); f.reader.reads != reads+1 {
				t.Fatal("the second back-off did not grow")
			}
		})
	}
}

func TestAutoSyncStopIsClearedByAManualSync(t *testing.T) {
	f := newAutoFixture(t, "alice@example.test")
	f.reader.cause = detect.CauseIncomplete
	f.pass(time.Minute)
	if v := f.view(); v.Auto.State != "stopped" {
		t.Fatalf("auto: %+v", v.Auto)
	}
	f.reader.cause = ""
	f.reader.users = users("alice@example.test", "bob@example.test")
	if view, err := f.s.Sync(context.Background(), f.env, f.id, false); err != nil || view.Last.State != "done" {
		t.Fatalf("manual sync: %+v %v", view.Last, err)
	}
	if v := f.view(); v.Auto == nil || v.Auto.State != "ok" {
		t.Fatalf("after a manual sync: %+v", v.Auto)
	}
	f.reader.users = users("alice@example.test", "bob@example.test", "carol@example.test")
	if _, writes := f.pass(AutoInterval); writes != 1 {
		t.Fatalf("automatic sync did not resume: %d writes", writes)
	}
}

func TestAutoSyncHoldsALargeRemoval(t *testing.T) {
	all := []string{"a@example.test", "b@example.test", "c@example.test", "d@example.test", "e@example.test", "f@example.test"}
	f := newAutoFixture(t, all...)
	// Three of six go (over max(2, 6/5)): none is removed, the new one is added.
	f.reader.users = users("a@example.test", "b@example.test", "c@example.test", "g@example.test")
	if _, writes := f.pass(time.Minute); writes != 1 {
		t.Fatalf("writes: %d", writes)
	}
	if n := len(f.cloud.rules); n != 7 {
		t.Fatalf("rules: %v", ruleAddresses(f.cloud))
	}
	v := f.view()
	if v.Auto == nil || v.Auto.State != "ok" || v.Auto.Held != 3 {
		t.Fatalf("auto: %+v", v.Auto)
	}
	// The hold stays shown while nothing changes.
	if f.pass(AutoInterval); f.view().Auto.Held != 3 {
		t.Fatalf("hold forgotten: %+v", f.view().Auto)
	}
	// The administrator's 同步信箱 removes them.
	if view, err := f.s.Sync(context.Background(), f.env, f.id, false); err != nil || view.Last.Removed != 3 {
		t.Fatalf("manual sync: %+v %v", view.Last, err)
	}
	if v := f.view(); v.Auto.Held != 0 || len(f.cloud.rules) != 4 {
		t.Fatalf("after: %+v %v", v.Auto, ruleAddresses(f.cloud))
	}
}

func TestAutoSyncMakesASmallRemoval(t *testing.T) {
	f := newAutoFixture(t, "a@example.test", "b@example.test", "c@example.test")
	f.reader.users = users("a@example.test", "b@example.test")
	if _, writes := f.pass(time.Minute); writes != 1 {
		t.Fatalf("writes: %d", writes)
	}
	got := ruleAddresses(f.cloud)
	sort.Strings(got)
	if strings.Join(got, ",") != "a@example.test,b@example.test" {
		t.Fatalf("rules: %v", got)
	}
	if v := f.view(); v.Auto.Held != 0 || v.Synced.Mailboxes != 2 || v.Synced.Removed != 1 {
		t.Fatalf("after: %+v %+v", v.Auto, v.Synced)
	}
}

func TestAutoSyncWaitsForAToken(t *testing.T) {
	f := newAutoFixture(t, "alice@example.test")
	f.cloud.revoked = true
	f.reader.users = users("alice@example.test", "bob@example.test")
	f.pass(time.Minute)
	v := f.view()
	if v.Auto == nil || v.Auto.State != "failing" || v.Auto.CauseKey != "mail.inbound.cause.token" || v.Auto.Unsynced != 1 || !v.TokenInvalid {
		t.Fatalf("revoked: %+v invalid=%v", v.Auto, v.TokenInvalid)
	}
	// The token is known bad: no further Cloudflare call until it is replaced.
	if req, _ := f.pass(AutoMaxBackoff); req != 0 {
		t.Fatalf("%d requests with a refused token", req)
	}
}

func TestAutoSyncNeverRunsBesideAManualSyncOrARemoval(t *testing.T) {
	f := newAutoFixture(t, "alice@example.test")
	l := f.s.lock(f.id)
	l.Lock()
	f.pass(time.Minute)
	l.Unlock()
	if f.reader.reads != 0 {
		t.Fatal("ran while the setup was locked")
	}
	// A removed setup is never synced again.
	// (as the removal leaves it: the record cleared, the journal's inbound
	// operation rolled back)
	if err := f.env.KV.Put(context.Background(), keptModule, keptKey(f.id), keptRecord{}); err != nil {
		t.Fatal(err)
	}
	if err := f.env.KV.Put(context.Background(), "mail.wiring", "inbound.example.test", cloudOperation{}); err != nil {
		t.Fatal(err)
	}
	f.pass(AutoInterval)
	if f.reader.reads != 0 {
		t.Fatal("synced a removed setup")
	}
}

func TestAutoSyncLoopStopsWithItsContext(t *testing.T) {
	f := newAutoFixture(t, "alice@example.test")
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); f.s.AutoSync(ctx, f.env) }()
	cancel()
	wg.Wait()
}
