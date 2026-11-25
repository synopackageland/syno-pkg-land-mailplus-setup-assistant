package mail

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/cloudflare"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

// the whole-domain mode and the manual mailbox sync.

// mailboxes is a MailPlus account read for the sync (one domain).
type mailboxes struct {
	users []detect.Account
	// unknown: the read did not answer definitely.
	unknown bool
	// stopped: MailPlus Server is installed but not running; cause: the
	// account read failed with this detail (the package read succeeded).
	stopped bool
	cause   string
	reads   int
}

func (m *mailboxes) ReadAccounts(_ context.Context, _ core.Env, domain string) detect.State {
	m.reads++
	s := detect.State{Accounts: map[string]detect.Observation[[]detect.Account]{}}
	if m.unknown {
		return s
	}
	s.Package = detect.Fact(detect.Package{Installed: true, Running: !m.stopped})
	switch {
	case m.stopped:
	case m.cause != "":
		s.Accounts[domain] = detect.Observation[[]detect.Account]{Status: detect.Unknown, Detail: m.cause}
	default:
		s.Accounts[domain] = detect.Fact(append([]detect.Account{}, m.users...))
	}
	return s
}

func users(addresses ...string) []detect.Account {
	out := []detect.Account{}
	for i, a := range addresses {
		out = append(out, detect.Account{ID: i + 1, Name: strings.Split(a, "@")[0], Addresses: []string{a}, Active: true})
	}
	return out
}

// applyAll plans, snapshots and applies every change, as the setup does.
func applyAll(t *testing.T, adapter *cloudflareAdapter, env core.Env, request setup.PlanRequest) []setup.AppliedChange {
	t.Helper()
	ctx := context.Background()
	prepared, err := adapter.Plan(ctx, env, request)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	applied := []setup.AppliedChange{}
	for _, c := range prepared.Changes {
		snap, err := adapter.Snapshot(ctx, env, c)
		if err != nil {
			t.Fatalf("snapshot %s: %v", c.ID, err)
		}
		if err := adapter.Apply(ctx, env, c); err != nil {
			t.Fatalf("apply %s: %v", c.ID, err)
		}
		applied = append(applied, setup.AppliedChange{Change: c, Snapshot: snap, At: env.Now()})
	}
	return applied
}

func rollbackAll(t *testing.T, adapter *cloudflareAdapter, env core.Env, applied []setup.AppliedChange) {
	t.Helper()
	for i := len(applied) - 1; i >= 0; i-- {
		if err := adapter.Rollback(context.Background(), env, applied[i].Change, applied[i].Snapshot); err != nil {
			t.Fatalf("rollback %s: %v", applied[i].Change.ID, err)
		}
	}
}

func wholeDomain(t *testing.T, cloud *inboundCloud) (*cloudflareAdapter, core.Env, setup.PlanRequest) {
	adapter, env, request := inboundFixture(t, cloud, lanDSM())
	request.Domain = "example.test"
	request.Addresses = []string{"admin@example.test"}
	request.ReceiveMode = setup.ReceiveDomain
	return adapter, env, request
}

func TestWholeDomainPlanApplyRollback(t *testing.T) {
	cloud := newInboundCloud()
	adapter, env, request := wholeDomain(t, cloud)
	applied := applyAll(t, adapter, env, request)
	ids := []string{}
	for _, a := range applied {
		ids = append(ids, a.Change.ID)
	}
	if strings.Join(ids, ",") != "inbound.vpc,inbound.worker,inbound.catchall" {
		t.Fatalf("changes: %v", ids)
	}
	last := applied[len(applied)-1].Change
	if last.Before != "" || !strings.HasPrefix(last.After, "*@example.test → syno-home-keeper-") {
		t.Fatalf("catch-all change: %q → %q", last.Before, last.After)
	}
	// No per-address rule; the catch-all points at this setup's Worker.
	if len(cloud.rules) != 0 || cloud.catchAllPuts != 1 || !cloud.catchAll.Enabled ||
		cloud.catchAll.Actions[0].Type != "worker" || cloud.catchAll.Actions[0].Value[0] != cloud.workers[0].ID {
		t.Fatalf("catch-all: %+v rules=%d", cloud.catchAll, len(cloud.rules))
	}
	// A lost reply: applying again writes nothing.
	if err := adapter.Apply(context.Background(), env, last); err != nil || cloud.catchAllPuts != 1 {
		t.Fatalf("re-apply: %v puts=%d", err, cloud.catchAllPuts)
	}
	rollbackAll(t, adapter, env, applied)
	if c := cloud.catchAll; c.Enabled || c.Actions[0].Type != "drop" || c.Name != "" {
		t.Fatalf("catch-all not restored: %+v", c)
	}
	if len(cloud.services) != 0 || len(cloud.workers) != 0 {
		t.Fatal("owned resources remain after rollback")
	}
}

func TestWholeDomainNeverTouchesAForeignCatchAll(t *testing.T) {
	ctx := context.Background()
	forward := cloudflare.RoutingRule{ID: "catch", Name: "operator", Enabled: true, Matchers: []cloudflare.RoutingMatcher{{Type: "all"}},
		Actions: []cloudflare.RoutingAction{{Type: "forward", Value: []string{"owner@elsewhere.test"}}}}

	// In use at plan time: refused, nothing written.
	cloud := newInboundCloud()
	in := forward
	cloud.catchAll = &in
	adapter, env, request := wholeDomain(t, cloud)
	if _, err := adapter.Plan(ctx, env, request); !errors.Is(err, setup.ErrCatchAllInUse) {
		t.Fatalf("in-use catch-all: %v", err)
	}
	// A subdomain has no catch-all of its own: refused without a read.
	cloud = newInboundCloud()
	adapter, env, request = wholeDomain(t, cloud)
	request.Domain, request.Addresses = "mail.example.test", []string{"admin@mail.example.test"}
	if _, err := adapter.Plan(ctx, env, request); !errors.Is(err, setup.ErrCatchAllInUse) {
		t.Fatalf("subdomain: %v", err)
	}
	for _, r := range cloud.requests {
		if strings.Contains(r, "catch_all") {
			t.Fatalf("subdomain read the catch-all: %s", r)
		}
	}

	// Changed by somebody after the setup: the rollback leaves it as it is.
	cloud = newInboundCloud()
	adapter, env, request = wholeDomain(t, cloud)
	applied := applyAll(t, adapter, env, request)
	changed := forward
	cloud.catchAll = &changed
	puts := cloud.catchAllPuts
	rollbackAll(t, adapter, env, applied)
	if cloud.catchAllPuts != puts || cloud.catchAll.Actions[0].Type != "forward" {
		t.Fatalf("foreign catch-all touched: %+v", cloud.catchAll)
	}

	// Changed between the plan and the apply: the apply refuses (stale).
	cloud = newInboundCloud()
	adapter, env, request = wholeDomain(t, cloud)
	prepared, err := adapter.Plan(ctx, env, request)
	if err != nil {
		t.Fatal(err)
	}
	changed = forward
	cloud.catchAll = &changed
	for _, c := range prepared.Changes {
		if c.ID != "inbound.catchall" {
			continue
		}
		if _, err := adapter.Snapshot(ctx, env, c); !errors.Is(err, setup.ErrStale) {
			t.Fatalf("snapshot of a changed catch-all: %v", err)
		}
		if err := adapter.Apply(ctx, env, c); !errors.Is(err, setup.ErrStale) {
			t.Fatalf("apply on a changed catch-all: %v", err)
		}
	}
	if cloud.catchAll.Actions[0].Type != "forward" {
		t.Fatal("foreign catch-all overwritten")
	}
}

func TestReceiveModes(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		zone     string
		catchAll *cloudflare.RoutingRule
		domain   bool
		reason   string
	}{
		"apex, unused": {zone: "example.test", domain: true},
		"apex, drop":   {zone: "example.test", catchAll: &cloudflare.RoutingRule{Enabled: true, Actions: []cloudflare.RoutingAction{{Type: "drop"}}}, domain: true},
		"apex, in use": {zone: "example.test", catchAll: &cloudflare.RoutingRule{Enabled: true, Actions: []cloudflare.RoutingAction{{Type: "forward", Value: []string{"x@y.test"}}}}, reason: "mail.setup.receive.inUse"},
		"subdomain":    {zone: "example.test", reason: "mail.setup.receive.subdomain"},
	} {
		cloud := newInboundCloud()
		cloud.zoneName, cloud.catchAll = tc.zone, tc.catchAll
		adapter, env, request := inboundFixture(t, cloud, lanDSM())
		domain := "example.test"
		if name == "subdomain" {
			domain = "mail.example.test"
		}
		s := &InboundSync{cloud: adapter}
		got, err := s.ReceiveModes(ctx, env, request.TokenRef, testZone, domain)
		if err != nil || got.Domain != tc.domain || got.DomainReason != tc.reason {
			t.Errorf("%s: %+v %v", name, got, err)
		}
		for _, r := range cloud.requests {
			if !strings.HasPrefix(r, "GET ") {
				t.Errorf("%s: wrote %s", name, r)
			}
		}
	}
}

// keptSetup applies a per-address setup for example.test and records it.
func keptSetup(t *testing.T, cloud *inboundCloud, addresses ...string) (*InboundSync, *mailboxes, core.Env, string) {
	t.Helper()
	adapter, env, request := inboundFixture(t, cloud, lanDSM())
	request.Domain, request.Addresses = "example.test", addresses
	applied := applyAll(t, adapter, env, request)
	reader := &mailboxes{users: users(addresses...)}
	s := &InboundSync{cloud: adapter, reader: reader, background: &core.Background{}, wait: 5 * time.Second}
	id := strings.Repeat("d", 32)
	if err := s.Kept(context.Background(), env, setup.KeptSetup{FlowID: id, Domain: request.Domain, Intent: setup.Receive,
		AccountID: testAccount, ZoneID: testZone, TokenRef: request.TokenRef, Applied: applied}); err != nil {
		t.Fatalf("kept: %v", err)
	}
	return s, reader, env, id
}

func ruleAddresses(cloud *inboundCloud) []string {
	out := []string{}
	for _, r := range cloud.rules {
		out = append(out, r.Matchers[0].Value)
	}
	return out
}

func TestKeptSetupSyncAddsAndRemovesMailboxes(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	s, reader, env, id := keptSetup(t, cloud, "alice@example.test", "bob@example.test")
	cloud.rules = append(cloud.rules, cloudflare.RoutingRule{ID: "foreign", Name: "operator", Enabled: true,
		Matchers: []cloudflare.RoutingMatcher{{Type: "literal", Field: "to", Value: "dave@example.test"}},
		Actions:  []cloudflare.RoutingAction{{Type: "forward", Value: []string{"dave@elsewhere.test"}}}})

	// Nothing runs until the administrator asks: Status reads records only.
	before := len(cloud.requests)
	list, err := s.Status(ctx, env)
	if err != nil || len(list.Setups) != 1 || list.Setups[0].Receive != setup.ReceiveAddresses || !list.Setups[0].Token || list.Setups[0].Last != nil {
		t.Fatalf("status: %+v %v", list, err)
	}
	if len(cloud.requests) != before || reader.reads != 0 {
		t.Fatal("status called Cloudflare or MailPlus")
	}

	// bob was deleted, carol and dave added in MailPlus; dave has a foreign rule.
	reader.users = users("alice@example.test", "carol@example.test", "dave@example.test")
	view, err := s.Sync(ctx, env, id, false)
	if err != nil {
		t.Fatal(err)
	}
	if last := view.Last; last == nil || last.State != "done" || last.Added != 1 || last.Removed != 1 || last.Pending != 1 || last.Addresses[0] != "dave@example.test" {
		t.Fatalf("sync: %+v", view.Last)
	}
	got := strings.Join(ruleAddresses(cloud), ",")
	if got != "alice@example.test,dave@example.test,carol@example.test" {
		t.Fatalf("rules: %s", got)
	}
	if cloud.rules[1].ID != "foreign" || cloud.rules[1].Actions[0].Type != "forward" {
		t.Fatal("foreign rule touched")
	}
	// Idempotent: a second run changes nothing.
	writes := 0
	before = len(cloud.requests)
	if view, err = s.Sync(ctx, env, id, false); err != nil || view.Last.Added != 0 || view.Last.Removed != 0 {
		t.Fatalf("second sync: %+v %v", view.Last, err)
	}
	for _, r := range cloud.requests[before:] {
		if !strings.HasPrefix(r, "GET ") {
			writes++
		}
	}
	if writes != 0 {
		t.Fatalf("idempotent sync wrote %d times", writes)
	}
}

// Follow-up 3: the Overview says how many mailboxes a per-address
// setup syncs, from the record alone (no Cloudflare or MailPlus call), and
// the count outlives the worker's memory of the last run.
func TestKeptSetupKeepsItsSyncedCount(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	s, reader, env, id := keptSetup(t, cloud, "alice@example.test", "bob@example.test")
	status := func(s *InboundSync) KeptView {
		t.Helper()
		before := len(cloud.requests)
		list, err := s.Status(ctx, env)
		if err != nil || len(list.Setups) != 1 {
			t.Fatalf("status: %+v %v", list, err)
		}
		if len(cloud.requests) != before {
			t.Fatal("status called Cloudflare")
		}
		return list.Setups[0]
	}
	// The setup itself is the first sync: two mailboxes, nothing added or removed yet.
	if v := status(s); v.Synced == nil || v.Synced.Mailboxes != 2 || v.Synced.Added != 0 || v.Synced.Removed != 0 || v.Synced.At == 0 {
		t.Fatalf("after setup: %+v", v.Synced)
	}
	cloud.rules = append(cloud.rules, cloudflare.RoutingRule{ID: "foreign", Name: "operator", Enabled: true,
		Matchers: []cloudflare.RoutingMatcher{{Type: "literal", Field: "to", Value: "dave@example.test"}},
		Actions:  []cloudflare.RoutingAction{{Type: "forward", Value: []string{"dave@elsewhere.test"}}}})
	reader.users = users("alice@example.test", "carol@example.test", "dave@example.test", "erin@example.test")
	view, err := s.Sync(ctx, env, id, false)
	if err != nil {
		t.Fatal(err)
	}
	if view.Synced == nil || view.Synced.Mailboxes != 3 {
		t.Fatalf("the sync's reply: %+v", view.Synced)
	}
	// alice, carol and erin receive; dave stays pending (a foreign rule), bob is gone.
	want := Synced{Mailboxes: 3, Added: 2, Removed: 1}
	got := status(s).Synced
	if got == nil || got.Mailboxes != want.Mailboxes || got.Added != want.Added || got.Removed != want.Removed {
		t.Fatalf("after sync: %+v", got)
	}
	// A restarted worker has no Last, but the record still has the count.
	fresh := &InboundSync{cloud: s.cloud, reader: reader, background: &core.Background{}, wait: 5 * time.Second}
	if view := status(fresh); view.Last != nil || view.Synced == nil || !reflect.DeepEqual(*view.Synced, *got) {
		t.Fatalf("after restart: %+v %+v", view.Last, view.Synced)
	}
	// A failed sync keeps the last completed count.
	reader.unknown = true
	if _, err := s.Sync(ctx, env, id, false); err != nil {
		t.Fatal(err)
	}
	if v := status(s); v.Last.State != "failed" || v.Synced == nil || !reflect.DeepEqual(*v.Synced, *got) {
		t.Fatalf("after a failed sync: %+v %+v", v.Last, v.Synced)
	}
}

func TestKeptSetupNeverRevealsItsToken(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	s, _, env, id := keptSetup(t, cloud, "alice@example.test")
	list, err := s.Status(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), "fixture-value") || strings.Contains(string(raw), "secret:") {
		t.Fatalf("status reveals the token: %s", raw)
	}
	var rec keptRecord
	if found, err := env.KV.Get(ctx, keptModule, keptKey(id), &rec); err != nil || !found {
		t.Fatalf("record: %v", err)
	}
	raw, _ = json.Marshal(rec)
	if strings.Contains(string(raw), "fixture-value") {
		t.Fatal("record holds the token itself")
	}
	// Forgetting deletes the sealed token; the sync then asks for one.
	view, err := s.SetToken(ctx, env, id, "")
	if err != nil || view.Token {
		t.Fatalf("forget: %+v %v", view, err)
	}
	if v, err := env.Secrets.Get(ctx, rec.TokenRef); err == nil && v != "" {
		t.Fatal("token still sealed after forget")
	}
	if _, err := s.Sync(ctx, env, id, false); !errors.Is(err, setup.ErrSyncTokenRequired) {
		t.Fatalf("sync without a token: %v", err)
	}
	// A replacement is checked first and sealed under the record's own name.
	view, err = s.SetToken(ctx, env, id, "fixture-value")
	if err != nil || !view.Token {
		t.Fatalf("replace: %+v %v", view, err)
	}
	raw, _ = json.Marshal(view)
	if strings.Contains(string(raw), "fixture-value") {
		t.Fatal("reply reveals the token")
	}
	if _, err := s.SetToken(ctx, env, id, "has space"); !errors.Is(err, setup.ErrInvalid) {
		t.Fatalf("malformed token: %v", err)
	}
}

func TestKeptSetupSyncFailuresChangeNothing(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	s, reader, env, id := keptSetup(t, cloud, "alice@example.test", "bob@example.test")

	// MailPlus did not answer definitely: no rule is removed.
	reader.unknown = true
	before := len(cloud.requests)
	view, err := s.Sync(ctx, env, id, false)
	if err != nil || view.Last.State != "failed" || view.Last.CauseKey != "mail.inbound.cause.mailplus" {
		t.Fatalf("unknown read: %+v %v", view.Last, err)
	}
	if len(cloud.requests) != before || len(cloud.rules) != 2 {
		t.Fatal("an uncertain MailPlus read reached Cloudflare")
	}

	// A refused write (missing permission or revoked token): ask for a token.
	reader.unknown = false
	reader.users = users("alice@example.test", "bob@example.test", "carol@example.test")
	cloud.fail = map[string][2]int{"POST /zones/" + testZone + "/email/routing/rules": {403, 10000}}
	view, err = s.Sync(ctx, env, id, false)
	if err != nil || view.Last.State != "failed" || view.Last.CauseKey != "mail.inbound.cause.token" {
		t.Fatalf("refused write: %+v %v", view.Last, err)
	}

	// The whole-domain mode has nothing to sync.
	if _, err := s.Sync(ctx, env, strings.Repeat("e", 32), false); !errors.Is(err, setup.ErrNoFlow) {
		t.Fatalf("unknown setup: %v", err)
	}
}

func TestKeptOnlyRecordsCloudflareSetups(t *testing.T) {
	_, env, _ := cfFixture(t, &fakeCloud{})
	s := &InboundSync{}
	err := s.Kept(context.Background(), env, setup.KeptSetup{FlowID: strings.Repeat("f", 32), Domain: "example.test",
		Applied: []setup.AppliedChange{{Change: core.Change{ID: "mailplus.relay", Target: "mailplus.relay"}}}})
	if !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("a MailPlus-only setup must not be recorded: %v", err)
	}
}

func TestLegacySetupIsAdoptedOnlyWhileItsRulesExist(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	adapter, env, request := inboundFixture(t, cloud, lanDSM())
	request.Domain, request.Addresses = "example.test", []string{"alice@example.test"}
	applied := applyAll(t, adapter, env, request) // a build ≤40 setup: no kept record
	reader := &mailboxes{users: users("alice@example.test", "bob@example.test")}
	s := &InboundSync{cloud: adapter, reader: reader, background: &core.Background{}, wait: 5 * time.Second}
	list, err := s.Status(ctx, env)
	if err != nil || len(list.Setups) != 1 || list.Setups[0].Token || list.Setups[0].ID != legacyID("example.test") {
		t.Fatalf("legacy status: %+v %v", list, err)
	}
	id := list.Setups[0].ID
	if _, err := s.Sync(ctx, env, id, false); !errors.Is(err, setup.ErrSyncTokenRequired) {
		t.Fatalf("legacy without a token: %v", err)
	}
	if _, err := s.SetToken(ctx, env, id, "fixture-value"); err != nil {
		t.Fatal(err)
	}
	view, err := s.Sync(ctx, env, id, false)
	if err != nil || view.Last.State != "done" || view.Last.Added != 1 {
		t.Fatalf("legacy sync: %+v %v", view.Last, err)
	}
	// Rolled back outside this build: the zone has none of its rules left.
	cloud.rules = nil
	view, err = s.Sync(ctx, env, id, false)
	if err != nil || view.Last.CauseKey != "mail.inbound.cause.gone" || len(cloud.rules) != 0 {
		t.Fatalf("gone legacy setup: %+v %v rules=%d", view.Last, err, len(cloud.rules))
	}
	_ = applied
}

func TestRolledBackSetupLeavesNoRecord(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	adapter, env, request := inboundFixture(t, cloud, lanDSM())
	request.Domain, request.Addresses = "example.test", []string{"alice@example.test"}
	applied := applyAll(t, adapter, env, request)
	rollbackAll(t, adapter, env, applied)
	s := &InboundSync{cloud: adapter}
	list, err := s.Status(ctx, env)
	if err != nil || len(list.Setups) != 0 {
		t.Fatalf("a rolled-back setup is listed: %+v %v", list, err)
	}
}
