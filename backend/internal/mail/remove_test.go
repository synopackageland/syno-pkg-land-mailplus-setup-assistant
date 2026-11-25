package mail

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/cloudflare"
	"SynoMailPlusSetupAssistant/internal/mail/relay"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

// "Remove Cloudflare setup" undoes exactly what a kept setup applied.

// mailplusSide stands in for MailPlus Server: the setup changed its default
// route; the setup's rollback restores the recorded pre-setup state.
type mailplusSide struct {
	route    string
	restores int
	fail     error
	// domainInUse: the setup's MailPlus mail domain has users.
	domainInUse bool
	domains     int
	// left is the time the removal step gave the last MailPlus rollback.
	left time.Duration
}

type removal struct {
	s     *InboundSync
	env   core.Env
	id    string
	cloud *inboundCloud
	mp    *mailplusSide
}

// removable keeps a setup like the wizard does: the relay turned on, the
// MailPlus route changed, then the Cloudflare receiving steps, in that order.
func removable(t *testing.T, cloud *inboundCloud, mode string, addresses ...string) removal {
	t.Helper()
	return removableAt(t, cloud, "example.test", mode, addresses...)
}

func removableAt(t *testing.T, cloud *inboundCloud, domain, mode string, addresses ...string) removal {
	t.Helper()
	ctx := context.Background()
	adapter, env, request := inboundFixture(t, cloud, lanDSM())
	request.Domain, request.Addresses, request.ReceiveMode = domain, addresses, mode
	mp := &mailplusSide{route: "cloudflare relay"}
	// The relay this setup turned on, with its copy of the token.
	if err := env.Secrets.Put(ctx, relay.TokenSecretKey, "fixture-value"); err != nil {
		t.Fatal(err)
	}
	if err := env.KV.Put(ctx, "core.services", relay.ID, true); err != nil {
		t.Fatal(err)
	}
	applied := []setup.AppliedChange{
		{Change: core.Change{ID: "relay.configure", Target: "homekeeper.relay", Params: map[string]string{"domain": "example.test"}}, Snapshot: json.RawMessage(`{"enabled":false}`)},
		{Change: core.Change{ID: "mailplus.delivery", Target: "mailplus.delivery", Params: map[string]string{"domain": "example.test"}}, Snapshot: json.RawMessage(`{"route":"direct"}`)},
	}
	applied = append(applied, applyAll(t, adapter, env, request)...)
	undo := func(ctx context.Context, env core.Env, c core.Change, snapshot json.RawMessage) error {
		switch {
		case strings.HasPrefix(c.Target, "cloudflare."):
			return adapter.Rollback(ctx, env, c, snapshot)
		case strings.HasPrefix(c.Target, "mailplus."):
			if d, ok := ctx.Deadline(); ok {
				mp.left = time.Until(d)
			}
			if mp.fail != nil {
				return mp.fail
			}
			if c.Target == "mailplus.domain" {
				if mp.domainInUse {
					return setup.ErrDomainInUse
				}
				mp.domains--
				return nil
			}
			var saved map[string]string
			_ = json.Unmarshal(snapshot, &saved)
			mp.route = saved["route"]
			mp.restores++
			return nil
		}
		return errors.New("unexpected target " + c.Target)
	}
	s := &InboundSync{cloud: adapter, reader: &mailboxes{users: users(addresses...)}, background: &core.Background{}, wait: 5 * time.Second,
		undo: undo, relayOff: (&relayAdapter{}).relayOff}
	id := strings.Repeat("d", 32)
	if err := s.Kept(ctx, env, setup.KeptSetup{FlowID: id, Domain: request.Domain, Intent: setup.Both,
		AccountID: testAccount, ZoneID: testZone, TokenRef: request.TokenRef, Applied: applied}); err != nil {
		t.Fatalf("kept: %v", err)
	}
	return removal{s: s, env: env, id: id, cloud: cloud, mp: mp}
}

func (r removal) record(t *testing.T) keptRecord {
	t.Helper()
	var rec keptRecord
	if _, err := r.env.KV.Get(context.Background(), keptModule, keptKey(r.id), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// foreign puts resources this App did not create into the fixture.
func foreign(cloud *inboundCloud) {
	cloud.rules = append(cloud.rules, cloudflare.RoutingRule{ID: "foreign", Name: "operator", Enabled: true,
		Matchers: []cloudflare.RoutingMatcher{{Type: "literal", Field: "to", Value: "dave@example.test"}},
		Actions:  []cloudflare.RoutingAction{{Type: "forward", Value: []string{"dave@elsewhere.test"}}}})
	// Same name pattern, but not this setup's owner marker.
	cloud.services = append(cloud.services, cloudflare.VPCService{ServiceID: "foreign-service", Name: "syno-home-keeper-someone-else-smtp"})
}

func TestRemoveUndoesExactlyWhatTheSetupCreated(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test", "bob@example.test")
	foreign(r.cloud)

	list, _ := r.s.Status(ctx, r.env)
	if got := strings.Join(list.Setups[0].Removes, ","); got != "ui.remove.item.receiveAddresses,ui.remove.item.mailplus,ui.remove.item.relay,ui.remove.item.token" {
		t.Fatalf("removes: %s", got)
	}
	if list.Setups[0].RoutingOwned {
		t.Fatal("routing was already on: not this setup's")
	}
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if run := view.Removal; run == nil || run.State != "done" || run.Done != run.Total {
		t.Fatalf("removal: %+v", view.Removal)
	}
	// Cloudflare: only the foreign rule and service remain; no Worker.
	if len(r.cloud.rules) != 1 || r.cloud.rules[0].ID != "foreign" || len(r.cloud.services) != 1 || r.cloud.services[0].ServiceID != "foreign-service" || len(r.cloud.workers) != 0 {
		t.Fatalf("left: rules=%+v services=%+v workers=%+v", r.cloud.rules, r.cloud.services, r.cloud.workers)
	}
	// Email Routing stays on (not this setup's to turn off).
	if r.cloud.disables != 0 || !r.cloud.routing.Enabled {
		t.Fatal("Email Routing turned off")
	}
	// MailPlus back to its recorded pre-setup state; the relay off.
	if r.mp.route != "direct" {
		t.Fatalf("MailPlus not restored: %s", r.mp.route)
	}
	var on bool
	if _, err := r.env.KV.Get(ctx, "core.services", relay.ID, &on); err != nil || on {
		t.Fatal("relay still on")
	}
	if v, _ := r.env.Secrets.Get(ctx, relay.TokenSecretKey); v != "" {
		t.Fatal("relay still holds the token")
	}
	// The token forgotten, the setup gone from the Overview.
	if v, _ := r.env.Secrets.Get(ctx, "secret:fixture.cloudflare"); v != "" {
		t.Fatal("token still sealed")
	}
	if list, err := r.s.Status(ctx, r.env); err != nil || len(list.Setups) != 0 {
		t.Fatalf("still listed: %+v %v", list, err)
	}
	// The finished run can still be asked for; a new one has nothing to remove.
	if view, err := r.s.Remove(ctx, r.env, r.id, false, true); err != nil || view.Removal.State != "done" {
		t.Fatalf("poll after done: %+v %v", view, err)
	}
}

func TestRemoveStopsAndResumesWhereItStopped(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	// The Worker cannot be deleted right now: the rules are already gone.
	r.cloud.fail = map[string][2]int{"DELETE /accounts/" + testAccount + "/workers/scripts/" + r.cloud.workers[0].ID: {503, 1}}
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal.State != "failed" || view.Removal.CauseKey != "mail.inbound.cause.cloudflare" {
		t.Fatalf("first run: %+v %v", view.Removal, err)
	}
	if len(r.cloud.rules) != 0 || len(r.cloud.workers) != 1 {
		t.Fatal("the run did not stop at the Worker")
	}
	// The record kept what is left; the token stays for the retry.
	left := r.record(t).Applied
	if len(left) != 4 || left[len(left)-1].Change.ID != "inbound.worker" {
		t.Fatalf("left in the record: %d", len(left))
	}
	if v, _ := r.env.Secrets.Get(ctx, "secret:fixture.cloudflare"); v == "" {
		t.Fatal("token dropped before the end")
	}
	r.cloud.fail = nil
	before := len(r.cloud.requests)
	view, err = r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal.State != "done" {
		t.Fatalf("retry: %+v %v", view.Removal, err)
	}
	for _, req := range r.cloud.requests[before:] {
		if strings.Contains(req, "/email/routing/rules") {
			t.Fatalf("retry touched the rules again: %s", req)
		}
	}
	if r.mp.restores != 1 {
		t.Fatalf("MailPlus restored %d times", r.mp.restores)
	}
}

func TestRemoveCountsAlreadyGoneResourcesAsDone(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	// Removed by hand on Cloudflare, and the relay already off.
	r.cloud.rules, r.cloud.workers, r.cloud.services = nil, nil, nil
	_ = r.env.KV.Put(ctx, "core.services", relay.ID, false)
	_ = r.env.Secrets.Delete(ctx, relay.TokenSecretKey)
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal.State != "done" {
		t.Fatalf("removal: %+v %v", view.Removal, err)
	}
}

func TestRemoveRestoresTheWholeDomainSettingOnlyWhileOurs(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveDomain, "alice@example.test")
	if got := r.s.view(r.record(t)).Removes[0]; got != "ui.remove.item.receiveDomain" {
		t.Fatalf("removes: %s", got)
	}
	if view, err := r.s.Remove(ctx, r.env, r.id, false, false); err != nil || view.Removal.State != "done" {
		t.Fatalf("removal: %+v %v", view.Removal, err)
	}
	if c := r.cloud.catchAll; c.Enabled || c.Actions[0].Type != "drop" {
		t.Fatalf("not restored: %+v", c)
	}

	// Changed by somebody after the setup: left as it is.
	r = removable(t, newInboundCloud(), setup.ReceiveDomain, "alice@example.test")
	r.cloud.catchAll = &cloudflare.RoutingRule{ID: "catch", Name: "operator", Enabled: true, Matchers: []cloudflare.RoutingMatcher{{Type: "all"}},
		Actions: []cloudflare.RoutingAction{{Type: "forward", Value: []string{"owner@elsewhere.test"}}}}
	puts := r.cloud.catchAllPuts
	if view, err := r.s.Remove(ctx, r.env, r.id, false, false); err != nil || view.Removal.State != "done" {
		t.Fatalf("removal: %+v %v", view.Removal, err)
	}
	if r.cloud.catchAllPuts != puts || r.cloud.catchAll.Actions[0].Type != "forward" {
		t.Fatal("a foreign catch-all was touched")
	}
}

func TestRemoveAsksForATokenWhenPermissionIsMissing(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	rule := r.cloud.rules[0].ID
	r.cloud.fail = map[string][2]int{"DELETE /zones/" + testZone + "/email/routing/rules/" + rule: {403, 10000}}
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal.State != "failed" || view.Removal.CauseKey != "mail.inbound.cause.token" {
		t.Fatalf("refused: %+v %v", view.Removal, err)
	}
	if len(r.cloud.rules) != 1 || r.mp.restores != 0 {
		t.Fatal("a refused removal went on")
	}
	// Without a token it is refused before it starts.
	if _, err := r.s.SetToken(ctx, r.env, r.id, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.s.Remove(ctx, r.env, r.id, false, false); !errors.Is(err, setup.ErrSyncTokenRequired) {
		t.Fatalf("no token: %v", err)
	}
	// A new token is sealed under a new name; the removal uses it.
	r.cloud.fail = nil
	if _, err := r.s.SetToken(ctx, r.env, r.id, "fixture-value"); err != nil {
		t.Fatal(err)
	}
	if v, _ := r.env.Secrets.Get(ctx, "secret:fixture.cloudflare"); v != "" {
		t.Fatal("the old token name still holds a token")
	}
	view, err = r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal.State != "done" {
		t.Fatalf("with the new token: %+v %v", view.Removal, err)
	}
	if v, _ := r.env.Secrets.Get(ctx, keptTokenRef(r.id)); v != "" {
		t.Fatal("new token not forgotten")
	}
}

func TestRemoveTurnsRoutingOffOnlyWhenThisSetupEnabledIt(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	cloud.routing.Enabled = false // this setup enables Email Routing on the zone
	r := removable(t, cloud, setup.ReceiveAddresses, "alice@example.test")
	list, _ := r.s.Status(ctx, r.env)
	if !list.Setups[0].RoutingOwned {
		t.Fatal("the setup enabled routing: the option must be offered")
	}
	// Not ticked: routing stays on.
	if view, err := r.s.Remove(ctx, r.env, r.id, false, false); err != nil || view.Removal.State != "done" || cloud.disables != 0 || !cloud.routing.Enabled {
		t.Fatalf("unticked: %+v %v disables=%d", view.Removal, err, cloud.disables)
	}

	cloud = newInboundCloud()
	cloud.routing.Enabled = false
	r = removable(t, cloud, setup.ReceiveAddresses, "alice@example.test")
	if view, err := r.s.Remove(ctx, r.env, r.id, true, false); err != nil || view.Removal.State != "done" || cloud.disables != 1 || cloud.routing.Enabled {
		t.Fatalf("ticked: %+v %v disables=%d", view.Removal, err, cloud.disables)
	}

	// Routing that was on before the setup: the option is refused.
	r = removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	if _, err := r.s.Remove(ctx, r.env, r.id, true, false); !errors.Is(err, setup.ErrInvalid) {
		t.Fatalf("routing not ours: %v", err)
	}
}

func TestRemoveStopsWhenMailPlusCannotBeRestored(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	r.mp.fail = setup.ErrUnavailable
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal.State != "failed" || view.Removal.CauseKey != "mail.remove.cause.nas" {
		t.Fatalf("removal: %+v %v", view.Removal, err)
	}
	// Cloudflare was undone; the relay still runs for the route MailPlus still uses.
	var on bool
	_, _ = r.env.KV.Get(ctx, "core.services", relay.ID, &on)
	if len(r.cloud.workers) != 0 || !on {
		t.Fatalf("workers=%d relay=%v", len(r.cloud.workers), on)
	}
	r.mp.fail = nil
	if view, err := r.s.Remove(ctx, r.env, r.id, false, false); err != nil || view.Removal.State != "done" || r.mp.route != "direct" {
		t.Fatalf("retry: %+v %v", view.Removal, err)
	}
}

// the executor refuses, unsent, a delegated call whose deadline is
// nearer than core.DSMReadTimeout; a 2-minute step made every MailPlus
// restore fail on a real NAS. A step must hold the delivery rollback's four
// delegated calls (two reads, two writes).
func TestRemoveGivesMailPlusRollbackRoomForItsDSMCalls(t *testing.T) {
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	view, err := r.s.Remove(context.Background(), r.env, r.id, false, false)
	if err != nil || view.Removal.State != "done" {
		t.Fatalf("removal: %+v %v", view.Removal, err)
	}
	if r.mp.left < core.DSMCalls(4) {
		t.Fatalf("MailPlus rollback got %v, needs at least %v", r.mp.left, core.DSMCalls(4))
	}
}

func TestRemoveLegacySetupTouchesOnlyItsMarkedResources(t *testing.T) {
	ctx := context.Background()
	cloud := newInboundCloud()
	adapter, env, request := inboundFixture(t, cloud, lanDSM())
	request.Domain, request.Addresses = "example.test", []string{"alice@example.test"}
	applyAll(t, adapter, env, request) // a build ≤40 setup: no kept record
	foreign(cloud)
	s := &InboundSync{cloud: adapter, background: &core.Background{}, wait: 5 * time.Second,
		undo: func(context.Context, core.Env, core.Change, json.RawMessage) error { return errors.New("no journal") }}
	id := legacyID("example.test")
	if _, err := s.SetToken(ctx, env, id, "fixture-value"); err != nil {
		t.Fatal(err)
	}
	view, err := s.Remove(ctx, env, id, false, false)
	if err != nil || view.Removal.State != "done" {
		t.Fatalf("legacy removal: %+v %v", view.Removal, err)
	}
	if len(cloud.rules) != 1 || cloud.rules[0].ID != "foreign" || len(cloud.workers) != 0 || len(cloud.services) != 1 {
		t.Fatalf("left: rules=%d workers=%d services=%d", len(cloud.rules), len(cloud.workers), len(cloud.services))
	}
	if list, _ := s.Status(ctx, env); len(list.Setups) != 0 {
		t.Fatal("legacy setup still listed")
	}
}

// the MailPlus mail domain the setup created is removed with it, but
// kept (and said) once MailPlus users use it; the removal still finishes.
func TestRemoveDeletesTheCreatedDomainOrKeepsItInUse(t *testing.T) {
	for _, inUse := range []bool{false, true} {
		ctx := context.Background()
		r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
		rec := r.record(t)
		rec.Applied = append([]setup.AppliedChange{{Change: core.Change{ID: "mailplus.domain", Target: "mailplus.domain",
			Params: map[string]string{"domain": "example.test"}}, Snapshot: json.RawMessage(`{}`)}}, rec.Applied...)
		if err := r.env.KV.Put(ctx, keptModule, keptKey(r.id), rec); err != nil {
			t.Fatal(err)
		}
		r.mp.domains, r.mp.domainInUse = 1, inUse
		list, _ := r.s.Status(ctx, r.env)
		if got := strings.Join(list.Setups[0].Removes, ","); !strings.Contains(got, "ui.remove.item.mailplusDomain") {
			t.Fatalf("removes: %s", got)
		}
		view, err := r.s.Remove(ctx, r.env, r.id, false, false)
		if err != nil || view.Removal == nil || view.Removal.State != "done" {
			t.Fatalf("in use %v: %+v %v", inUse, view.Removal, err)
		}
		if inUse && (view.Removal.KeptDomain != "example.test" || r.mp.domains != 1) {
			t.Fatalf("in use: %+v domains=%d", view.Removal, r.mp.domains)
		}
		if !inUse && (view.Removal.KeptDomain != "" || r.mp.domains != 0) {
			t.Fatalf("unused: %+v domains=%d", view.Removal, r.mp.domains)
		}
	}
}
