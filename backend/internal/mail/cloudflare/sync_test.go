package cloudflare

import (
	"context"
	"reflect"
	"testing"
)

// the whole-domain mode (catch-all) and the per-address mailbox sync.

const ruleList = "/zones/zone/email/routing/rules"
const catchAllPath = "/zones/zone/email/routing/rules/catch_all"

func ownRule(id, address string) RoutingRule {
	return RoutingRule{ID: id, Name: "syno-home-keeper:fixture", Enabled: true,
		Matchers: []RoutingMatcher{{Type: "literal", Field: "to", Value: address}},
		Actions:  []RoutingAction{{Type: "worker", Value: []string{"syno-home-keeper-fixture-inbound"}}}}
}

func foreignRule(id, address string) RoutingRule {
	return RoutingRule{ID: id, Name: "operator forward", Enabled: true,
		Matchers: []RoutingMatcher{{Type: "literal", Field: "to", Value: address}},
		Actions:  []RoutingAction{{Type: "forward", Value: []string{"someone@elsewhere.test"}}}}
}

func ourCatchAll() RoutingRule {
	return RoutingRule{ID: "catch", Name: "syno-home-keeper:fixture", Enabled: true,
		Matchers: []RoutingMatcher{{Type: "all"}},
		Actions:  []RoutingAction{{Type: "worker", Value: []string{"syno-home-keeper-fixture-inbound"}}}}
}

func TestCatchAllUnusedAndOurs(t *testing.T) {
	c := fixture(t)
	for name, tc := range map[string]struct {
		rule         RoutingRule
		unused, ours bool
	}{
		"disabled":      {RoutingRule{Enabled: false, Actions: []RoutingAction{{Type: "forward", Value: []string{"x@y.test"}}}}, true, false},
		"drop":          {RoutingRule{Enabled: true, Actions: []RoutingAction{{Type: "drop"}}}, true, false},
		"forward":       {RoutingRule{Enabled: true, Actions: []RoutingAction{{Type: "forward", Value: []string{"x@y.test"}}}}, false, false},
		"other worker":  {RoutingRule{Name: "syno-home-keeper:fixture", Enabled: true, Matchers: []RoutingMatcher{{Type: "all"}}, Actions: []RoutingAction{{Type: "worker", Value: []string{"someone-else"}}}}, false, false},
		"ours":          {ourCatchAll(), false, true},
		"ours disabled": {func() RoutingRule { r := ourCatchAll(); r.Enabled = false; return r }(), true, false},
	} {
		if got := CatchAllUnused(tc.rule); got != tc.unused {
			t.Errorf("%s: unused %v want %v", name, got, tc.unused)
		}
		if got := c.CatchAllOurs(tc.rule); got != tc.ours {
			t.Errorf("%s: ours %v want %v", name, got, tc.ours)
		}
	}
}

func TestSetCatchAllWritesOnlyTheUnusedSnapshot(t *testing.T) {
	ctx := context.Background()
	before := RoutingRule{ID: "catch", Name: "", Enabled: false, Matchers: []RoutingMatcher{{Type: "all"}}, Actions: []RoutingAction{{Type: "drop"}}}
	set := exchange{method: "PUT", path: catchAllPath, result: ourCatchAll(), check: bodyIs(map[string]any{
		"name": "syno-home-keeper:fixture", "enabled": true, "matchers": []map[string]string{{"type": "all"}},
		"actions": []map[string]any{{"type": "worker", "value": []string{"syno-home-keeper-fixture-inbound"}}}})}
	c := fixture(t, get(catchAllPath, before), set,
		// A lost reply: already ours, no second write.
		get(catchAllPath, ourCatchAll()))
	if err := c.SetCatchAll(ctx, "zone", before); err != nil {
		t.Fatal(err)
	}
	if err := c.SetCatchAll(ctx, "zone", before); err != nil {
		t.Fatalf("already ours: %v", err)
	}
}

func TestSetCatchAllNeverTouchesAForeignCatchAll(t *testing.T) {
	ctx := context.Background()
	before := RoutingRule{Enabled: false, Matchers: []RoutingMatcher{{Type: "all"}}, Actions: []RoutingAction{{Type: "drop"}}}
	forward := RoutingRule{Name: "operator", Enabled: true, Matchers: []RoutingMatcher{{Type: "all"}}, Actions: []RoutingAction{{Type: "forward", Value: []string{"x@y.test"}}}}
	// Changed since the plan (now a forward), or in use from the start: no PUT.
	c := fixture(t, get(catchAllPath, forward), get(catchAllPath, forward))
	if err := c.SetCatchAll(ctx, "zone", before); !IsKind(err, ErrOwnership) {
		t.Fatalf("changed catch-all: %v", err)
	}
	if err := c.SetCatchAll(ctx, "zone", forward); !IsKind(err, ErrOwnership) {
		t.Fatalf("in-use catch-all: %v", err)
	}
}

func TestRestoreCatchAll(t *testing.T) {
	ctx := context.Background()
	before := RoutingRule{Name: "", Enabled: true, Matchers: []RoutingMatcher{{Type: "all"}}, Actions: []RoutingAction{{Type: "drop"}}}
	restore := exchange{method: "PUT", path: catchAllPath, result: before, check: bodyIs(map[string]any{
		"name": "", "enabled": true, "matchers": []map[string]string{{"type": "all"}}, "actions": []map[string]string{{"type": "drop"}}})}
	foreign := RoutingRule{Name: "operator", Enabled: true, Matchers: []RoutingMatcher{{Type: "all"}}, Actions: []RoutingAction{{Type: "forward", Value: []string{"x@y.test"}}}}
	c := fixture(t,
		get(catchAllPath, ourCatchAll()), restore, // ours: the snapshot goes back
		get(catchAllPath, before),  // already restored: nothing to write
		get(catchAllPath, foreign)) // changed by somebody: left as it is
	if ok, err := c.RestoreCatchAll(ctx, "zone", before); !ok || err != nil {
		t.Fatalf("restore: %v %v", ok, err)
	}
	if ok, err := c.RestoreCatchAll(ctx, "zone", before); !ok || err != nil {
		t.Fatalf("already restored: %v %v", ok, err)
	}
	if ok, err := c.RestoreCatchAll(ctx, "zone", before); ok || err != nil {
		t.Fatalf("foreign catch-all must be left: %v %v", ok, err)
	}
}

func TestSyncRoutingRulesAddsRemovesAndIgnoresForeignRules(t *testing.T) {
	ctx := context.Background()
	rules := []RoutingRule{
		ownRule("keep", "alice@example.test"),
		ownRule("gone", "bob@example.test"),         // user deleted: removed
		foreignRule("theirs", "carol@example.test"), // foreign: never touched, carol stays pending
		foreignRule("other", "dave@example.test"),   // foreign, not wanted: untouched
		ownRule("elsewhere", "x@other.test"),        // ours but another domain: untouched
	}
	create := post(ruleList, ownRule("new", "erin@example.test"))
	create.check = bodyIs(map[string]any{"name": "syno-home-keeper:fixture", "enabled": true, "priority": 0,
		"matchers": []map[string]string{{"type": "literal", "field": "to", "value": "erin@example.test"}},
		"actions":  []map[string]any{{"type": "worker", "value": []string{"syno-home-keeper-fixture-inbound"}}}})
	c := fixture(t, get(ruleList, rules),
		get(ruleList+"/gone", rules[1]), del(ruleList+"/gone"),
		create)
	got, err := c.SyncRoutingRules(ctx, "zone", "example.test",
		[]string{"alice@example.test", "carol@example.test", "erin@example.test"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	want := SyncResult{Added: []string{"erin@example.test"}, Removed: []string{"bob@example.test"},
		Pending: []SyncPending{{Address: "carol@example.test", Cause: SyncConflict}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sync: %+v", got)
	}
}

func TestSyncRoutingRulesIsIdempotent(t *testing.T) {
	// In line already: one read, no write.
	c := fixture(t, get(ruleList, []RoutingRule{ownRule("a", "alice@example.test")}))
	got, err := c.SyncRoutingRules(context.Background(), "zone", "example.test", []string{"alice@example.test"}, 100)
	if err != nil || len(got.Added)+len(got.Removed)+len(got.Pending) != 0 {
		t.Fatalf("no-op sync: %+v %v", got, err)
	}
}

func TestSyncRoutingRulesCapsWrites(t *testing.T) {
	c := fixture(t, get(ruleList, []RoutingRule{}),
		post(ruleList, ownRule("1", "a@example.test")), post(ruleList, ownRule("2", "b@example.test")))
	got, err := c.SyncRoutingRules(context.Background(), "zone", "example.test",
		[]string{"a@example.test", "b@example.test", "c@example.test"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Added) != 2 || len(got.Pending) != 1 || got.Pending[0] != (SyncPending{Address: "c@example.test", Cause: SyncLimit}) {
		t.Fatalf("cap: %+v", got)
	}
}

func TestSyncRoutingRulesZoneLimit(t *testing.T) {
	full := []RoutingRule{}
	for i := 0; i < maxZoneRules; i++ {
		full = append(full, foreignRule("f", "u"+string(rune('a'+i%26))+string(rune('a'+i/26))+"@other.test"))
	}
	first := get(ruleList, full[:100])
	first.info = &resultInfo{Page: 1, PerPage: 100, TotalPages: 2, TotalCount: maxZoneRules}
	second := get(ruleList, full[100:])
	second.info = &resultInfo{Page: 2, PerPage: 100, TotalPages: 2, TotalCount: maxZoneRules}
	c := fixture(t, first, second)
	got, err := c.SyncRoutingRules(context.Background(), "zone", "example.test", []string{"a@example.test"}, 100)
	if err != nil || len(got.Pending) != 1 || got.Pending[0].Cause != SyncLimit {
		t.Fatalf("zone limit: %+v %v", got, err)
	}
}

func TestSyncRoutingRulesStopsOnAMissingPermission(t *testing.T) {
	refused := exchange{method: "POST", path: ruleList, status: 403, issues: []apiIssue{{Code: 10000, Message: "Authentication error"}}}
	c := fixture(t, get(ruleList, []RoutingRule{}), refused)
	_, err := c.SyncRoutingRules(context.Background(), "zone", "example.test", []string{"a@example.test", "b@example.test"}, 100)
	if !PermissionRefused(err) {
		t.Fatalf("want a permission refusal, got %v", err)
	}
}

func TestSyncRoutingRulesRefusesAddressesOutsideTheDomain(t *testing.T) {
	c := fixture(t) // no request at all
	if _, err := c.SyncRoutingRules(context.Background(), "zone", "example.test", []string{"a@other.test"}, 100); !IsKind(err, ErrInvalid) {
		t.Fatalf("outside domain: %v", err)
	}
}

func TestSyncRoutingRulesLimitedHoldsALargeRemovalButStillAdds(t *testing.T) {
	// Three of four rules would go, over a limit of two: none is deleted,
	// the new address is still added.
	rules := []RoutingRule{ownRule("a", "a@example.test"), ownRule("b", "b@example.test"),
		ownRule("c", "c@example.test"), ownRule("d", "d@example.test")}
	c := fixture(t, get(ruleList, rules), post(ruleList, ownRule("e", "e@example.test")))
	got, err := c.SyncRoutingRulesLimited(context.Background(), "zone", "example.test",
		[]string{"a@example.test", "e@example.test"}, 100, func(owned int) int {
			if owned != 4 {
				t.Errorf("owned %d", owned)
			}
			return 2
		})
	if err != nil || got.Held != 3 || len(got.Removed) != 0 || !reflect.DeepEqual(got.Added, []string{"e@example.test"}) {
		t.Fatalf("held: %+v %v", got, err)
	}
}

func TestSyncRoutingRulesLimitedAllowsASmallRemoval(t *testing.T) {
	rules := []RoutingRule{ownRule("a", "a@example.test"), ownRule("b", "b@example.test")}
	c := fixture(t, get(ruleList, rules), get(ruleList+"/b", rules[1]), del(ruleList+"/b"))
	got, err := c.SyncRoutingRulesLimited(context.Background(), "zone", "example.test",
		[]string{"a@example.test"}, 100, func(int) int { return 2 })
	if err != nil || got.Held != 0 || !reflect.DeepEqual(got.Removed, []string{"b@example.test"}) {
		t.Fatalf("small removal: %+v %v", got, err)
	}
}
