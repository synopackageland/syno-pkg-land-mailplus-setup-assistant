package mail

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/relay"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

func sweepStore(t *testing.T, env core.Env) *core.Store {
	t.Helper()
	store, ok := env.KV.(*core.Store)
	if !ok {
		t.Fatalf("fixture KV is %T, not the store", env.KV)
	}
	return store
}

func seal(t *testing.T, env core.Env, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if err := env.Secrets.Put(context.Background(), k, "fixture-value"); err != nil {
			t.Fatal(err)
		}
	}
}

func putFlow(t *testing.T, env core.Env, owner string, f setup.Flow) {
	t.Helper()
	if err := env.KV.Put(context.Background(), "mail.setup", setup.FlowKey(owner), f); err != nil {
		t.Fatal(err)
	}
}

func refChange(id, param, ref string) core.Change {
	return core.Change{ID: id, Target: "mailplus.delivery", Params: map[string]string{"domain": "example.test", param: ref}}
}

func without(all []string, gone map[string]bool) []string {
	out := []string{}
	for _, k := range all {
		if !gone[k] {
			out = append(out, k)
		}
	}
	return out
}

// the sealed operations builds ≤45 left behind (flows rolled back or
// removed) go; a kept setup's, a live flow's and every token stay; a second
// run deletes nothing.
func TestSweepRemovesOnlyOrphanedOperations(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	store := sweepStore(t, r.env)

	// Left by old flows: a rolled-back plan, a removed kept setup (its
	// record emptied), and values no record names at all.
	rolledBack := "secret:mail.wiring.relay." + strings.Repeat("1", 32)
	removed := "secret:mail.setup.operation." + strings.Repeat("2", 32)
	stray := "secret:mail.wiring.cloudflare." + strings.Repeat("3", 32)
	orphans := []string{
		rolledBack, rolledBack + ".attempt", rolledBack + ".receipt",
		"secret:mail.wiring.credentials." + strings.Repeat("1", 32), "secret:mail.wiring.credentials." + strings.Repeat("1", 32) + ".user", "secret:mail.wiring.credentials." + strings.Repeat("1", 32) + ".pass",
		removed,
		stray, stray + ".attempt", stray + ".receipt",
	}
	seal(t, r.env, orphans...)
	putFlow(t, r.env, "old-admin", setup.Flow{ID: strings.Repeat("a", 32), Owner: "old-admin", Phase: setup.PhaseRolledBack,
		Plan: nil, Applied: []setup.AppliedChange{{Change: refChange("relay.configure", "operationRef", rolledBack)}}})
	removedID := strings.Repeat("b", 32)
	putFlow(t, r.env, "gone-admin", setup.Flow{ID: removedID, Owner: "gone-admin", Phase: setup.PhaseKept,
		Applied: []setup.AppliedChange{{Change: refChange("mailplus.delivery", "operationRef", removed)}}})
	if err := r.env.KV.Put(ctx, keptModule, keptKey(removedID), keptRecord{}); err != nil {
		t.Fatal(err)
	}

	// Still needed: a flow mid-apply (plan and applied), a failed rollback,
	// and a kept flow that has no record (nothing else will drop them).
	live := "secret:mail.wiring.credentials." + strings.Repeat("4", 32)
	livePlan := "secret:mail.setup.operation." + strings.Repeat("5", 32)
	failed := "secret:mail.wiring.cloudflare." + strings.Repeat("6", 32)
	unrecorded := "secret:mail.setup.operation." + strings.Repeat("7", 32)
	needed := []string{live, live + ".user", live + ".pass", livePlan, failed, failed + ".attempt", unrecorded}
	seal(t, r.env, needed...)
	putFlow(t, r.env, "busy-admin", setup.Flow{ID: strings.Repeat("c", 32), Owner: "busy-admin", Phase: setup.PhaseApplying,
		Applied: []setup.AppliedChange{{Change: refChange("relay.configure", "credentialRef", live)}}})
	busy := setup.Flow{}
	if _, err := r.env.KV.Get(ctx, "mail.setup", setup.FlowKey("busy-admin"), &busy); err != nil {
		t.Fatal(err)
	}
	// The plan is only reachable through JSON (storedPlan is unexported).
	if err := r.env.KV.Put(ctx, "mail.setup", setup.FlowKey("busy-admin"), map[string]any{
		"id": busy.ID, "owner": busy.Owner, "phase": busy.Phase, "applied": busy.Applied,
		"plan": map[string]any{"changes": []core.Change{refChange("mailplus.dkim.disable", "operationRef", livePlan)}},
	}); err != nil {
		t.Fatal(err)
	}
	putFlow(t, r.env, "stuck-admin", setup.Flow{ID: strings.Repeat("e", 32), Owner: "stuck-admin", Phase: setup.PhaseFailed,
		Applied: []setup.AppliedChange{{Change: refChange("cloudflare.sending", "operationRef", failed)}}})
	putFlow(t, r.env, "local-admin", setup.Flow{ID: strings.Repeat("f", 32), Owner: "local-admin", Phase: setup.PhaseKept,
		Applied: []setup.AppliedChange{{Change: refChange("mailplus.delivery", "operationRef", unrecorded)}}})

	// Tokens and the relay's values are never operations.
	tokens := []string{"secret:mail.setup." + strings.Repeat("9", 32) + ".token." + strings.Repeat("8", 32), "mail.relay.credentials"}
	seal(t, r.env, tokens...)

	before := sealedKeys(t, r.env.DataDir)
	rec := r.record(t)
	keptOps := setup.OperationSecrets(appliedChanges(rec.Applied))
	if len(keptOps) == 0 || rec.TokenRef == "" {
		t.Fatalf("fixture: kept setup has no sealed operations or token: %+v", rec)
	}

	n, err := SweepOperationSecrets(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	gone := map[string]bool{}
	for _, k := range orphans {
		gone[k] = true
	}
	after := sealedKeys(t, r.env.DataDir)
	if want := without(before, gone); !reflect.DeepEqual(after, want) {
		t.Fatalf("after the sweep:\n got %v\nwant %v", after, want)
	}
	if n.Removed != len(orphans) || n.Sealed != len(before) || !n.Ran {
		t.Fatalf("counts %+v, want removed %d of %d", n, len(orphans), len(before))
	}
	have := map[string]bool{}
	for _, k := range after {
		have[k] = true
	}
	for _, k := range append(append(append([]string{rec.TokenRef, relay.TokenSecretKey}, tokens...), needed...), keptOps...) {
		if strings.HasSuffix(k, ".user") || strings.HasSuffix(k, ".pass") || strings.HasSuffix(k, ".attempt") || strings.HasSuffix(k, ".receipt") {
			if !have[k] && contains(before, k) {
				t.Fatalf("%s was swept", k)
			}
			continue
		}
		if !have[k] {
			t.Fatalf("%s was swept", k)
		}
	}

	// Idempotent: nothing left to remove.
	again, err := SweepOperationSecrets(ctx, store)
	if err != nil || again.Removed != 0 || again.Kept != n.Kept {
		t.Fatalf("second run %+v %v, first %+v", again, err, n)
	}
	if got := sealedKeys(t, r.env.DataDir); !reflect.DeepEqual(got, after) {
		t.Fatalf("second run changed the keys: %v", got)
	}

	// The kept setup still removes cleanly with what the sweep left.
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal == nil || view.Removal.State != "done" {
		t.Fatalf("removal after the sweep: %+v %v", view.Removal, err)
	}
}

func contains(list []string, k string) bool {
	for _, x := range list {
		if x == k {
			return true
		}
	}
	return false
}

// It runs once: the second start reads the marker and touches nothing.
func TestSweepRunsOncePerInstallation(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	store := sweepStore(t, r.env)
	orphan := "secret:mail.setup.operation." + strings.Repeat("2", 32)
	seal(t, r.env, orphan)
	n, err := SweepOperationSecretsOnce(ctx, store)
	if err != nil || !n.Ran || n.Removed != 1 {
		t.Fatalf("first start: %+v %v", n, err)
	}
	seal(t, r.env, orphan) // even a new leftover is not the sweep's business now
	n, err = SweepOperationSecretsOnce(ctx, store)
	if err != nil || n.Ran {
		t.Fatalf("second start ran again: %+v %v", n, err)
	}
	if !contains(sealedKeys(t, r.env.DataDir), orphan) {
		t.Fatal("second start deleted a value")
	}
}

// A record it cannot read stops the sweep before any delete, and it is not
// marked done, so the next start tries again.
func TestSweepStopsOnAnUnreadableRecord(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	store := sweepStore(t, r.env)
	orphan := "secret:mail.setup.operation." + strings.Repeat("2", 32)
	seal(t, r.env, orphan)
	if err := r.env.KV.Put(ctx, "mail.setup", setup.FlowKey("odd-admin"), "not a flow"); err != nil {
		t.Fatal(err)
	}
	before := sealedKeys(t, r.env.DataDir)
	if n, err := SweepOperationSecretsOnce(ctx, store); err == nil || n.Removed != 0 {
		t.Fatalf("swept past an unreadable flow: %+v %v", n, err)
	}
	if got := sealedKeys(t, r.env.DataDir); !reflect.DeepEqual(got, before) {
		t.Fatalf("keys changed: %v", got)
	}
	var done bool
	if _, err := store.Get(ctx, sweepModule, sweepMarker, &done); err != nil || done {
		t.Fatalf("marked done after a stop: %v %v", done, err)
	}
}

// putSignedIn stores a flow with a Cloudflare sign-in (the sign-in type is
// unexported, so through JSON).
func putSignedIn(t *testing.T, env core.Env, owner, id string, phase setup.Phase, tokenRef string) {
	t.Helper()
	if err := env.KV.Put(context.Background(), "mail.setup", setup.FlowKey(owner), map[string]any{
		"id": id, "owner": owner, "phase": phase, "cloud": map[string]any{"gen": strings.Repeat("0", 32), "tokenRef": tokenRef},
	}); err != nil {
		t.Fatal(err)
	}
}

// The flows' sign-in tokens nothing needs go (a kept or
// rolled-back flow's leftover, a bare ".token" from an older build, one no
// flow names); the kept setup's token, every unfinished flow's sign-in, the
// relay's keys, build ≤44 kept tokens and operations stay. A second run
// deletes nothing.
func TestSweepRemovesOnlyStaleFlowTokens(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	store := sweepStore(t, r.env)
	tok := func(flow, gen string) string {
		return "secret:mail.setup." + strings.Repeat(flow, 32) + ".token." + strings.Repeat(gen, 32)
	}
	stale := []string{
		tok("1", "a"), // a rolled-back flow still naming it
		tok("2", "b"), // a kept flow still naming it (its delete failed)
		tok("3", "c"), // no flow names it
		"secret:mail.setup." + strings.Repeat("4", 32) + ".token", // an older build's bare form
	}
	seal(t, r.env, stale...)
	putSignedIn(t, r.env, "rolled-admin", strings.Repeat("1", 32), setup.PhaseRolledBack, stale[0])
	putSignedIn(t, r.env, "kept-admin", strings.Repeat("2", 32), setup.PhaseKept, stale[1])

	live := map[setup.Phase]string{
		setup.PhaseNew: tok("5", "d"), setup.PhaseApplying: tok("6", "e"), setup.PhaseDecision: tok("7", "f"),
		setup.PhaseFailed: tok("8", "a"), setup.PhaseInterrupted: tok("9", "b"), setup.PhaseRollingBack: tok("a", "c"),
	}
	i := 0
	for phase, ref := range live {
		i++
		seal(t, r.env, ref)
		putSignedIn(t, r.env, "live-admin-"+string(rune('a'+i)), strings.Repeat(string(rune('a'+i)), 32), phase, ref)
	}
	others := []string{relay.TokenSecretKey, relay.CredentialsSecretKey, "secret:mail.kept." + strings.Repeat("c", 32),
		"secret:mail.setup.operation." + strings.Repeat("d", 32)}
	seal(t, r.env, others...)

	// The kept setup's token under the name a real setup gives it (the
	// record owns its flow's sign-in token).
	rec := r.record(t)
	value, err := r.env.Secrets.Get(ctx, rec.TokenRef)
	if err != nil {
		t.Fatal(err)
	}
	rec.TokenRef = tok("b", "e")
	if err := r.env.Secrets.Put(ctx, rec.TokenRef, value); err != nil {
		t.Fatal(err)
	}
	if err := r.env.KV.Put(ctx, keptModule, keptKey(r.id), rec); err != nil {
		t.Fatal(err)
	}
	before := sealedKeys(t, r.env.DataDir)
	n, err := SweepFlowTokens(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	gone := map[string]bool{}
	for _, k := range stale {
		gone[k] = true
	}
	after := sealedKeys(t, r.env.DataDir)
	if want := without(before, gone); !reflect.DeepEqual(after, want) {
		t.Fatalf("after the sweep:\n got %v\nwant %v", after, want)
	}
	if n.Removed != len(stale) || n.Kept != len(live)+1 || n.Sealed != len(before) || !n.Ran {
		t.Fatalf("counts %+v", n)
	}
	again, err := SweepFlowTokens(ctx, store)
	if err != nil || again.Removed != 0 || again.Kept != n.Kept {
		t.Fatalf("second run %+v %v", again, err)
	}
	// The kept setup still syncs its token into a removal.
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal == nil || view.Removal.State != "done" {
		t.Fatalf("removal after the sweep: %+v %v", view.Removal, err)
	}
}

func TestFlowTokenFamily(t *testing.T) {
	for key, want := range map[string]bool{
		"secret:mail.setup." + strings.Repeat("1", 32) + ".token." + strings.Repeat("2", 32): true,
		"secret:mail.setup." + strings.Repeat("1", 32) + ".token":                            true,
		"secret:mail.setup.operation." + strings.Repeat("1", 32):                             false,
		"secret:mail.setup." + strings.Repeat("1", 32) + ".tokens":                           false,
		"secret:mail.setup..token":                                                           false,
		"secret:mail.kept." + strings.Repeat("1", 32):                                        false,
		relay.TokenSecretKey:                                  false,
		relay.CredentialsSecretKey:                            false,
		"secret:mail.wiring.relay." + strings.Repeat("1", 32): false,
	} {
		if got := isFlowToken(key); got != want {
			t.Errorf("isFlowToken(%q) = %v", key, got)
		}
	}
}

// Once per installation, independent of the operation sweep (which already
// ran on installations of build 47); an unreadable flow stops it unmarked.
func TestFlowTokenSweepRunsOnceAndStopsOnAnUnreadableRecord(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	store := sweepStore(t, r.env)
	if err := store.Put(ctx, sweepModule, sweepMarker, true); err != nil {
		t.Fatal(err)
	}
	stale := "secret:mail.setup." + strings.Repeat("3", 32) + ".token"
	seal(t, r.env, stale)
	if err := r.env.KV.Put(ctx, "mail.setup", setup.FlowKey("odd-admin"), "not a flow"); err != nil {
		t.Fatal(err)
	}
	if n, err := SweepFlowTokensOnce(ctx, store); err == nil || n.Removed != 0 || !contains(sealedKeys(t, r.env.DataDir), stale) {
		t.Fatalf("swept past an unreadable flow: %+v %v", n, err)
	}
	var done bool
	if _, err := store.Get(ctx, sweepModule, sweepTokensMarker, &done); err != nil || done {
		t.Fatalf("marked done after a stop: %v %v", done, err)
	}
	putFlow(t, r.env, "odd-admin", setup.Flow{ID: strings.Repeat("f", 32), Owner: "odd-admin", Phase: setup.PhaseRolledBack})
	if n, err := SweepFlowTokensOnce(ctx, store); err != nil || !n.Ran || n.Removed != 1 {
		t.Fatalf("first start: %+v %v", n, err)
	}
	seal(t, r.env, stale)
	if n, err := SweepFlowTokensOnce(ctx, store); err != nil || n.Ran {
		t.Fatalf("second start ran again: %+v %v", n, err)
	}
}
