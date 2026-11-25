package mail

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

// The one-time sweep of sealed operations. Build 46 drops a plan's
// sealed operations when its flow is rolled back and each step's when a kept
// setup is removed (setup.DropOperationSecrets). Flows that builds ≤45 rolled
// back or removed left theirs behind: values nothing can read again. The
// sweep deletes exactly those: a value of an operation family that no kept
// setup and no live flow refers to. Tokens (the kept setup's, a flow's
// sign-in, the relay's) and the relay credentials are never in an operation
// family, so the sweep never sees them.
//
// The second sweep (build 48) deletes the flows' sealed
// sign-in tokens (secret:mail.setup.<flow>.token.<gen>) that no kept setup
// and no unfinished flow refers to: a flow drops its token when it is kept
// or rolled back, but older builds, or a delete that failed, left some
// behind. The relay's token and the relay credentials have their own keys.

// operationFamilies are the key prefixes under which a plan seals its
// operations (operationRef, credentialRef) and their .user/.pass/.attempt/
// .receipt derivatives.
var operationFamilies = []string{
	"secret:mail.setup.operation.",
	"secret:mail.wiring.cloudflare.",
	"secret:mail.wiring.credentials.",
	"secret:mail.wiring.relay.",
}

// The markers record that each sweep ran; each runs once per installation.
const (
	sweepModule       = "core.sweep"
	sweepMarker       = "operationSecrets.v1"
	sweepTokensMarker = "flowTokens.v1"
)

// SweepCount is what the sweep logs: counts only, never a key or a value.
type SweepCount struct {
	Sealed  int // sealed values before the sweep
	Removed int // values of the swept family nothing refers to, deleted
	Kept    int // values of the swept family a kept setup or a live flow refers to
	Ran     bool
}

func isOperationSecret(key string) bool {
	for _, p := range operationFamilies {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// SweepOperationSecretsOnce runs SweepOperationSecrets unless it already ran
// on this installation, and records that it ran only after it succeeded. The
// worker calls it at start, before it serves anything, so no flow moves while
// it reads. A second start reads one KV value and writes nothing.
func SweepOperationSecretsOnce(ctx context.Context, store *core.Store) (SweepCount, error) {
	return sweepOnce(ctx, store, sweepMarker, SweepOperationSecrets)
}

// SweepFlowTokensOnce runs SweepFlowTokens once per installation, the same
// way.
func SweepFlowTokensOnce(ctx context.Context, store *core.Store) (SweepCount, error) {
	return sweepOnce(ctx, store, sweepTokensMarker, SweepFlowTokens)
}

func sweepOnce(ctx context.Context, store *core.Store, marker string, sweep func(context.Context, *core.Store) (SweepCount, error)) (SweepCount, error) {
	var done bool
	if _, err := store.Get(ctx, sweepModule, marker, &done); err != nil {
		return SweepCount{}, err
	}
	if done {
		return SweepCount{}, nil
	}
	n, err := sweep(ctx, store)
	if err != nil {
		return n, err
	}
	return n, store.Put(ctx, sweepModule, marker, true)
}

// SweepOperationSecrets deletes the sealed operations no kept setup and no
// live flow refers to. It reads every kept record and every flow first; a
// record it cannot read stops it before any delete. It is idempotent: a
// second run finds nothing to delete.
func SweepOperationSecrets(ctx context.Context, store *core.Store) (SweepCount, error) {
	return sweepFamily(ctx, store, isOperationSecret, referencedOperations)
}

// SweepFlowTokens deletes the flows' sealed sign-in tokens no kept setup and
// no unfinished flow refers to, with the same rules.
func SweepFlowTokens(ctx context.Context, store *core.Store) (SweepCount, error) {
	return sweepFamily(ctx, store, isFlowToken, referencedTokens)
}

func sweepFamily(ctx context.Context, store *core.Store, family func(string) bool, referenced func(sweepRecords) map[string]bool) (SweepCount, error) {
	secrets := core.SecretStore{Store: store}
	keys, err := secrets.Keys(ctx)
	if err != nil {
		return SweepCount{}, err
	}
	recs, err := readSweepRecords(ctx, store)
	if err != nil {
		return SweepCount{}, err
	}
	needed := referenced(recs)
	n := SweepCount{Sealed: len(keys), Ran: true}
	for _, k := range keys {
		if !family(k) {
			continue
		}
		if needed[k] {
			n.Kept++
			continue
		}
		if err := secrets.Delete(ctx, k); err != nil {
			return n, err
		}
		n.Removed++
	}
	return n, nil
}

// isFlowToken: secret:mail.setup.<flow>.token.<gen> (setup.tokenRef), and the
// bare ".token" some older builds used. Never an operation, a kept-setup
// token of build ≤44 (secret:mail.kept.) or the relay's keys.
func isFlowToken(key string) bool {
	rest, ok := strings.CutPrefix(key, "secret:mail.setup.")
	if !ok || isOperationSecret(key) {
		return false
	}
	flow, tail, ok := strings.Cut(rest, ".")
	return ok && flow != "" && (tail == "token" || strings.HasPrefix(tail, "token."))
}

var errSweepRecord = errors.New("unreadable record")

// sweepRecords is every kept record and every flow, read strictly.
type sweepRecords struct {
	kept     []keptRecord
	recorded map[string]bool // kept KV keys that hold a record (or its tombstone)
	flows    []setup.Flow
}

func readSweepRecords(ctx context.Context, store *core.Store) (sweepRecords, error) {
	out := sweepRecords{recorded: map[string]bool{}}
	keptKeys, err := store.AllKeys(ctx, keptModule, "setup.")
	if err != nil {
		return out, err
	}
	for _, k := range keptKeys {
		out.recorded[k] = true
		var rec keptRecord
		if err := getRecord(ctx, store, keptModule, k, &rec); err != nil {
			return out, err
		}
		out.kept = append(out.kept, rec)
	}
	flowKeys, err := store.AllKeys(ctx, "mail.setup", "flow.")
	if err != nil {
		return out, err
	}
	for _, k := range flowKeys {
		var f setup.Flow
		if err := getRecord(ctx, store, "mail.setup", k, &f); err != nil {
			return out, err
		}
		out.flows = append(out.flows, f)
	}
	return out, nil
}

// referencedOperations lists the sealed operations still needed: those of
// every kept setup's remaining steps (its removal reads them), and those of
// every flow that is neither rolled back nor removed. A kept flow is covered
// by its kept record (which removal trims step by step, and empties when
// done); a kept flow without one keeps its operations, as it did before.
func referencedOperations(recs sweepRecords) map[string]bool {
	needed := map[string]bool{}
	add := func(changes []core.Change) {
		for _, ref := range setup.OperationSecrets(changes) {
			needed[ref] = true
		}
	}
	for _, rec := range recs.kept {
		add(appliedChanges(rec.Applied))
	}
	for _, f := range recs.flows {
		switch {
		case f.Phase == setup.PhaseRolledBack:
			continue
		case f.Phase == setup.PhaseKept && recs.recorded[keptKey(f.ID)]:
			continue
		}
		add(appliedChanges(f.Applied))
		if f.Plan != nil {
			add(f.Plan.Changes)
		}
	}
	return needed
}

// referencedTokens lists the sign-in tokens still needed: every kept setup's
// (its sync, its removal and the relay's replacement read it) and the
// sign-in of every unfinished flow (one that is neither kept nor rolled
// back: it may still plan, apply or roll back with it).
func referencedTokens(recs sweepRecords) map[string]bool {
	needed := map[string]bool{}
	for _, rec := range recs.kept {
		if rec.TokenRef != "" {
			needed[rec.TokenRef] = true
		}
	}
	for _, f := range recs.flows {
		if f.Phase == setup.PhaseKept || f.Phase == setup.PhaseRolledBack || f.Cloud == nil || f.Cloud.TokenRef == "" {
			continue
		}
		needed[f.Cloud.TokenRef] = true
	}
	return needed
}

func appliedChanges(applied []setup.AppliedChange) []core.Change {
	out := make([]core.Change, 0, len(applied))
	for _, a := range applied {
		out = append(out, a.Change)
	}
	return out
}

// getRecord reads one KV record strictly: a value that is gone between the
// listing and the read, or that does not decode, stops the sweep.
func getRecord(ctx context.Context, store *core.Store, module, key string, out any) error {
	var raw json.RawMessage
	found, err := store.Get(ctx, module, key, &raw)
	if err != nil {
		return err
	}
	if !found {
		return errSweepRecord
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return errSweepRecord
	}
	return nil
}
