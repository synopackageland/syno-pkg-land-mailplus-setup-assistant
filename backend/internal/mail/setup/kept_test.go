package setup

import (
	"context"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

// keptRecorder is an InboundSync that records the kept setups.
type keptRecorder struct {
	kept []KeptSetup
	err  error
}

func (k *keptRecorder) ReceiveModes(context.Context, core.Env, string, string, string) (ReceiveModes, error) {
	return ReceiveModes{Domain: true}, nil
}

func (k *keptRecorder) Kept(_ context.Context, _ core.Env, s KeptSetup) error {
	k.kept = append(k.kept, s)
	return k.err
}

func keepCloudSetup(t *testing.T, inbound InboundSync) core.Env {
	t.Helper()
	ctx := context.Background()
	w, _ := cloudRouteWizard(newDirectory())
	w.options.Inbound = inbound
	env := fakeEnv()
	flow, _ := w.Start(ctx, env, owner)
	if err := signIn(w, ctx, env, owner, flow.ID); err != nil {
		t.Fatal(err)
	}
	detectDone(t, w, env, flow.ID, Send, "example.test", viaCloudflare)
	p, e := w.Preview(ctx, env, owner, flow.ID, Configuration{})
	for e == nil && p.Pending {
		time.Sleep(time.Millisecond)
		p, e = w.PollPreview(ctx, env, owner, flow.ID)
	}
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.Apply(ctx, env, owner, flow.ID); e != nil {
		t.Fatal(e)
	}
	w.Wait()
	if _, e = w.Decide(ctx, env, owner, flow.ID, "keep"); e != nil {
		t.Fatal(e)
	}
	w.Wait()
	return env
}

// a kept Cloudflare setup hands its sealed token to its record (for
// the mailbox sync and the removal); without a record the token is dropped.
func TestKeptSetupTakesOverTheToken(t *testing.T) {
	rec := &keptRecorder{}
	env := keepCloudSetup(t, rec)
	if len(rec.kept) != 1 {
		t.Fatalf("kept: %+v", rec.kept)
	}
	k := rec.kept[0]
	if k.Domain != "example.test" || k.AccountID != testAccount || k.ZoneID != testZone || len(k.Applied) == 0 {
		t.Fatalf("kept setup: %+v", k)
	}
	if refs := tokenRefs(env); len(refs) != 1 || refs[0] != k.TokenRef {
		t.Fatalf("the record's token must stay sealed: %v vs %q", refs, k.TokenRef)
	}

	// Nothing on Cloudflare to keep (ErrNotFound): the token is dropped.
	env = keepCloudSetup(t, &keptRecorder{err: core.ErrNotFound})
	if refs := tokenRefs(env); len(refs) != 0 {
		t.Fatalf("token kept without a record: %v", refs)
	}
	// No record keeper at all: dropped as before.
	env = keepCloudSetup(t, nil)
	if refs := tokenRefs(env); len(refs) != 0 {
		t.Fatalf("token kept without a record keeper: %v", refs)
	}
}
