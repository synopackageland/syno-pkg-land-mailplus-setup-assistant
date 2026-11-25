package setup

import (
	"context"
	"sort"
	"strings"
	"testing"

	"SynoMailPlusSetupAssistant/internal/core"
)

// sealingCloud seals one operation per change at Plan time, the way the real
// adapters do (operationRef, plus a derived .attempt marker).
type sealingCloud struct{ *failingCloud }

func (s sealingCloud) Plan(ctx context.Context, env core.Env, r PlanRequest) (Prepared, error) {
	p, err := s.fakeCloud.Plan(ctx, env, r)
	for i, c := range p.Changes {
		ref := "secret:mail.setup.operation.fixture." + c.ID
		_ = env.Secrets.Put(ctx, ref, `{"op":"`+c.ID+`"}`)
		_ = env.Secrets.Put(ctx, ref+".attempt", "sent")
		params := map[string]string{"operationRef": ref}
		for k, v := range c.Params {
			params[k] = v
		}
		p.Changes[i].Params = params
	}
	return p, err
}

func sealed(s secrets) []string {
	secretsMu.Lock()
	defer secretsMu.Unlock()
	out := []string{}
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// A rolled-back flow leaves no sealed value of its own behind.
func TestNoSealedSecretOutlivesARolledBackFlow(t *testing.T) {
	env := fakeEnv()
	ctx := context.Background()
	f := sealingCloud{&failingCloud{fakeCloud: &fakeCloud{restorable: true, value: "original"}, failAt: 2}}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: f, Verifier: verifier{result: Verification{Readback: true, Delivery: true}}})
	id, _ := ready(t, w, env, Send)
	preview(t, w, env, id)
	planned := 0
	for _, k := range sealed(env.Secrets.(secrets)) {
		if strings.HasPrefix(k, "secret:mail.setup.operation.fixture.") {
			planned++
		}
	}
	if planned < 4 {
		t.Fatalf("the fixture sealed too little to prove anything: %v", sealed(env.Secrets.(secrets)))
	}
	if _, e := w.Apply(ctx, env, owner, id); e != nil {
		t.Fatal(e)
	}
	if v := wait(t, w, env, id); v.Phase != PhaseRolledBack {
		t.Fatalf("not rolled back: %+v", v)
	}
	// Only the environment's own credential (not the flow's) remains.
	if left := sealed(env.Secrets.(secrets)); len(left) != 1 || left[0] != "secret:provision" {
		t.Fatalf("sealed values outlived the flow: %v", left)
	}
}

func TestOperationSecretsListsOnlyChangeReferences(t *testing.T) {
	got := OperationSecrets([]core.Change{
		{Params: map[string]string{"operationRef": "secret:a", "credentialRef": "secret:b", "domain": "secret:not-a-ref"}},
		{Params: map[string]string{"tokenRef": "plain", "inbound": "routing"}},
	})
	want := []string{"secret:a", "secret:a.attempt", "secret:a.pass", "secret:a.receipt", "secret:a.user",
		"secret:b", "secret:b.attempt", "secret:b.pass", "secret:b.receipt", "secret:b.user"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v", got)
	}
}
