package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

type memoryKV struct {
	mu     sync.Mutex
	values map[string]json.RawMessage
}

func (m *memoryKV) Get(_ context.Context, mod, key string, out any) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.values[mod+"/"+key]
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(v, out)
}
func (m *memoryKV) Put(_ context.Context, mod, key string, v any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, e := json.Marshal(v)
	if m.values == nil {
		m.values = map[string]json.RawMessage{}
	}
	m.values[mod+"/"+key] = b
	return e
}

type secrets map[string]string

var secretsMu sync.Mutex

func (s secrets) Get(_ context.Context, k string) (string, error) {
	secretsMu.Lock()
	defer secretsMu.Unlock()
	return s[k], nil
}
func (s secrets) Put(_ context.Context, k, v string) error {
	secretsMu.Lock()
	defer secretsMu.Unlock()
	s[k] = v
	return nil
}
func (s secrets) Delete(_ context.Context, k string) error {
	secretsMu.Lock()
	defer secretsMu.Unlock()
	delete(s, k)
	return nil
}
func fakeEnv() core.Env {
	return core.Env{KV: &memoryKV{}, Secrets: secrets{"secret:provision": "fixture-credential-must-never-appear"}}
}
func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

type source struct {
	state   detect.State
	receive chan bool
	// domain: the state is the requested domain's (else the fixture's).
	domain bool
}

// MailDomains answers with the fixture state's MailPlus domains.
func (s source) MailDomains(context.Context, core.Env) ([]string, error) {
	if !s.state.Domains.IsKnown() {
		return nil, errors.New("unread")
	}
	out := []string{}
	for _, d := range s.state.Domains.Value {
		out = append(out, d.Name)
	}
	return out, nil
}

func (s source) Detect(_ context.Context, _ core.Env, r detect.Request) detect.State {
	if s.receive != nil {
		s.receive <- r.Receive
	}
	st := s.state
	if s.domain {
		st.Domain = r.Domain
	}
	return st
}

type fakeCloud struct {
	changes     []core.Change
	permissions []Permission
	restorable  bool
	writes      int
	undos       int
	value       string
	snapshot    json.RawMessage
	planErr     error
}

func (f *fakeCloud) RequiredPermissions(r PlanRequest) ([]Permission, error) {
	if f.permissions != nil {
		return f.permissions, nil
	}
	return []Permission{{Scope: "zone", Resource: r.ZoneID, Name: "Zone Read"}, {Scope: "zone", Resource: r.ZoneID, Name: "DNS Write"}}, nil
}
func (f *fakeCloud) Plan(_ context.Context, _ core.Env, r PlanRequest) (Prepared, error) {
	ps, _ := f.RequiredPermissions(r)
	cs := f.changes
	if cs == nil {
		for _, need := range r.Decision.Needs {
			if strings.HasPrefix(need, "dns.") {
				cs = append(cs, core.Change{ID: need, Target: "cloudflare.dns", ActionKey: "mail.setup.change." + need, Params: map[string]string{"domain": r.Domain}, Before: "missing", After: "new " + need})
			}
		}
	}
	return Prepared{Changes: cs, Permissions: ps, Restorable: f.restorable}, f.planErr
}
func (f *fakeCloud) Snapshot(_ context.Context, _ core.Env, _ core.Change) (json.RawMessage, error) {
	if f.snapshot != nil {
		return f.snapshot, nil
	}
	return raw(map[string]string{"before": f.value}), nil
}
func (f *fakeCloud) Apply(_ context.Context, _ core.Env, c core.Change) error {
	f.writes++
	f.value = c.After
	return nil
}
func (f *fakeCloud) Rollback(_ context.Context, _ core.Env, _ core.Change, b json.RawMessage) error {
	var v map[string]string
	if json.Unmarshal(b, &v) != nil {
		return errors.New("bad snapshot")
	}
	f.value = v["before"]
	f.undos++
	return nil
}

type verifier struct {
	result Verification
	err    error
}

func (v verifier) Verify(context.Context, core.Env, PlanRequest, []core.Change) (Verification, error) {
	return v.result, v.err
}

const owner = "admin"

// ready starts a flow and polls detection until the facts are in.
func ready(t *testing.T, w *Wizard, env core.Env, intent Intent) (string, DetectView) {
	t.Helper()
	ctx := context.Background()
	flow, e := w.Start(ctx, env, owner)
	if e != nil || flow.ID == "" || flow.Resume {
		t.Fatalf("start: %+v %v", flow, e)
	}
	v, e := w.Detect(ctx, env, owner, flow.ID, intent, "Example.TEST.", yes, false)
	if e != nil || v.Done {
		t.Fatalf("detection must start asynchronously: %+v %v", v, e)
	}
	deadline := time.Now().Add(time.Second)
	for !v.Done && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		v, e = w.Detect(ctx, env, owner, flow.ID, intent, "example.test", yes, false)
	}
	if e != nil || !v.Done || len(v.Facts) == 0 || v.Branch == nil {
		t.Fatalf("facts: %+v %v", v, e)
	}
	return flow.ID, v
}
func directWizard(f *fakeCloud, v verifier) *Wizard {
	return New(Options{Detector: source{state: healthy()}, Cloudflare: f, Verifier: v})
}
func preview(t *testing.T, w *Wizard, env core.Env, id string) PreviewView {
	t.Helper()
	ctx := context.Background()
	ps, e := permissions(w, ctx, env, owner, id, strings.Repeat("a", 32), strings.Repeat("b", 32))
	if e != nil || len(ps) != 2 {
		t.Fatalf("permissions: %+v %v", ps, e)
	}
	p, e := w.Preview(ctx, env, owner, id, Configuration{})
	if e != nil || len(p.Changes) == 0 || len(p.Permissions) != 2 {
		t.Fatalf("preview: %+v %v", p, e)
	}
	return p
}

// wait polls Status until the phase leaves the running phases.
func wait(t *testing.T, w *Wizard, env core.Env, id string) FlowView {
	t.Helper()
	w.Wait()
	v, e := w.Status(context.Background(), env, owner, id)
	if e != nil {
		t.Fatal(e)
	}
	return v
}

func TestFlowExactPreviewApplyVerifyKeep(t *testing.T) {
	env := fakeEnv()
	ctx := context.Background()
	f := &fakeCloud{restorable: true, value: "original"}
	w := directWizard(f, verifier{result: Verification{Readback: true, Delivery: true}})
	id, d := ready(t, w, env, Send)
	if d.Branch.Kind != "configure" || !d.Branch.NeedsAccount || len(d.Branch.Fields) != 0 {
		t.Fatalf("branch: %+v", d.Branch)
	}
	p := preview(t, w, env, id)
	if f.writes != 0 {
		t.Fatal("preview performed a remote write")
	}
	if len(p.Changes) != 3 || p.Changes[0].Target != "cloudflare.dns" {
		t.Fatalf("unexpected changes: %+v", p.Changes)
	}
	// Apply of a single change is refused until a durable snapshot exists.
	if !errors.Is(w.ApplyChange(ctx, env, p.Changes[0]), ErrUnsafe) {
		t.Fatal("apply without snapshot accepted")
	}
	if _, e := w.Decide(ctx, env, owner, id, "keep"); !errors.Is(e, ErrBusy) {
		t.Fatal("keep accepted before apply")
	}
	started, e := w.Apply(ctx, env, owner, id)
	if e != nil || started.Phase != PhaseApplying || started.Total != 3 {
		t.Fatalf("apply: %+v %v", started, e)
	}
	v := wait(t, w, env, id)
	if v.Phase != PhaseDecision || !v.Verified || v.Done != 3 {
		t.Fatalf("decision: %+v", v)
	}
	if f.value != p.Changes[len(p.Changes)-1].After || f.writes != 3 {
		t.Fatal("planned record not applied exactly once")
	}
	if e := w.ApplyChange(ctx, env, p.Changes[0]); e != nil || f.writes != 3 {
		t.Fatal("repeat apply not idempotent")
	}
	if _, e := w.Apply(ctx, env, owner, id); !errors.Is(e, ErrBusy) {
		t.Fatal("second apply accepted")
	}
	// A closed window resumes the open decision instead of starting over.
	again, e := w.Start(ctx, env, owner)
	if e != nil || !again.Resume || again.ID != id || again.Phase != PhaseDecision {
		t.Fatalf("resume: %+v %v", again, e)
	}
	v, e = w.Decide(ctx, env, owner, id, "keep")
	if e != nil || v.Outcome != "ok" || v.Phase != PhaseKept {
		t.Fatalf("keep: %+v %v", v, e)
	}
	fresh, e := w.Start(ctx, env, owner)
	if e != nil || fresh.Resume || fresh.ID == id {
		t.Fatalf("kept flow was resumed: %+v %v", fresh, e)
	}
	// Reading again reuses the open, empty flow without a new ID.
	if again, e := w.Start(ctx, env, owner); e != nil || again.ID != fresh.ID {
		t.Fatalf("open flow replaced: %+v %v", again, e)
	}
	b, _ := json.Marshal(env.KV.(*memoryKV).values)
	if strings.Contains(string(b), "fixture-credential-must-never-appear") {
		t.Fatal("credential in stored flow")
	}
}

func TestFailedVerifyRetainsRollbackAndCannotClaimSuccess(t *testing.T) {
	env := fakeEnv()
	ctx := context.Background()
	f := &fakeCloud{restorable: true, value: "original"}
	w := directWizard(f, verifier{err: errors.New("credential-bearing transport error must be sanitized")})
	id, _ := ready(t, w, env, Send)
	preview(t, w, env, id)
	if _, e := w.Apply(ctx, env, owner, id); e != nil {
		t.Fatal(e)
	}
	v := wait(t, w, env, id)
	if v.Phase != PhaseDecision || v.Verified || len(v.Findings) != 1 || v.Findings[0].Severity != core.SeverityWarning {
		t.Fatalf("failed verify: %+v", v)
	}
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "credential-bearing") {
		t.Fatal("verifier error text leaked")
	}
	if _, e := w.Decide(ctx, env, owner, id, "rollback"); e != nil {
		t.Fatal(e)
	}
	v = wait(t, w, env, id)
	if v.Phase != PhaseRolledBack || v.Outcome != "rolledBack" || f.value != "original" || f.undos != 3 {
		t.Fatalf("rollback did not restore original value: %+v %q %d", v, f.value, f.undos)
	}
}

func TestKeepingUnverifiedChangesIsRecordedAsFailed(t *testing.T) {
	env := fakeEnv()
	ctx := context.Background()
	w := directWizard(&fakeCloud{restorable: true}, verifier{result: Verification{Readback: true}})
	id, _ := ready(t, w, env, Send)
	preview(t, w, env, id)
	if _, e := w.Apply(ctx, env, owner, id); e != nil {
		t.Fatal(e)
	}
	wait(t, w, env, id)
	v, e := w.Decide(ctx, env, owner, id, "keep")
	if e != nil || v.Outcome != "failed" {
		t.Fatalf("unverified keep: %+v %v", v, e)
	}
}

type failingCloud struct {
	*fakeCloud
	failAt int
	err    error
}

func (f *failingCloud) Apply(ctx context.Context, env core.Env, c core.Change) error {
	if f.writes+1 == f.failAt {
		f.writes++
		if f.err != nil {
			return f.err
		}
		return errors.New("provider said SECRET")
	}
	return f.fakeCloud.Apply(ctx, env, c)
}

func TestApplyFailureRollsBackIncludingTheInFlightChange(t *testing.T) {
	env := fakeEnv()
	ctx := context.Background()
	f := &failingCloud{fakeCloud: &fakeCloud{restorable: true, value: "original"}, failAt: 2}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: f, Verifier: verifier{result: Verification{Readback: true, Delivery: true}}})
	id, _ := ready(t, w, env, Send)
	preview(t, w, env, id)
	if _, e := w.Apply(ctx, env, owner, id); e != nil {
		t.Fatal(e)
	}
	v := wait(t, w, env, id)
	// The second change's reply was lost (error): it is journaled and rolled
	// back from its snapshot too, newest first.
	if v.Phase != PhaseRolledBack || v.Error == "" || strings.Contains(v.Error, "SECRET") || f.undos != 2 || f.value != "original" {
		t.Fatalf("failed apply: %+v undos=%d value=%q", v, f.undos, f.value)
	}
}

// A write refused for a missing DSM grant names the grant and
// the step it stopped at, never a DSM code.
func TestApplyRefusedForAMissingGrantNamesTheGrantAndTheStep(t *testing.T) {
	env := fakeEnv()
	ctx := context.Background()
	f := &failingCloud{fakeCloud: &fakeCloud{restorable: true, value: "original"}, failAt: 2,
		err: fmt.Errorf("dsm said 105: %w", core.AuthorityRequired{Profile: "mail-write"})}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: f, Verifier: verifier{result: Verification{Readback: true, Delivery: true}}})
	id, _ := ready(t, w, env, Send)
	preview(t, w, env, id)
	if _, e := w.Apply(ctx, env, owner, id); e != nil {
		t.Fatal(e)
	}
	v := wait(t, w, env, id)
	if v.Phase != PhaseRolledBack || v.Error != "authority_required:mail-write" || len(v.Changes) < 2 || v.FailedStep != v.Changes[1].ID {
		t.Fatalf("refused apply: phase=%s error=%q step=%q", v.Phase, v.Error, v.FailedStep)
	}
	if strings.Contains(v.Error, "105") {
		t.Fatal("DSM code leaked")
	}
}

func TestInterruptedTransactionOffersRollback(t *testing.T) {
	env := fakeEnv()
	ctx := context.Background()
	f := &fakeCloud{restorable: true, value: "original"}
	w := directWizard(f, verifier{result: Verification{Readback: true, Delivery: true}})
	id, _ := ready(t, w, env, Send)
	p := preview(t, w, env, id)
	// Simulate a worker that stopped after journaling and applying one change.
	snap, e := w.Snapshot(ctx, env, p.Changes[0])
	if e != nil {
		t.Fatal(e)
	}
	if e := w.ApplyChange(ctx, env, p.Changes[0]); e != nil {
		t.Fatal(e)
	}
	if _, e := w.update(ctx, env, owner, id, func(fl *Flow) error {
		fl.Phase, fl.Applied = PhaseApplying, []AppliedChange{{Change: p.Changes[0], Snapshot: snap}}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	restarted := directWizard(f, verifier{})
	v, e := restarted.Start(ctx, env, owner)
	if e != nil || !v.Resume || v.Phase != PhaseInterrupted {
		t.Fatalf("interrupted: %+v %v", v, e)
	}
	if _, e := restarted.Detect(ctx, env, owner, id, Send, "example.test", yes, true); !errors.Is(e, ErrStale) {
		t.Fatal("new detection over a half-applied plan")
	}
	if _, e := restarted.Decide(ctx, env, owner, id, "keep"); !errors.Is(e, ErrBusy) {
		t.Fatal("unverified interrupted plan kept")
	}
	if _, e := restarted.Decide(ctx, env, owner, id, "rollback"); e != nil {
		t.Fatal(e)
	}
	if v = wait(t, restarted, env, id); v.Phase != PhaseRolledBack || f.value != "original" {
		t.Fatalf("rollback after interruption: %+v %q", v, f.value)
	}
}

func TestInvalidAndUnsafePlansAreRefused(t *testing.T) {
	cases := []struct {
		name string
		f    *fakeCloud
	}{
		{"unrestorable", &fakeCloud{}},
		{"wrong-target", &fakeCloud{restorable: true, changes: []core.Change{{ID: "x", Target: "mailplus.smtp", ActionKey: "mail.setup.change.mailplus.smtp", Before: "a", After: "b"}}}},
		{"credential-leak", &fakeCloud{restorable: true, changes: []core.Change{{ID: "x", Target: "cloudflare.dns", ActionKey: "mail.setup.change.dns.spf", Before: "a", After: "fixture-credential-must-never-appear"}}}},
		{"password-field", &fakeCloud{restorable: true, changes: []core.Change{{ID: "x", Target: "cloudflare.dns", ActionKey: "mail.setup.change.dns.spf", Before: "a", After: "b", Params: map[string]string{"password": "hidden"}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := fakeEnv()
			w := directWizard(tc.f, verifier{})
			id, _ := ready(t, w, env, Send)
			if _, e := permissions(w, context.Background(), env, owner, id, strings.Repeat("a", 32), strings.Repeat("b", 32)); e != nil {
				t.Fatal(e)
			}
			_, e := w.Preview(context.Background(), env, owner, id, Configuration{})
			if e == nil || tc.f.writes != 0 {
				t.Fatalf("unsafe plan accepted: %v", e)
			}
			if _, e := w.Apply(context.Background(), env, owner, id); !errors.Is(e, ErrBusy) {
				t.Fatal("apply without a plan accepted")
			}
		})
	}
	env := fakeEnv()
	w := directWizard(&fakeCloud{restorable: true, permissions: []Permission{{Scope: "zone", Resource: strings.Repeat("c", 32), Name: "DNS Write"}}}, verifier{})
	id, _ := ready(t, w, env, Send)
	if _, e := permissions(w, context.Background(), env, owner, id, strings.Repeat("a", 32), strings.Repeat("b", 32)); e == nil {
		t.Fatal("wrong-resource permission scope accepted")
	}
	if _, e := permissions(w, context.Background(), env, owner, id, "not-hex", strings.Repeat("b", 32)); !errors.Is(e, ErrInvalid) {
		t.Fatal("invalid account accepted")
	}
}

func TestTamperedChangesAndForgedSnapshotsRefused(t *testing.T) {
	env := fakeEnv()
	ctx := context.Background()
	f := &fakeCloud{restorable: true}
	w := directWizard(f, verifier{result: Verification{Readback: true, Delivery: true}})
	id, _ := ready(t, w, env, Send)
	p := preview(t, w, env, id)
	c := p.Changes[0]
	c.After = "different record"
	if _, e := w.Snapshot(ctx, env, c); e == nil {
		t.Fatal("tampered preview accepted")
	}
	if _, e := w.Apply(ctx, env, owner, id); e != nil {
		t.Fatal(e)
	}
	wait(t, w, env, id)
	if e := w.RollbackChange(ctx, env, p.Changes[0], raw(map[string]string{"before": "forged"})); e == nil {
		t.Fatal("forged snapshot accepted")
	}
	if _, e := w.Preview(ctx, env, owner, id, Configuration{}); !errors.Is(e, ErrStale) {
		t.Fatalf("new preview over applied plan accepted: %v", e)
	}
}

func TestOtherAdministratorCannotReachTheFlow(t *testing.T) {
	env := fakeEnv()
	w := directWizard(&fakeCloud{restorable: true}, verifier{})
	id, _ := ready(t, w, env, Send)
	if _, e := w.Status(context.Background(), env, "other", id); !errors.Is(e, ErrNoFlow) {
		t.Fatal("other administrator read the flow")
	}
	if _, e := w.Detect(context.Background(), env, owner, "forged", Send, "example.test", yes, false); !errors.Is(e, ErrNoFlow) {
		t.Fatal("forged flow ID accepted")
	}
}

func TestIntentAndReceiveConsent(t *testing.T) {
	for _, intent := range []Intent{Send, Receive, Both} {
		t.Run(string(intent), func(t *testing.T) {
			ch := make(chan bool, 1)
			w := New(Options{Detector: source{state: healthy(), receive: ch}})
			ready(t, w, fakeEnv(), intent)
			if got := <-ch; got != intent.Receives() {
				t.Fatal("receive probe consent did not match intent")
			}
		})
	}
	// Diagnose and check are browser hand-offs to the diagnose wizard.
	for _, intent := range []Intent{Diagnose, Check, Intent("invented")} {
		w := New(Options{Detector: source{state: healthy()}})
		env := fakeEnv()
		flow, _ := w.Start(context.Background(), env, owner)
		if _, e := w.Detect(context.Background(), env, owner, flow.ID, intent, "example.test", yes, false); !errors.Is(e, ErrInvalid) {
			t.Fatalf("intent %q accepted by detection", intent)
		}
	}
}

func TestSecretsAndExactAddressValidation(t *testing.T) {
	state := healthy()
	decision := Decide(state, Receive, yes)
	decision.Receive = RoutingReceive
	decision.Needs = []string{"cloudflare.inbound"}
	base := form{AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), TokenRef: "secret:provision"}
	r, e := makeRequest("s", state, Receive, decision, base)
	if e != nil || len(r.Addresses) == 0 {
		t.Fatal(r.Addresses, e)
	}
	// Receiving through Cloudflare takes no typed address at all, a valid one
	// included: MailPlus Server's own list is the only source.
	for _, address := range []string{"alice@example.test", "*@example.test", "alice@other.test", "mallory@example.test", "Alice <alice@example.test>"} {
		f := base
		f.Addresses = address
		if _, e := makeRequest("s", state, Receive, decision, f); !errors.Is(e, ErrInvalid) {
			t.Fatalf("typed address accepted: %q", address)
		}
	}
	f := base
	f.TokenRef = "raw-credential-not-a-secret-reference"
	if _, e := makeRequest("s", state, Receive, decision, f); !errors.Is(e, ErrInvalid) {
		t.Fatal("raw credential accepted")
	}
}

// Exercise cancellation of a poll request while the bounded read-only job runs
func TestDetectionSurvivesPollRequestCancellation(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	w := New(Options{Detector: blockingSource{entered: entered, release: release}, Timeout: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	_, done, e := w.pollDetection(ctx, core.Env{}, "job", detect.Request{Domain: "example.test"}, nil)
	if done || e != nil {
		t.Fatal("detection should start asynchronously")
	}
	<-entered
	cancel()
	close(release)
	w.mu.Lock()
	job := w.jobs["job"]
	w.mu.Unlock()
	<-job.done
	_, done, e = w.pollDetection(context.Background(), core.Env{}, "job", detect.Request{}, nil)
	if !done || e != nil {
		t.Fatal("poll cancellation discarded bounded detection")
	}
}

type blockingSource struct {
	entered chan struct{}
	release chan struct{}
}

func (b blockingSource) Detect(ctx context.Context, _ core.Env, _ detect.Request) detect.State {
	close(b.entered)
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	return healthy()
}

func TestMissingSecretAndSecretSnapshotFailClosed(t *testing.T) {
	env := fakeEnv()
	ctx := context.Background()
	f := &fakeCloud{restorable: true}
	w := directWizard(f, verifier{})
	id, _ := ready(t, w, env, Send)
	p := preview(t, w, env, id)
	f.snapshot = raw(map[string]string{"before": "fixture-credential-must-never-appear"})
	if _, e := w.Snapshot(ctx, env, p.Changes[0]); !errors.Is(e, ErrUnsafe) {
		t.Fatal("secret snapshot accepted")
	}
	if _, e := w.Apply(ctx, env, owner, id); e != nil {
		t.Fatal(e)
	}
	if v := wait(t, w, env, id); v.Phase != PhaseRolledBack || f.writes != 0 {
		t.Fatalf("secret snapshot reached a write: %+v", v)
	}
	env2 := fakeEnv()
	w2 := directWizard(&fakeCloud{restorable: true}, verifier{})
	id2, _ := ready(t, w2, env2, Send)
	if _, e := permissions(w2, ctx, env2, owner, id2, strings.Repeat("a", 32), strings.Repeat("b", 32)); e != nil {
		t.Fatal(e)
	}
	// The sign-in's sealed token disappears before the preview.
	if g, _ := w2.load(ctx, env2, owner, id2); g.Cloud == nil || g.Cloud.TokenRef == "" {
		t.Fatal("no sealed sign-in token")
	} else {
		delete(env2.Secrets.(secrets), g.Cloud.TokenRef)
	}
	if _, e := w2.Preview(ctx, env2, owner, id2, Configuration{}); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("absent secret was not rejected: %v", e)
	}
}
