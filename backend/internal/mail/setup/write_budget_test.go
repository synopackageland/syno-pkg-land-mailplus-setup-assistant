package setup

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

// uncertainCloud: the first write goes out (the value changes) but its reply
// is lost; rollback reads fail while unreadable is set.
type uncertainCloud struct {
	*fakeCloud
	unreadable int
	rollbacks  int
}

func (f *uncertainCloud) Apply(ctx context.Context, env core.Env, c core.Change) error {
	if f.writes == 0 {
		f.writes++
		f.value = c.After
		return core.ErrDSMWriteUncertain
	}
	return f.fakeCloud.Apply(ctx, env, c)
}

func (f *uncertainCloud) Rollback(ctx context.Context, env core.Env, c core.Change, b json.RawMessage) error {
	f.rollbacks++
	if f.unreadable > 0 {
		f.unreadable--
		return core.ErrDSMTimeout // the current setting could not be read in time
	}
	return f.fakeCloud.Rollback(ctx, env, c, b)
}

func TestUncertainWriteIsReconciledNeverResent(t *testing.T) {
	env := fakeEnv()
	f := &uncertainCloud{fakeCloud: &fakeCloud{restorable: true, value: "original"}}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: f, Verifier: verifier{result: Verification{Readback: true, Delivery: true}}})
	id, _ := ready(t, w, env, Send)
	preview(t, w, env, id)
	if _, e := w.Apply(context.Background(), env, owner, id); e != nil {
		t.Fatal(e)
	}
	v := wait(t, w, env, id)
	if v.Phase != PhaseRolledBack || v.Error != ErrUnconfirmed.Error() || f.writes != 1 || f.undos != 1 || f.value != "original" {
		t.Fatalf("uncertain write: %+v writes=%d undos=%d value=%q", v, f.writes, f.undos, f.value)
	}
}

func TestUnreadableRollbackEndsUnconfirmedAndWaitsForTheAdministrator(t *testing.T) {
	env := fakeEnv()
	f := &uncertainCloud{fakeCloud: &fakeCloud{restorable: true, value: "original"}, unreadable: 1}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: f, Verifier: verifier{result: Verification{Readback: true, Delivery: true}}})
	id, _ := ready(t, w, env, Send)
	preview(t, w, env, id)
	if _, e := w.Apply(context.Background(), env, owner, id); e != nil {
		t.Fatal(e)
	}
	v := wait(t, w, env, id)
	// The state is unknown: failed, says so, and nothing was written again.
	if v.Phase != PhaseFailed || v.Error != ErrUnconfirmed.Error() || f.writes != 1 || f.rollbacks != 1 || f.value == "original" {
		t.Fatalf("unreadable rollback: %+v writes=%d rollbacks=%d", v, f.writes, f.rollbacks)
	}
	// Only the administrator's explicit rollback tries again.
	if _, e := w.Decide(context.Background(), env, owner, id, "rollback"); e != nil {
		t.Fatal(e)
	}
	v = wait(t, w, env, id)
	if v.Phase != PhaseRolledBack || f.writes != 1 || f.value != "original" {
		t.Fatalf("explicit rollback: %+v writes=%d value=%q", v, f.writes, f.value)
	}
}

// A rollback after the apply's own budget ran out still runs: it has its own.
func TestRollbackAfterAnExpiredApplyBudget(t *testing.T) {
	env := fakeEnv()
	f := &fakeCloud{restorable: true, value: "original"}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: f, Verifier: verifier{result: Verification{Readback: true, Delivery: true}}})
	id, _ := ready(t, w, env, Send)
	preview(t, w, env, id)
	if _, e := w.Apply(context.Background(), env, owner, id); e != nil {
		t.Fatal(e)
	}
	if v := wait(t, w, env, id); v.Phase != PhaseDecision || f.writes == 0 {
		t.Fatalf("apply: %+v", v)
	}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	w.failAndRollback(expired, env, owner, id, context.DeadlineExceeded)
	v, e := w.Status(context.Background(), env, owner, id)
	if e != nil || v.Phase != PhaseRolledBack || v.Error != ErrUnconfirmed.Error() || f.value != "original" {
		t.Fatalf("rollback after expired budget: %+v %v value=%q", v, e, f.value)
	}
}

// slowCloud prepares its plan slowly, like MailPlus reads on a loaded NAS.
type slowCloud struct {
	*fakeCloud
	delay time.Duration
}

func (f *slowCloud) Plan(ctx context.Context, env core.Env, r PlanRequest) (Prepared, error) {
	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
		return Prepared{}, ctx.Err()
	}
	return f.fakeCloud.Plan(ctx, env, r)
}

func TestPreviewWithTenSecondReadsSucceeds(t *testing.T) {
	t.Parallel()
	env := fakeEnv()
	f := &slowCloud{fakeCloud: &fakeCloud{restorable: true, value: "original"}, delay: 10 * time.Second}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: f, Verifier: verifier{result: Verification{Readback: true, Delivery: true}}})
	id, _ := ready(t, w, env, Send)
	preview(t, w, env, id) // within PreviewWait: one call returns the plan
}

func TestSlowPreviewAnswersPendingThenThePlan(t *testing.T) {
	env := fakeEnv()
	f := &slowCloud{fakeCloud: &fakeCloud{restorable: true, value: "original"}, delay: 300 * time.Millisecond}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: f, Verifier: verifier{result: Verification{Readback: true, Delivery: true}}})
	w.previewWait = 20 * time.Millisecond
	id, _ := ready(t, w, env, Send)
	ctx := context.Background()
	if _, e := permissions(w, ctx, env, owner, id, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); e != nil {
		t.Fatal(e)
	}
	p, e := w.Preview(ctx, env, owner, id, Configuration{})
	if e != nil || !p.Pending || p.Changes == nil {
		t.Fatalf("first reply must be pending: %+v %v", p, e)
	}
	if _, e := w.Apply(ctx, env, owner, id); e == nil {
		t.Fatal("applied a plan that was not prepared yet")
	}
	for range 100 {
		if p, e = w.PollPreview(ctx, env, owner, id); e != nil || !p.Pending {
			break
		}
	}
	if e != nil || p.Pending || len(p.Changes) == 0 {
		t.Fatalf("poll: %+v %v", p, e)
	}
	// A later poll returns the stored plan.
	if again, e := w.PollPreview(ctx, env, owner, id); e != nil || len(again.Changes) != len(p.Changes) {
		t.Fatalf("stored plan: %+v %v", again, e)
	}
}

func TestWriteWizardBudgetsHoldTwoMinuteCalls(t *testing.T) {
	if snapshotBudget < 2*core.DSMCallWall || changeBudget < 4*core.DSMCallWall || PrepareBudget < 6*core.DSMCallWall || VerifyBudget < DetectBudget {
		t.Fatal("a step cannot hold its calls at two minutes each")
	}
	if applyBudget(3) < 3*(snapshotBudget+changeBudget)+VerifyBudget || rollbackBudget(0) < changeBudget || rollbackBudget(3) < 3*changeBudget {
		t.Fatal("transaction budgets too small")
	}
	if PreviewWait >= 30*time.Second {
		t.Fatal("a preview call must answer well within the HTTP timeout")
	}
}

// gateCloud blocks every Apply until gate is closed.
type gateCloud struct {
	*fakeCloud
	gate    chan struct{}
	entered chan struct{}
}

func (f *gateCloud) Apply(ctx context.Context, env core.Env, c core.Change) error {
	select {
	case f.entered <- struct{}{}:
	default:
	}
	<-f.gate
	return f.fakeCloud.Apply(ctx, env, c)
}

func readyAs(t *testing.T, w *Wizard, env core.Env, who string) string {
	t.Helper()
	ctx := context.Background()
	flow, e := w.Start(ctx, env, who)
	if e != nil {
		t.Fatal(e)
	}
	for range 1000 {
		v, e := w.Detect(ctx, env, who, flow.ID, Send, "example.test", yes, false)
		if e != nil {
			t.Fatal(e)
		}
		if v.Done {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, e := permissions(w, ctx, env, who, flow.ID, strings.Repeat("a", 32), strings.Repeat("b", 32)); e != nil {
		t.Fatal(e)
	}
	if p, e := w.Preview(ctx, env, who, flow.ID, Configuration{}); e != nil || p.Pending {
		t.Fatal(p, e)
	}
	return flow.ID
}

func TestOneTransactionAtATimeForThePackage(t *testing.T) {
	env := fakeEnv()
	f := &gateCloud{fakeCloud: &fakeCloud{restorable: true, value: "original"}, gate: make(chan struct{}), entered: make(chan struct{}, 1)}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: f, Verifier: verifier{result: Verification{Readback: true, Delivery: true}}})
	a := readyAs(t, w, env, "alice")
	b := readyAs(t, w, env, "bob")
	if _, e := w.Apply(context.Background(), env, "alice", a); e != nil {
		t.Fatal(e)
	}
	<-f.entered // alice's transaction is writing
	if _, e := w.Apply(context.Background(), env, "bob", b); !errors.Is(e, ErrOtherTransaction) {
		t.Fatalf("a second administrator applied beside the first: %v", e)
	}
	close(f.gate)
	w.Wait()
	if _, e := w.Apply(context.Background(), env, "bob", b); e != nil {
		t.Fatalf("after the first finished: %v", e)
	}
	w.Wait()
}

func TestAStepThatNeverStartedIsNotUnconfirmed(t *testing.T) {
	if got := publicError(core.ErrDSMSlotTimeout); !errors.Is(got, ErrNotStarted) {
		t.Fatalf("not started: %v", got)
	}
	if publicCode(core.ErrDSMSlotTimeout) != ErrNotStarted.Error() || publicCode(core.ErrDSMWriteUncertain) != ErrUnconfirmed.Error() {
		t.Fatal("public codes")
	}
}

// countingPlan counts plan preparations; the first one hangs until canceled.
type countingPlan struct {
	*fakeCloud
	plans atomic.Int32
}

func (f *countingPlan) Plan(ctx context.Context, env core.Env, r PlanRequest) (Prepared, error) {
	if f.plans.Add(1) == 1 {
		<-ctx.Done()
		return Prepared{}, ctx.Err()
	}
	return f.fakeCloud.Plan(ctx, env, r)
}

func TestAnInterruptedPreviewPreparesAgainFromTheSealedAnswers(t *testing.T) {
	env := fakeEnv()
	bg := &core.Background{Abandon: 100 * time.Millisecond}
	f := &countingPlan{fakeCloud: &fakeCloud{restorable: true, value: "original"}}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: f, Verifier: verifier{result: Verification{Readback: true, Delivery: true}}, Background: bg})
	w.previewWait = 10 * time.Millisecond
	id, _ := ready(t, w, env, Send)
	ctx := context.Background()
	if _, e := permissions(w, ctx, env, owner, id, strings.Repeat("a", 32), strings.Repeat("b", 32)); e != nil {
		t.Fatal(e)
	}
	if p, e := w.Preview(ctx, env, owner, id, Configuration{}); e != nil || !p.Pending {
		t.Fatal(p, e)
	}
	bg.Wait() // nobody polled: the preparation was canceled
	var p PreviewView
	var e error
	for range 200 {
		if p, e = w.PollPreview(ctx, env, owner, id); e != nil || !p.Pending {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if e != nil || p.Pending || len(p.Changes) == 0 || f.plans.Load() != 2 {
		t.Fatalf("restart: %+v %v plans=%d", p, e, f.plans.Load())
	}
}

// notStartedCloud: the second change gets no executor slot (nothing sent).
type notStartedCloud struct{ *fakeCloud }

func (f *notStartedCloud) Apply(ctx context.Context, env core.Env, c core.Change) error {
	if f.writes == 1 {
		return core.ErrDSMSlotTimeout
	}
	return f.fakeCloud.Apply(ctx, env, c)
}

// Change 1 applied, change 2 never started: the flow rolls change 1 back and
// keeps the step's reason, whose text speaks only about that step.
func TestNotStartedAfterAnAppliedChangeNeverClaimsNothingChanged(t *testing.T) {
	env := fakeEnv()
	f := &notStartedCloud{&fakeCloud{restorable: true, value: "original"}}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: f, Verifier: verifier{result: Verification{Readback: true, Delivery: true}}})
	id, _ := ready(t, w, env, Send)
	if p := preview(t, w, env, id); len(p.Changes) < 2 {
		t.Fatalf("need two changes: %+v", p.Changes)
	}
	if _, e := w.Apply(context.Background(), env, owner, id); e != nil {
		t.Fatal(e)
	}
	v := wait(t, w, env, id)
	if v.Phase != PhaseRolledBack || v.Error != ErrNotStarted.Error() || f.writes != 1 || f.value != "original" {
		t.Fatalf("flow %+v writes=%d value=%q", v, f.writes, f.value)
	}
	root := filepath.Join("..", "..", "..", "..", "i18n", "messages")
	for _, loc := range []string{"en", "zh-TW", "zh-CN", "ja", "ko", "de", "fr", "es", "it"} {
		b, err := os.ReadFile(filepath.Join(root, loc+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var texts map[string]string
		if err := json.Unmarshal(b, &texts); err != nil {
			t.Fatal(err)
		}
		text := texts[ErrNotStarted.Error()]
		for _, claim := range []string{"nothing changed", "設定也沒有改變", "设置也没有改变", "nothing was changed"} {
			if strings.Contains(text, claim) {
				t.Fatalf("%s: %q claims the whole flow changed nothing", loc, text)
			}
		}
	}
}

// set_multiple went out, set_type never started: the change is partly
// applied, so it is not "not started", and rollback reconciles it.
func TestDeliveryActivationNotStartedIsPartlyAppliedNotNotStarted(t *testing.T) {
	ctx := context.Background()
	env := fakeEnv()
	dsm := dsmFake()
	env.DSM = dsm
	store := env.Secrets.(secrets)
	store["secret:auth-name"] = "fixture-auth-user"
	store["secret:auth-password"] = "fixture-auth-password"
	state := healthy()
	r := PlanRequest{SessionID: "partial-slot", Domain: state.Domain, State: state, Decision: Decision{Needs: []string{"mailplus.delivery"}}}
	mp := NewMailPlus()
	p, e := mp.Plan(ctx, env, r, relayPrior())
	if e != nil {
		t.Fatal(e)
	}
	c := p.Changes[0]
	snap, e := mp.Snapshot(ctx, env, c)
	if e != nil {
		t.Fatal(e)
	}
	dsm.notStarted = "SYNO.MailPlusServer.SMTP.Delivery.set_type"
	e = mp.Apply(ctx, env, c)
	if e == nil || errors.Is(e, ErrNotStarted) || !errors.Is(e, ErrUnavailable) || dsm.confidential != 1 || len(dsm.hosts) != 1 {
		t.Fatalf("partial activation reported as %v (hosts %v)", e, dsm.hosts)
	}
	// Rollback: set_type goes out, set_multiple never starts: partly
	// restored, again not "not started"; the next rollback finishes.
	dsm.notStarted = "SYNO.MailPlusServer.SMTP.Delivery.set_multiple"
	if e = mp.Rollback(ctx, env, c, snap); e == nil || errors.Is(e, ErrNotStarted) {
		t.Fatalf("partial rollback reported as %v", e)
	}
	if e = mp.Rollback(ctx, env, c, snap); e != nil || dsm.typ["host_type"] != "none" || len(dsm.hosts) != 0 {
		t.Fatalf("rollback not reconciled: %v %v %v", e, dsm.typ, dsm.hosts)
	}
}
