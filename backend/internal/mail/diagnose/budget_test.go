package diagnose

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

// slowState answers after delay, like a NAS whose DSM reads take seconds.
type slowState struct {
	delay time.Duration
	calls atomic.Int32
}

func (s *slowState) Snapshot(ctx context.Context, _ core.Env) (State, error) {
	s.calls.Add(1)
	select {
	case <-time.After(s.delay):
		return healthy(), nil
	case <-ctx.Done():
		return State{}, ctx.Err()
	}
}

// poll drives the run like the wizard: short calls until it completes.
func poll(t *testing.T, r *Runner, env core.Env, id string, wait time.Duration) (Run, []string) {
	t.Helper()
	phases := []string{}
	for range 1000 {
		run, err := r.Next(context.Background(), env, "admin", id, wait)
		if err != nil {
			t.Fatal(err)
		}
		if run.Pending {
			phases = append(phases, run.Phase)
		}
		if run.Complete {
			return run, phases
		}
	}
	t.Fatal("run never completed")
	return Run{}, nil
}

// The sample-nas case: the read takes ~10 s. No call waits for it; the run reads
// once, reports progress, and every check judges the same snapshot.
func TestDiagnosisCompletesWhenTheReadTakesTenSeconds(t *testing.T) {
	t.Parallel()
	source := &slowState{delay: 10 * time.Second}
	r := &Runner{D: New(Dependencies{State: source, DNS: goodDNS(), Network: &fakeNetwork{}})}
	env := core.Env{Now: func() time.Time { return testNow }}
	run, err := r.Start("admin", CannotSend)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	call := time.Now()
	first, err := r.Next(context.Background(), env, "admin", run.ID, 300*time.Millisecond)
	if err != nil || !first.Pending || first.Phase != "reading" || time.Since(call) > 2*time.Second {
		t.Fatalf("first call must answer quickly with progress: %+v %v", first, err)
	}
	done, phases := poll(t, r, env, run.ID, 300*time.Millisecond)
	if done.Done != done.Total || source.calls.Load() != 1 {
		t.Fatalf("run %+v read %d times, want once", done, source.calls.Load())
	}
	if len(phases) == 0 || time.Since(started) < 9*time.Second {
		t.Fatal("no progress was reported during the slow read")
	}
	for _, f := range done.Findings {
		if strings.Contains(f.ID, ".unavailable") {
			t.Fatalf("a slow read is not an unavailable one: %s", f.ID)
		}
	}
}

// An unreadable snapshot is the MailPlus Server precondition unknown: one
// finding names why, and no other check runs (each would only repeat it).
func TestUnreadableSnapshotSaysWhyOnce(t *testing.T) {
	source := &fakeState{err: Unreadable{Cause: core.CauseTimeout}}
	r := &Runner{D: New(Dependencies{State: source, DNS: goodDNS(), Network: &fakeNetwork{}})}
	run, _ := r.Start("admin", CannotSend)
	done, _ := poll(t, r, core.Env{}, run.ID, time.Second)
	if len(done.Findings) != 1 || done.Findings[0].Check != string(MailPlus) || !done.Complete || done.Done != done.Total {
		t.Fatalf("want one unavailable MailPlus finding: %+v", done)
	}
	for _, f := range done.Findings {
		if !strings.HasSuffix(f.ID, ".unavailable") || f.WhyKey != "mail.setup.unreadable.timeout" || f.FixKey != "" {
			t.Fatalf("finding does not name the timeout: %+v", f)
		}
	}
	// A DSM code is never shown: not in the text, the params or the folded
	// evidence; known codes name their plain cause.
	for cause, key := range map[string]string{"dsm_117": "dsm", "dsm_105": "dsmPermission", "dsm_119": "dsmSession", "dsm_102": "mailplusApiMissing"} {
		f := unreadable(MailPlus, Unreadable{Cause: cause})
		if f.WhyKey != "mail.setup.unreadable."+key || f.Params["code"] != "" {
			t.Fatalf("%s: %+v", cause, f)
		}
		if strings.Contains(string(f.Evidence), "dsm_") || !strings.Contains(string(f.Evidence), `"mail.setup.cause.`+key+`"`) {
			t.Fatalf("%s: evidence shows the raw cause: %s", cause, f.Evidence)
		}
	}
}

// Raw DSM causes anywhere in evidence (nested too) become plain cause keys;
// other values pass unchanged.
func TestEvidenceNeverShowsADSMCode(t *testing.T) {
	ev := map[string]any{"cause": "dsm_105", "reads": []any{map[string]any{"api": "SYNO.MailPlusServer.Domain", "cause": "dsm_119"}}, "note": "dsm_x", "count": 3}
	got := string(plainEvidence(ev))
	for _, want := range []string{`"mail.setup.cause.dsmPermission"`, `"mail.setup.cause.dsmSession"`, `"dsm_x"`, `"count":3`, `"SYNO.MailPlusServer.Domain"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("evidence %s lacks %s", got, want)
		}
	}
	if strings.Contains(got, "dsm_105") || strings.Contains(got, "dsm_119") {
		t.Fatalf("raw DSM cause kept: %s", got)
	}
}

// An executor refusal code never reaches the page either: evidence and an
// unreadable finding name it in plain words, with no code in params.
func TestEvidenceNeverShowsAnExecutorCode(t *testing.T) {
	got := string(plainEvidence(map[string]any{"cause": "executor_POLICY_DENIED", "reads": []any{map[string]any{"cause": "executor_SOME_FUTURE_CODE"}}}))
	for _, want := range []string{`"mail.setup.cause.executorApproval"`, `"mail.setup.cause.executor"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("evidence %s lacks %s", got, want)
		}
	}
	if strings.Contains(got, "POLICY_DENIED") || strings.Contains(got, "SOME_FUTURE_CODE") {
		t.Fatalf("raw executor code kept: %s", got)
	}
	f := unreadable(MailPlus, Unreadable{Cause: "executor_POLICY_DENIED"})
	if f.WhyKey != "mail.setup.unreadable.executorApproval" || f.Params["code"] != "" || strings.Contains(string(f.Evidence), "POLICY_DENIED") {
		t.Fatalf("%+v %s", f, f.Evidence)
	}
	for k, v := range f.Params {
		if strings.Contains(v, "POLICY_DENIED") {
			t.Fatalf("param %s shows the code: %s", k, v)
		}
	}
}

// refusingDSM refuses like a revoked grant until granted is set.
type refusingDSM struct{ granted atomic.Bool }

func (d *refusingDSM) Call(context.Context, string, string, int, map[string]any, any) error {
	if d.granted.Load() {
		return nil
	}
	return core.AuthorityRequired{Profile: "mail-read"}
}

// readingState swallows DSM errors the way the detector does.
type readingState struct{ calls atomic.Int32 }

func (s *readingState) Snapshot(ctx context.Context, env core.Env) (State, error) {
	s.calls.Add(1)
	if err := env.DSM.Call(ctx, "SYNO.Core.Package", "list", 2, nil, nil); err != nil {
		return State{}, Unreadable{Cause: core.Cause(err)}
	}
	return healthy(), nil
}

func TestRefusedGrantPausesTheRunAndReadsAgainAfterTheGrant(t *testing.T) {
	dsm := &refusingDSM{}
	source := &readingState{}
	r := &Runner{D: New(Dependencies{State: source, DNS: goodDNS(), Network: &fakeNetwork{}})}
	env := core.Env{DSM: dsm, Now: func() time.Time { return testNow }}
	run, _ := r.Start("admin", CannotSend)
	_, err := r.Next(context.Background(), env, "admin", run.ID, time.Second)
	var authority core.AuthorityRequired
	if !errors.As(err, &authority) || authority.Profile != "mail-read" {
		t.Fatalf("refusal = %v, want authority_required", err)
	}
	dsm.granted.Store(true)
	done, _ := poll(t, r, env, run.ID, time.Second)
	if source.calls.Load() != 2 || done.Done != done.Total {
		t.Fatalf("after the grant the run must read again once: calls %d", source.calls.Load())
	}
}

func TestIPv6IsNotProbedWithoutAGlobalIPv6Address(t *testing.T) {
	for _, tc := range []struct {
		name string
		has  func() (bool, error)
		want string
	}{
		{"none", func() (bool, error) { return false, nil }, "no global IPv6 address"},
		{"undecidable", func() (bool, error) { return false, errors.New("netlink") }, "host addresses unavailable"},
	} {
		n := SystemNetwork{GlobalIPv6: tc.has}
		started := time.Now()
		e := n.Egress(context.Background(), "tcp6")
		ports := n.Outbound(context.Background(), "tcp6")
		if time.Since(started) > time.Second {
			t.Fatalf("%s: IPv6 was probed", tc.name)
		}
		if e.ProbeResult.Status != "unknown" || !strings.Contains(e.ProbeResult.Detail, tc.want) || len(e.Sources) != 0 {
			t.Fatalf("%s: egress = %+v, want unknown", tc.name, e)
		}
		for _, p := range ports {
			if p.Status != "unknown" || !strings.Contains(p.Detail, tc.want) {
				t.Fatalf("%s: port = %+v, want unknown", tc.name, p)
			}
		}
	}
}

func TestCheckBudgetsAreAligned(t *testing.T) {
	d := New(Dependencies{})
	if d.deps.RunTimeout != CheckBudget || CheckBudget < 10*time.Minute {
		t.Fatalf("RunTimeout %v, CheckBudget %v", d.deps.RunTimeout, CheckBudget)
	}
	if NextWait >= 30*time.Second {
		t.Fatalf("next waits %v; DSM's HTTP timeout must never be reached", NextWait)
	}
	if runTTL <= SnapshotBudget+CheckBudget {
		t.Fatal("a run must outlive its background work")
	}
}

func TestStoppingTheWorkerCancelsARunningDiagnosis(t *testing.T) {
	base, stop := context.WithCancel(context.Background())
	bg := &core.Background{Base: base}
	source := &slowState{delay: time.Hour}
	r := &Runner{D: New(Dependencies{State: source, DNS: goodDNS(), Network: &fakeNetwork{}}), Background: bg}
	run, _ := r.Start("admin", CannotSend)
	if p, err := r.Next(context.Background(), core.Env{}, "admin", run.ID, 50*time.Millisecond); err != nil || !p.Pending {
		t.Fatal(p, err)
	}
	stop()
	done := make(chan struct{})
	go func() { bg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the read kept running after the worker stopped")
	}
}

func TestAnUnpolledDiagnosisStopsAndRestartsWhenPolledAgain(t *testing.T) {
	bg := &core.Background{Abandon: 100 * time.Millisecond}
	source := &slowState{delay: time.Hour}
	r := &Runner{D: New(Dependencies{State: source, DNS: goodDNS(), Network: &fakeNetwork{}}), Background: bg}
	run, _ := r.Start("admin", CannotSend)
	if _, err := r.Next(context.Background(), core.Env{}, "admin", run.ID, 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { bg.Wait(); close(done) }()
	select {
	case <-done: // nobody polled: the slow read was canceled
	case <-time.After(5 * time.Second):
		t.Fatal("unpolled read kept running")
	}
	// The poller is back: the run reads again instead of using the cut read.
	source.delay = 10 * time.Millisecond
	got, _ := poll(t, r, core.Env{Now: func() time.Time { return testNow }}, run.ID, time.Second)
	if source.calls.Load() != 2 || got.Done != got.Total {
		t.Fatalf("restart: calls %d, run %+v", source.calls.Load(), got)
	}
	for _, f := range got.Findings {
		if strings.HasSuffix(f.ID, ".unavailable") {
			t.Fatal("the abandoned read leaked into the result")
		}
	}
}

// Licence counts are read now: an unread count says the read failed; the
// linked Synology Account is still not read by this version.
func TestUnreadLicenceSaysWhy(t *testing.T) {
	want := map[string]string{"license_unknown": "mail.diag.license_unread.why", "owner_unknown": "mail.diag.license_unchecked.why"}
	seen := 0
	for _, f := range checkAccess(State{}) {
		for cause, key := range want {
			if strings.Contains(f.ID, cause) {
				seen++
				if f.WhyKey != key {
					t.Fatalf("%s explains with %s, want %s", f.ID, f.WhyKey, key)
				}
			}
		}
	}
	if seen != 2 {
		t.Fatalf("saw %d of the two unknown licence findings", seen)
	}
}
