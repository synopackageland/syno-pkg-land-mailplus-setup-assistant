package core

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/synopackageland/syno-pkg-land-sdk/api"
	"github.com/synopackageland/syno-pkg-land-sdk/delegate"
)

// slowExecutor answers webapi.call after delay, honoring cancellation like
// the SDK client does, and records what each call was given.
type slowExecutor struct {
	delay     time.Duration
	busyFirst int
	mu        sync.Mutex
	active    int
	maxActive int
	calls     int
	budgets   []time.Duration
}

func (f *slowExecutor) Call(ctx context.Context, op string, _ map[string]string, _ any, out any) error {
	if op != "webapi.call" {
		return fmt.Errorf("unexpected %s", op)
	}
	f.mu.Lock()
	f.calls++
	if f.busyFirst > 0 {
		f.busyFirst--
		f.mu.Unlock()
		return &api.Error{Code: "ROOT_BUSY"}
	}
	if deadline, ok := ctx.Deadline(); ok {
		f.budgets = append(f.budgets, time.Until(deadline))
	}
	f.active++
	f.maxActive = max(f.maxActive, f.active)
	f.mu.Unlock()
	defer func() { f.mu.Lock(); f.active--; f.mu.Unlock() }()
	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
		return &api.Error{Code: "EXECUTOR_TIMEOUT"}
	}
	return json.Unmarshal([]byte(`{"success":true,"data":{"ok":true}}`), out)
}

func readAuthority(t *testing.T, executor delegate.ExecutorClient, timeout time.Duration) *Authority {
	t.Helper()
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	a := &Authority{Store: store, Client: executor, ReadTimeout: timeout}
	g := delegate.Grant{DelegationID: fmt.Sprintf("%064x", 1), Scope: "mail-read", Lifetime: "until-revoked",
		Subject: delegate.Subject{Username: "alice", UID: json.Number("1024")}}
	if err := a.Bind(context.Background(), "alice", g); err != nil {
		t.Fatal(err)
	}
	return a
}

func readPackages(ctx context.Context, a *Authority) error {
	var out map[string]any
	return a.DSM("").Call(ctx, "SYNO.Core.Package", "list", 2, map[string]any{}, &out)
}

// socketExecutor is a real executor socket: it reads one request line from
// the SDK's delegate.Client and records the deadline_ms it was sent.
func socketExecutor(t *testing.T) (*delegate.Client, chan int64) {
	t.Helper()
	dir, err := os.MkdirTemp("", "exe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "executor.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	deadlines := make(chan int64, 16)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(conn).ReadBytes('\n')
			var req struct {
				DeadlineMS int64 `json:"deadline_ms"`
			}
			_ = json.Unmarshal(line, &req)
			deadlines <- req.DeadlineMS
			conn.Write([]byte(`{"ok":true,"result":{"success":true,"data":{"ok":true}}}` + "\n"))
			conn.Close()
		}
	}()
	return &delegate.Client{Socket: path, Timeout: delegate.ExecutorTimeout}, deadlines
}

func TestDelegatedReadGivesTheExecutorAtLeastTwoMinutes(t *testing.T) {
	// The real SDK client keeps its reply reserve twice (its own timeout,
	// then deadline_ms): measure what the executor is actually told.
	client, deadlines := socketExecutor(t)
	if err := readPackages(context.Background(), readAuthority(t, client, 0)); err != nil {
		t.Fatal(err)
	}
	got := <-deadlines
	t.Logf("executor deadline_ms = %d", got)
	if got < 125000 {
		t.Fatalf("executor deadline_ms = %d, want at least 125000", got)
	}
	// The executor's DSM command layer keeps one more reply reserve
	// (min(5 s, 25 %), SDK docs/request-deadlines.md); the socket cannot see
	// inside the executor, so apply that rule to the measured value.
	if dsm := got - min(5000, got/4); dsm < 120000 {
		t.Fatalf("DSM work gets %d ms, want at least 120000", dsm)
	}
}

func TestCallNeverStartsShortOrWaitsUnbounded(t *testing.T) {
	// Not enough of the caller's deadline left for a full budget: not sent.
	executor := &slowExecutor{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := readPackages(ctx, readAuthority(t, executor, 5*time.Second))
	if !errors.Is(err, ErrDSMSlotTimeout) || executor.calls != 0 {
		t.Fatalf("short start: %v after %d calls", err, executor.calls)
	}
	// Two calls hold both slots; a third waits at most SlotWait, then fails
	// without being sent. The two keep their full budget.
	slow := &slowExecutor{delay: 400 * time.Millisecond}
	a := readAuthority(t, slow, time.Second)
	a.SlotWait = 100 * time.Millisecond
	errs := make(chan error, 3)
	for range 3 {
		go func() { errs <- readPackages(context.Background(), a) }()
	}
	timedOut := 0
	for range 3 {
		if err := <-errs; errors.Is(err, ErrDSMSlotTimeout) {
			timedOut++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if timedOut != 1 || slow.calls != 2 || Cause(ErrDSMSlotTimeout) != CauseTimeout {
		t.Fatalf("slot wait: %d timed out, %d sent", timedOut, slow.calls)
	}
}

func TestBackgroundStopAndAbandonCancelWork(t *testing.T) {
	base, stop := context.WithCancel(context.Background())
	bg := &Background{Base: base, Abandon: 150 * time.Millisecond}
	ran := make(chan error, 2)
	slowRead := func(c context.Context) {
		select {
		case <-time.After(time.Minute):
			ran <- nil
		case <-c.Done():
			ran <- c.Err()
		}
	}
	// Nobody polls: canceled after Abandon.
	j, err := bg.Go(time.Hour, slowRead)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-ran; err == nil || !j.Interrupted() {
		t.Fatal("unpolled work was not canceled")
	}
	// Polled work lives until the worker stops; Wait then returns at once.
	if j, err = bg.Go(time.Hour, slowRead); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		time.Sleep(60 * time.Millisecond)
		j.Touch()
	}
	if j.Interrupted() {
		t.Fatal("polled work was canceled")
	}
	stop()
	done := make(chan struct{})
	go func() { bg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not end the work")
	}
	if err := <-ran; err == nil || !j.Interrupted() {
		t.Fatal("stop did not cancel the read")
	}
}

func TestSlowReadSucceedsAndTimeoutKeepsItsCause(t *testing.T) {
	// Scaled: a 10 s answer within a 125 s budget, as 40 ms within 500 ms.
	slow := &slowExecutor{delay: 40 * time.Millisecond}
	if err := readPackages(context.Background(), readAuthority(t, slow, 500*time.Millisecond)); err != nil {
		t.Fatal("slow read failed", err)
	}
	stuck := &slowExecutor{delay: time.Second}
	err := readPackages(context.Background(), readAuthority(t, stuck, 50*time.Millisecond))
	if !errors.Is(err, ErrDSMTimeout) || !errors.Is(err, context.DeadlineExceeded) || Cause(err) != CauseTimeout {
		t.Fatalf("timeout = %v (cause %q), want %s", err, Cause(err), CauseTimeout)
	}
}

func TestReadsShareTwoExecutorSlotsAndBudgetStartsWithTheSlot(t *testing.T) {
	// Six reads of 120 ms each, each with 200 ms: two run at a time, so the
	// last starts after ~240 ms of waiting and must still get its full budget.
	executor := &slowExecutor{delay: 120 * time.Millisecond}
	a := readAuthority(t, executor, 200*time.Millisecond)
	errs := make(chan error, 6)
	for range 6 {
		go func() { errs <- readPackages(context.Background(), a) }()
	}
	for range 6 {
		if err := <-errs; err != nil {
			t.Fatal("queued read lost its budget", err)
		}
	}
	if executor.maxActive > DSMSlots {
		t.Fatalf("%d concurrent calls, executor admits %d", executor.maxActive, DSMSlots)
	}
}

func TestReadRetriesRootBusy(t *testing.T) {
	executor := &slowExecutor{busyFirst: 2}
	if err := readPackages(context.Background(), readAuthority(t, executor, 5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if executor.calls != 3 {
		t.Fatalf("calls = %d, want 2 refusals then success", executor.calls)
	}
}

func TestCauseIsFixed(t *testing.T) {
	for err, want := range map[error]string{
		AuthorityRequired{Profile: "mail-read"}:   CauseAuthority,
		DSMError{Code: 105}:                       "dsm_105",
		ErrDSMReplyTooLarge:                       CauseTooLarge,
		ErrDSMTimeout:                             CauseTimeout,
		context.DeadlineExceeded:                  CauseTimeout,
		&api.Error{Code: "EXECUTOR_TIMEOUT"}:      CauseTimeout,
		&api.Error{Code: "EXECUTOR_UNAVAILABLE"}:  CauseUnavailable,
		errors.New("secret upstream text leaked"): CauseUnavailable,
	} {
		if got := Cause(err); got != want {
			t.Errorf("Cause(%v) = %q, want %q", err, got, want)
		}
	}
}

func writeAuthority(t *testing.T, executor delegate.ExecutorClient, timeout time.Duration) *Authority {
	t.Helper()
	a := readAuthority(t, executor, timeout)
	g := delegate.Grant{DelegationID: fmt.Sprintf("%064x", 2), Scope: "mail-write", Lifetime: "until-revoked",
		Subject: delegate.Subject{Username: "alice", UID: json.Number("1024")}}
	if err := a.Bind(context.Background(), "alice", g); err != nil {
		t.Fatal(err)
	}
	return a
}

func writeSMTP(a *Authority) error {
	var out map[string]any
	return a.DSM("alice").Call(context.Background(), "SYNO.MailPlusServer.Service.SMTP", "set", 1, map[string]any{"enable_smtp": true}, &out)
}

func TestTimedOutWriteIsUncertainAndNeverResent(t *testing.T) {
	executor := &slowExecutor{delay: time.Second}
	err := writeSMTP(writeAuthority(t, executor, 50*time.Millisecond))
	if !errors.Is(err, ErrDSMWriteUncertain) || errors.Is(err, context.DeadlineExceeded) || executor.calls != 1 {
		t.Fatalf("write timeout = %v after %d calls, want uncertain after one", err, executor.calls)
	}
	// A write gets the same two minutes as a read once it holds a slot.
	fast := &slowExecutor{}
	if err := writeSMTP(writeAuthority(t, fast, 0)); err != nil || fast.budgets[0] < DSMWriteTimeout-time.Second {
		t.Fatalf("write budget %v, %v", fast.budgets, err)
	}
}

func TestWriteRefusedBeforeDispatchIsRetried(t *testing.T) {
	executor := &slowExecutor{busyFirst: 1}
	if err := writeSMTP(writeAuthority(t, executor, 5*time.Second)); err != nil || executor.calls != 2 {
		t.Fatalf("ROOT_BUSY write: %v after %d calls", err, executor.calls)
	}
}

// codeExecutor answers every webapi.call with one refusal code.
type codeExecutor struct {
	code  string
	calls int
}

func (f *codeExecutor) Call(context.Context, string, map[string]string, any, any) error {
	f.calls++
	return &api.Error{Code: f.code}
}

func TestWriteFailuresAreUncertainUnlessRefusedBeforeAdmission(t *testing.T) {
	for _, code := range []string{"EXECUTOR_UNAVAILABLE", "EXECUTOR_PROTOCOL", "EXECUTOR_TIMEOUT", "WEBAPI_UNCERTAIN", "canceled", "SOMETHING_NEW",
		"EXECUTOR_PAUSED", "ROOT_STAGING_FULL", "disabled", "APP_STOPPED", "APP_STARTING", "STORAGE_ERROR", "DSM_FAILED"} {
		if err := writeSMTP(writeAuthority(t, &codeExecutor{code: code}, time.Second)); !errors.Is(err, ErrDSMWriteUncertain) {
			t.Errorf("%s after sending: %v, want uncertain", code, err)
		}
	}
	for _, code := range []string{"DELEGATION_DENIED", "APP_DENIED", "INELIGIBLE", "POLICY_DENIED", "AUTH_DENIED", "INVALID_REQUEST", "EXECUTOR_STARTING", "IDENTITY_CHANGED"} {
		ex := &codeExecutor{code: code}
		err := writeSMTP(writeAuthority(t, ex, time.Second))
		if errors.Is(err, ErrDSMWriteUncertain) || err == nil || ex.calls != 1 {
			t.Errorf("%s before admission: %v after %d calls", code, err, ex.calls)
		}
	}
	// A caller that gave up while waiting for a slot sent nothing.
	slow := &slowExecutor{delay: time.Second}
	a := writeAuthority(t, slow, 5*time.Second)
	for range DSMSlots {
		go func() { _ = readPackages(context.Background(), a) }()
	}
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	var out map[string]any
	err := a.DSM("alice").Call(ctx, "SYNO.MailPlusServer.Service.SMTP", "set", 1, map[string]any{}, &out)
	if errors.Is(err, ErrDSMWriteUncertain) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unsent write: %v", err)
	}
}

func TestBackgroundCloseRefusesLateWorkWithoutARace(t *testing.T) {
	if AbandonAfter < 3*time.Minute {
		t.Fatal("a hidden tab polls about once a minute: allow a few")
	}
	bg := &Background{}
	started := make(chan struct{})
	go func() {
		defer close(started)
		for range 200 {
			if _, err := bg.Go(time.Second, func(context.Context) {}); err != nil {
				if !errors.Is(err, ErrUnavailable) {
					t.Error(err)
				}
				return
			}
		}
	}()
	bg.Close()
	<-started
	if _, err := bg.Go(time.Second, func(context.Context) {}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Go after Close: %v", err)
	}
	base, stop := context.WithCancel(context.Background())
	stop()
	if _, err := (&Background{Base: base}).Go(time.Second, func(context.Context) {}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Go after the worker stopped: %v", err)
	}
}

// The not-sent list is exactly protocol v1's preAdmission: true set. The set
// is copied in testdata/preadmission.json (source and sha256 of SDK v0.53.19's
// spec/protocol/v1/errors.json), so this always runs; when that module is in
// the local cache, the copy is also checked against the spec file itself.
func TestBeforeAdmissionMatchesTheProtocolSpec(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "preadmission.json"))
	if err != nil {
		t.Fatal(err)
	}
	var copied struct {
		SHA256       string   `json:"sha256"`
		PreAdmission []string `json:"preAdmission"`
	}
	if err := json.Unmarshal(raw, &copied); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, c := range copied.PreAdmission {
		want[c] = true
	}
	if len(want) == 0 || !reflect.DeepEqual(want, beforeAdmission) {
		t.Fatalf("not-sent list differs from the spec:\nspec %v\nours %v", want, beforeAdmission)
	}
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		return
	}
	spec, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(out)), "github.com", "synopackageland", "syno-pkg-land-sdk@v0.53.24", "spec", "protocol", "v1", "errors.json"))
	if err != nil {
		return // the copy above is the check
	}
	if sum := sha256.Sum256(spec); hex.EncodeToString(sum[:]) != copied.SHA256 {
		t.Fatal("testdata/preadmission.json no longer matches the v0.53.19 spec file")
	}
}

// scriptedSocket is a real executor socket: the first busy replies are
// ROOT_BUSY, then every request succeeds after delay. It counts requests and
// the most served at once.
func scriptedSocket(t *testing.T, busy int, delay time.Duration) (*delegate.Client, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	dir, err := os.MkdirTemp("", "exe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	l, err := net.Listen("unix", filepath.Join(dir, "executor.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var requests, active, peak atomic.Int32
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = bufio.NewReader(conn).ReadBytes('\n')
				if n := requests.Add(1); int(n) <= busy {
					conn.Write([]byte(`{"ok":false,"code":"ROOT_BUSY","message":"busy"}` + "\n"))
					return
				}
				now := active.Add(1)
				for p := peak.Load(); now > p && !peak.CompareAndSwap(p, now); p = peak.Load() {
				}
				time.Sleep(delay)
				active.Add(-1)
				conn.Write([]byte(`{"ok":true,"result":{"success":true,"data":{"ok":true}}}` + "\n"))
			}()
		}
	}()
	return &delegate.Client{Socket: filepath.Join(dir, "executor.sock"), Timeout: delegate.ExecutorTimeout}, &requests, &peak
}

// SDK 0.53.20 retries ROOT_BUSY in its client; the app must not add a second
// layer, and its own 2-slot semaphore must not deadlock with the SDK's queue.
// Both layers allow two calls, so each is also run alone as the limit: an app
// semaphore of 1 must cap the executor at 1 (the app layer limits), and one of
// 3 must still cap it at 2 (the SDK queue limits).
func TestSDKAdmissionAndAppSemaphoreStackCleanly(t *testing.T) {
	client, requests, _ := scriptedSocket(t, 2, 0)
	if err := readPackages(context.Background(), readAuthority(t, client, 0)); err != nil {
		t.Fatal(err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("requests = %d, want 2 ROOT_BUSY then 1 success (one retry layer)", got)
	}
	for _, tc := range []struct {
		name      string
		slots     int
		atMost    int32
		mustReach bool
	}{
		{"stacked", 0, DSMSlots, false},
		{"app-limits", 1, 1, true},
		{"sdk-limits", DSMSlots + 1, DSMSlots, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _, peak := scriptedSocket(t, 0, 150*time.Millisecond)
			a := readAuthority(t, client, 5*time.Second)
			a.Slots = tc.slots
			errs := make(chan error, 6)
			for range 6 {
				go func() { errs <- readPackages(context.Background(), a) }()
			}
			for range 6 {
				if err := <-errs; err != nil {
					t.Fatal("stacked admission failed", err)
				}
			}
			if got := peak.Load(); got > tc.atMost || (tc.mustReach && got != tc.atMost) {
				t.Fatalf("executor served %d at once, want %d", got, tc.atMost)
			}
		})
	}
}

// A write that never reached the executor (no socket to dial) is not sent,
// per delegate.NotSent, so it is not reported as an uncertain outcome.
func TestWriteThatCouldNotDialIsNotUncertain(t *testing.T) {
	dir, _ := os.MkdirTemp("", "exe")
	defer os.RemoveAll(dir)
	client := &delegate.Client{Socket: filepath.Join(dir, "missing.sock"), Timeout: delegate.ExecutorTimeout}
	err := writeSMTP(writeAuthority(t, client, 2*time.Second))
	if err == nil || errors.Is(err, ErrDSMWriteUncertain) {
		t.Fatalf("undialable write: %v", err)
	}
}
