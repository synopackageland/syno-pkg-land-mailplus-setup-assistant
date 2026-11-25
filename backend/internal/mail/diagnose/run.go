package diagnose

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

type Symptom string

const (
	CannotSend    Symptom = "cannot-send"
	BounceOrSpam  Symptom = "bounce-or-spam"
	CannotReceive Symptom = "cannot-receive"
	PhoneConnect  Symptom = "phone-connect"
	NotSure       Symptom = "not-sure"
)

// SymptomPlan is a data table, ready for additional CSS-ticket scenarios.
// Causes are rule-based priorities, not statistical probabilities.
type SymptomPlan struct {
	Symptom Symptom
	Checks  []CheckID
	Causes  []string
}

var symptomPlans = []SymptomPlan{
	{CannotSend, []CheckID{Transport, MailPlus, Access, Relay, Network, DomainDNS},
		[]string{"missing", "stopped", "source_blocked", "account_inactive", "home_access", "license_owner", "license_count", "relay_failure", "smtp", "relay_stopped", "deferred_auth", "deferred_dns", "deferred_tls", "deferred_policy", "deferred_remote", "relay_stale", "queue_stale", "spf", "dkim", "ptr", "dnsbl"}},
	{BounceOrSpam, []CheckID{Transport, DomainDNS, Network, MailPlus, Relay},
		[]string{"deferred_policy", "spf", "dkim", "dmarc", "dnsbl", "ptr", "missing", "stopped", "relay_stopped", "queue_stale"}},
	{CannotReceive, []CheckID{Transport, MailPlus, Access, DomainDNS, Inbound, Certificate},
		[]string{"missing", "stopped", "source_blocked", "account_inactive", "home_access", "smtp", "mx", "inbound", "cert_expired", "cert_soon"}},
	{PhoneConnect, []CheckID{Transport, MailPlus, Access, Certificate, Client},
		[]string{"source_blocked", "account_inactive", "home_access", "protocol_split", "missing", "stopped", "cert_expired", "imap", "client", "cert_soon"}},
	{NotSure, []CheckID{Transport, MailPlus, Access, Relay, Network, DomainDNS, Inbound, Certificate, Client},
		[]string{"missing", "stopped", "source_blocked", "account_inactive", "home_access", "license_owner", "license_count", "relay_failure", "smtp", "relay_stopped", "cert_expired", "deferred_auth", "deferred_dns", "deferred_tls", "deferred_policy", "deferred_remote", "queue_stale", "relay_stale"}},
}

func Plans() []SymptomPlan {
	out := make([]SymptomPlan, 0, len(symptomPlans))
	for _, plan := range symptomPlans {
		copy, _ := PlanFor(plan.Symptom)
		out = append(out, copy)
	}
	return out
}

func PlanFor(symptom Symptom) (SymptomPlan, bool) {
	for _, plan := range symptomPlans {
		if plan.Symptom == symptom {
			plan.Checks = append([]CheckID(nil), plan.Checks...)
			plan.Causes = append([]string(nil), plan.Causes...)
			return plan, true
		}
	}
	return SymptomPlan{}, false
}

// Run is one diagnosis in progress: a symptom, its fixed check order and the
// findings gathered so far. It lives in the worker's memory only. The browser
// owns the step flow (the UI SDK Wizard) and polls next; the snapshot and each
// check run in the background, so no HTTP request waits for a slow NAS.
// Pending is true while the run works; Phase says on what ("reading" MailPlus
// Server, or "checking" the next check).
type Run struct {
	ID       string         `json:"id"`
	Symptom  Symptom        `json:"symptom"`
	Done     int            `json:"done"`
	Total    int            `json:"total"`
	Checks   []CheckID      `json:"checks"`
	Findings []core.Finding `json:"findings"`
	Complete bool           `json:"complete"`
	// Summary is what the result step shows (Summarize); set when Complete.
	Summary  *Summary `json:"summary,omitempty"`
	Pending  bool     `json:"pending,omitempty"`
	Phase    string   `json:"phase,omitempty"`
	owner    string
	started  time.Time
	snapshot *job
	check    *job
}

// job is one background step; done closes when its fields are final.
type job struct {
	bg       *core.Job
	done     chan struct{}
	state    State
	err      error // snapshot: Unreadable (checks unavailable); else a refusal
	findings []core.Finding
	index    int
}

// Runner keeps a bounded set of runs (16, retained while their background
// work can still be running).
type Runner struct {
	D *Diagnostics
	// Background runs snapshots and checks under the worker's lifetime
	// (canceled on stop, or when nobody polls the run). nil: untracked.
	Background *core.Background
	Now        func() time.Time
	mu         sync.Mutex
	runs       map[string]*Run
}

const (
	maxRuns = 16
	// A run holds one snapshot and its checks; keep it well past both.
	runTTL = SnapshotBudget + CheckBudget + 10*time.Minute
	// NextWait is how long one next call waits for background work before
	// it answers with progress; well under DSM's and nginx's HTTP timeouts.
	NextWait = 12 * time.Second
)

var (
	ErrUnknownSymptom = errors.New("unknown mail diagnostic symptom")
	ErrUnknownRun     = errors.New("unknown mail diagnostic run")
	ErrRunBusy        = errors.New("mail diagnostic run busy")
)

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Start begins a run for one symptom. No check runs yet.
func (r *Runner) Start(owner string, symptom Symptom) (Run, error) {
	plan, ok := PlanFor(symptom)
	if !ok {
		return Run{}, ErrUnknownSymptom
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return Run{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.runs == nil {
		r.runs = map[string]*Run{}
	}
	now := r.now()
	var oldest string
	for k, run := range r.runs {
		if now.Sub(run.started) > runTTL {
			delete(r.runs, k)
		} else if oldest == "" || run.started.Before(r.runs[oldest].started) {
			oldest = k
		}
	}
	if len(r.runs) >= maxRuns {
		delete(r.runs, oldest)
	}
	run := &Run{ID: hex.EncodeToString(id), Symptom: symptom, Total: len(plan.Checks), Checks: plan.Checks,
		Findings: []core.Finding{}, owner: owner, started: now}
	r.runs[run.ID] = run
	return run.copy(), nil
}

func (run *Run) copy() Run {
	out := *run
	out.Checks = append([]CheckID(nil), run.Checks...)
	out.Findings = append([]core.Finding{}, run.Findings...)
	return out
}

// Next advances the run without blocking for long: it starts the run's one
// snapshot, then each check, in the background, and waits at most wait for
// the current step. It returns the run with Pending while work continues.
// When the last check is done the findings are ranked for the symptom. A
// completed run is returned unchanged, so a repeated call never reruns checks.
// A missing grant ends the step with AuthorityRequired; the next call after
// the grant reads again.
func (r *Runner) Next(ctx context.Context, env core.Env, owner, id string, wait time.Duration) (Run, error) {
	if wait <= 0 || wait > NextWait {
		wait = NextWait
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	r.mu.Lock()
	run := r.runs[id]
	if run == nil || run.owner != owner {
		r.mu.Unlock()
		return Run{}, ErrUnknownRun
	}
	if run.Complete {
		out := run.copy()
		r.mu.Unlock()
		return out, nil
	}
	if run.Done < 0 || run.Done >= len(run.Checks) {
		r.mu.Unlock()
		return Run{}, ErrUnknownRun
	}
	if run.snapshot != nil && abandoned(run.snapshot) {
		run.snapshot, run.check = nil, nil // stopped or abandoned: read again
	}
	if run.check != nil && abandoned(run.check) {
		run.check = nil
	}
	if run.snapshot == nil {
		snap, err := r.startSnapshot(ctx, env)
		if err != nil {
			r.mu.Unlock()
			return Run{}, err // the worker is stopping
		}
		run.snapshot = snap
	}
	snap := run.snapshot
	snap.bg.Touch()
	if run.check != nil {
		run.check.bg.Touch()
	}
	r.mu.Unlock()

	if !await(ctx, deadline.C, snap.done) {
		return r.pending(run, "reading", ctx)
	}
	if snap.bg.Interrupted() {
		// Cut short while this poll waited: never use it; read again.
		r.mu.Lock()
		if run.snapshot == snap {
			run.snapshot, run.check = nil, nil
		}
		r.mu.Unlock()
		return r.pending(run, "reading", ctx)
	}
	var authority core.AuthorityRequired
	if errors.As(snap.err, &authority) {
		r.mu.Lock()
		if run.snapshot == snap {
			run.snapshot = nil // read again once the grant exists
		}
		r.mu.Unlock()
		return Run{}, authority
	}

	r.mu.Lock()
	if run.Complete {
		out := run.copy()
		r.mu.Unlock()
		return out, nil
	}
	if cause, stop := Precondition(snap.state, snap.err); stop {
		// MailPlus Server is not installed, not running or could not be
		// read: that is the only cause; no check that needs it runs.
		run.check = nil
		run.Findings = []core.Finding{cause}
		run.Done = len(run.Checks)
		run.Complete = true
		summary := PreconditionSummary(cause)
		run.Summary = &summary
		out := run.copy()
		r.mu.Unlock()
		return out, nil
	}
	if run.check == nil {
		check, err := r.startCheck(ctx, env, snap, run.Done, run.Checks[run.Done])
		if err != nil {
			r.mu.Unlock()
			return Run{}, err
		}
		run.check = check
	}
	check := run.check
	r.mu.Unlock()

	if !await(ctx, deadline.C, check.done) {
		return r.pending(run, "checking", ctx)
	}
	if check.bg.Interrupted() {
		r.mu.Lock()
		if run.check == check {
			run.check = nil // cut short: run this check again
		}
		r.mu.Unlock()
		return r.pending(run, "checking", ctx)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.runs[id] != run {
		return Run{}, ErrRunBusy
	}
	if run.check == check {
		run.check = nil
		if check.err != nil {
			return Run{}, check.err
		}
		if run.Done == check.index {
			run.Findings = append(run.Findings, check.findings...)
			run.Done++
			if run.Done == len(run.Checks) {
				run.Findings = Rank(run.Symptom, run.Findings)
				summary := Summarize(run.Checks, run.Findings)
				run.Summary = &summary
				run.Complete = true
			}
		}
	}
	return run.copy(), nil
}

// abandoned is a finished job that was canceled (worker stop or no poller):
// its result is incomplete and must not be used.
func abandoned(j *job) bool {
	select {
	case <-j.done:
		return j.bg.Interrupted()
	default:
		return false
	}
}

// await waits for done, the call's wait, or the caller going away.
func await(ctx context.Context, wait <-chan time.Time, done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
	}
	select {
	case <-done:
		return true
	case <-wait:
	case <-ctx.Done():
	}
	return false
}

func (r *Runner) pending(run *Run, phase string, ctx context.Context) (Run, error) {
	if err := ctx.Err(); err != nil {
		return Run{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := run.copy()
	out.Pending, out.Phase = true, phase
	return out, nil
}

// startSnapshot reads the state once for the run, in the background. It is
// a read-only core check so a refused grant is reported, not swallowed.
func (r *Runner) startSnapshot(ctx context.Context, env core.Env) (*job, error) {
	j := &job{done: make(chan struct{})}
	bg, err := r.Background.Go(SnapshotBudget, func(c context.Context) {
		defer close(j.done)
		res := &snapshotResult{}
		_, err := core.RunCheck(c, env, snapshotCheck{r.D, res}, SnapshotBudget)
		res.mu.Lock()
		if res.set {
			j.state, j.err = res.state, res.err
		} else {
			j.err = Unreadable{Cause: core.CauseUnavailable}
		}
		res.mu.Unlock()
		var authority core.AuthorityRequired
		if errors.As(err, &authority) {
			j.err = authority
		} else if err != nil {
			j.err = Unreadable{Cause: core.Cause(err)}
		}
	})
	j.bg = bg
	return j, err
}

// startCheck evaluates one check against the run's snapshot, in the background.
func (r *Runner) startCheck(ctx context.Context, env core.Env, snap *job, index int, id CheckID) (*job, error) {
	j := &job{done: make(chan struct{}), index: index}
	bg, err := r.Background.Go(CheckBudget, func(c context.Context) {
		defer close(j.done)
		j.findings, j.err = core.RunCheck(c, env, oneCheck{r.D, id, snap}, CheckBudget)
	})
	j.bg = bg
	return j, err
}

// snapshotResult is written by the snapshot check, which may still be
// finishing after core.RunCheck gave up at its budget.
type snapshotResult struct {
	mu    sync.Mutex
	set   bool
	state State
	err   error
}

type snapshotCheck struct {
	d   *Diagnostics
	res *snapshotResult
}

func (c snapshotCheck) ID() string              { return "mail.snapshot" }
func (c snapshotCheck) Interval() time.Duration { return 0 }
func (c snapshotCheck) Run(ctx context.Context, env core.Env) ([]core.Finding, error) {
	state, err := c.d.Snapshot(ctx, env)
	c.res.mu.Lock()
	c.res.state, c.res.err, c.res.set = state, err, true
	c.res.mu.Unlock()
	return nil, nil
}

// oneCheck adapts one diagnostic group to core.Check for core.RunCheck. With
// a snapshot it judges that shared state; without one it reads its own.
type oneCheck struct {
	d    *Diagnostics
	id   CheckID
	snap *job
}

func (c oneCheck) ID() string              { return string(c.id) }
func (c oneCheck) Interval() time.Duration { return 0 }
func (c oneCheck) Run(ctx context.Context, env core.Env) ([]core.Finding, error) {
	if c.snap == nil {
		return c.d.Run(ctx, env, c.id)
	}
	return c.d.Evaluate(ctx, env, c.snap.state, c.snap.err, c.id)
}
