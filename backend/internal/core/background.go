package core

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// AbandonAfter cancels background work nobody polled for this long. Browsers
// throttle timers in hidden tabs (about once a minute), so it allows a few
// throttled polls.
const AbandonAfter = 3 * time.Minute

// ErrInterrupted is work that was cut short (abandoned or the worker
// stopping): its result is incomplete. The job restarts on the next poll.
var ErrInterrupted = errors.New("interrupted")

// Background runs read-only work (detection, plan preparation, a diagnosis)
// that outlives the HTTP request that started it, but not the worker: Base
// is the worker's context, so stopping the package cancels it, and the worker
// waits (Wait) before it flushes and closes its store. Work nobody polls is
// canceled after Abandon (default AbandonAfter).
type Background struct {
	Base    context.Context
	Abandon time.Duration
	mu      sync.Mutex
	closed  bool
	wg      sync.WaitGroup
}

// Job is one piece of background work. Touch it on every poll.
type Job struct {
	base        context.Context
	ctx         context.Context
	cancel      context.CancelFunc
	touched     atomic.Int64
	interrupted atomic.Bool
}

// Interrupted reports work that was cut short (abandoned, replaced, or the
// worker stopping): its result is incomplete and must not be used.
func (j *Job) Interrupted() bool {
	return j != nil && (j.interrupted.Load() || j.base.Err() != nil)
}

// Touch records a poll: the work is still wanted.
func (j *Job) Touch() {
	if j != nil {
		j.touched.Store(time.Now().UnixNano())
	}
}

// Context is the job's context (canceled on stop, abandonment or budget).
func (j *Job) Context() context.Context { return j.ctx }

// Cancel stops the job (for example when a newer request replaces it).
func (j *Job) Cancel() { j.interrupted.Store(true); j.cancel() }

// Go starts work bounded by budget. Once the worker is stopping (Base done
// or Close called) it refuses with ErrUnavailable and starts nothing. A nil
// Background runs untracked under context.Background (tests that do not
// exercise the lifecycle).
func (b *Background) Go(budget time.Duration, work func(context.Context)) (*Job, error) {
	base := context.Background()
	abandon := AbandonAfter
	if b != nil {
		if b.Base != nil {
			base = b.Base
		}
		if b.Abandon > 0 {
			abandon = b.Abandon
		}
		// Add under the lock that Close takes, so Close never waits on a
		// counter that a late Go increments.
		b.mu.Lock()
		if b.closed || base.Err() != nil {
			b.mu.Unlock()
			return nil, ErrUnavailable
		}
		b.wg.Add(1)
		b.mu.Unlock()
	}
	ctx, cancel := context.WithTimeout(base, budget)
	j := &Job{base: base, ctx: ctx, cancel: cancel}
	j.Touch()
	go func() {
		// The watchdog cancels work whose poller went away.
		tick := time.NewTicker(max(abandon/3, time.Millisecond))
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if time.Since(time.Unix(0, j.touched.Load())) > abandon {
					j.interrupted.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	go func() {
		if b != nil {
			defer b.wg.Done()
		}
		defer cancel()
		work(ctx)
	}()
	return j, nil
}

// Wait blocks until the work started so far has returned (tests).
func (b *Background) Wait() {
	if b != nil {
		b.wg.Wait()
	}
}

// Close refuses new work, then waits for the work already started. The
// worker calls it on stop, before it flushes and closes the store.
func (b *Background) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.wg.Wait()
}
