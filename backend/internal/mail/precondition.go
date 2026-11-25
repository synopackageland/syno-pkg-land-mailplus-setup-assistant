package mail

import (
	"context"
	"sync"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

// MailPlusStatusWait is how long one mail.mailplus.status call waits for the
// package read before it answers "checking" (poll again); well under DSM's
// and nginx's HTTP timeouts, as the other background reads.
const MailPlusStatusWait = 8 * time.Second

// MailPlusStatusBudget is two delegated calls' worst wall (slot wait + call
// each): the package list, then MailPlus Server's first-run check.
const MailPlusStatusBudget = 2 * core.DSMCallWall

// MailPlusChecking is the answer while the package read still runs.
const MailPlusChecking detect.MailPlusState = "checking"

// mailPlusStatusReader is the production detector's precondition read.
type mailPlusStatusReader interface {
	MailPlusStatus(context.Context, core.Env) (detect.MailPlusStatus, error)
}

// Precondition answers mail.mailplus.status: is MailPlus Server installed and
// running? The Overview and both wizards ask it first, before anything that
// needs MailPlus Server. It reads only when asked (one SYNO.Core.Package list
// read in the background per administrator, joined by repeated calls) and
// keeps nothing once answered: nothing runs while nobody uses the App.
type Precondition struct {
	Reader     detect.Source
	Background *core.Background
	// Wait overrides MailPlusStatusWait (tests only).
	Wait time.Duration
	mu   sync.Mutex
	jobs map[string]*statusJob
}

type statusJob struct {
	bg     *core.Job
	done   chan struct{}
	status detect.MailPlusStatus
	err    error
}

// Status reads the precondition for owner, or follows the read that runs.
func (p *Precondition) Status(ctx context.Context, env core.Env, owner string) (detect.MailPlusStatus, error) {
	reader, ok := p.Reader.(mailPlusStatusReader)
	if !ok || env.DSM == nil {
		return detect.StatusOf(detect.Observation[detect.Package]{Status: detect.Unknown, Detail: core.CauseUnavailable}), nil
	}
	p.mu.Lock()
	if p.jobs == nil {
		p.jobs = map[string]*statusJob{}
	}
	j := p.jobs[owner]
	if j != nil && finishedInterrupted(j) {
		j = nil // cut short: read again
	}
	if j == nil {
		j = &statusJob{done: make(chan struct{})}
		bg, err := p.Background.Go(MailPlusStatusBudget, func(c context.Context) {
			defer close(j.done)
			j.status, j.err = reader.MailPlusStatus(c, env)
		})
		if err != nil {
			p.mu.Unlock()
			return detect.MailPlusStatus{}, err // the worker is stopping
		}
		j.bg = bg
		p.jobs[owner] = j
	}
	p.mu.Unlock()
	j.bg.Touch()
	wait := MailPlusStatusWait
	if p.Wait > 0 {
		wait = p.Wait
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-j.done:
	case <-timer.C:
		return detect.MailPlusStatus{State: MailPlusChecking}, nil
	case <-ctx.Done():
		return detect.MailPlusStatus{}, ctx.Err()
	}
	p.mu.Lock()
	if p.jobs[owner] == j {
		delete(p.jobs, owner)
	}
	p.mu.Unlock()
	if j.bg.Interrupted() {
		return detect.StatusOf(detect.Observation[detect.Package]{Status: detect.Unknown, Detail: core.CauseUnavailable}), nil
	}
	return j.status, j.err
}

func finishedInterrupted(j *statusJob) bool {
	select {
	case <-j.done:
		return j.bg.Interrupted()
	default:
		return false
	}
}
