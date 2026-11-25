package core

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// Host runs the enabled long-running services (the mail relay) and keeps the
// shared environment. It is event-driven: it reads the enabled flags after a
// write to core.services, when a service exits and when a restart back-off
// timer fires. While nothing changes it does no I/O (hibernation-safe).
type Host struct {
	Store     *Store
	Env       Env
	Authority *Authority
	services  map[string]*hostedService
	order     []string
	mu        sync.Mutex
	wake      chan struct{}
}

type hostedService struct {
	service Service
	active  bool
	cancel  context.CancelFunc
	next    time.Time
	backoff time.Duration
	lastErr string
}

// ServiceView is one service's public state.
type ServiceView struct {
	ID      string        `json:"id"`
	Enabled bool          `json:"enabled"`
	Status  ServiceStatus `json:"status"`
}

// NewHost fills the environment defaults from the store.
func NewHost(store *Store, env Env, services ...Service) (*Host, error) {
	if env.DataDir == "" {
		env.DataDir = store.DataDir
	}
	if env.DSM == nil {
		env.DSM = WebAPIDSM{}
	}
	if env.KV == nil {
		env.KV = store
	}
	if env.Secrets == nil {
		env.Secrets = SecretStore{Store: store}
	}
	if env.Now == nil {
		env.Now = time.Now
	}
	if env.Log == nil {
		env.Log = slog.Default()
	}
	h := &Host{Store: store, Env: env, services: map[string]*hostedService{}, wake: make(chan struct{}, 1)}
	for _, s := range services {
		if s.ID() == "" || h.services[s.ID()] != nil {
			return nil, ErrInvalid
		}
		h.services[s.ID()] = &hostedService{service: s, backoff: time.Second}
		h.order = append(h.order, s.ID())
	}
	return h, nil
}

// CallerEnv is the environment of one interactive request: DSM calls use the
// caller's own grants (writes need them), and the browser address is attached.
func (h *Host) CallerEnv(ctx context.Context, owner string) Env {
	env := h.Env
	env.Client = ClientFrom(ctx)
	if h.Authority != nil {
		env.DSM = h.Authority.DSM(owner)
	}
	return env
}

func (h *Host) SetService(ctx context.Context, id string, enabled bool) error {
	if h.services[id] == nil {
		return ErrNotFound
	}
	if err := h.Store.Put(ctx, "core.services", id, enabled); err != nil {
		return err
	}
	h.wakeServices()
	// A disable immediately requests stop; the host never overlaps instances.
	if !enabled {
		h.mu.Lock()
		if s := h.services[id]; s.cancel != nil {
			s.cancel()
		}
		h.mu.Unlock()
	}
	return nil
}

// Services may opt into fixed public error codes; arbitrary provider text is
// always replaced at the host boundary.
func serviceErrorCode(service Service, code string) string {
	if sanitizer, ok := service.(interface{ PublicErrorCode(string) string }); ok {
		return sanitizer.PublicErrorCode(code)
	}
	return "service_failed"
}

func (h *Host) Services(ctx context.Context) ([]ServiceView, error) {
	out := []ServiceView{}
	for _, id := range h.order {
		s := h.services[id]
		var enabled bool
		if _, err := h.Store.Get(ctx, "core.services", id, &enabled); err != nil {
			return nil, err
		}
		status := s.service.Status()
		if status.LastErr != "" {
			status.LastErr = serviceErrorCode(s.service, status.LastErr)
		}
		h.mu.Lock()
		if s.lastErr != "" && !status.Running {
			status.LastErr = s.lastErr
		}
		h.mu.Unlock()
		out = append(out, ServiceView{ID: id, Enabled: enabled, Status: status})
	}
	return out, nil
}

func (h *Host) wakeServices() {
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

// HostServices runs until ctx ends and then stops every service.
func (h *Host) HostServices(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		var wait time.Duration = -1
		for _, id := range h.order {
			s := h.services[id]
			var enabled bool
			_, err := h.Store.Get(ctx, "core.services", id, &enabled)
			h.mu.Lock()
			now := h.Env.Now()
			if err != nil || !enabled || ctx.Err() != nil {
				if s.cancel != nil {
					s.cancel()
				}
			} else if !s.active && now.Before(s.next) {
				if d := s.next.Sub(now); wait < 0 || d < wait {
					wait = d
				}
			} else if !s.active {
				run, cancel := context.WithCancel(ctx)
				s.active, s.cancel, s.lastErr = true, cancel, ""
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer h.wakeServices()
					started := h.Env.Now()
					var failure error
					func() {
						defer func() {
							if recover() != nil {
								failure = errors.New("service_failed")
							}
						}()
						failure = s.service.Start(run, h.Env)
					}()
					h.mu.Lock()
					defer h.mu.Unlock()
					s.active, s.cancel = false, nil
					if run.Err() == nil {
						if failure != nil {
							s.lastErr = serviceErrorCode(s.service, failure.Error())
						} else {
							s.lastErr = "service_stopped"
						}
						if h.Env.Now().Sub(started) >= time.Minute {
							s.backoff = time.Second
						}
						s.next = h.Env.Now().Add(s.backoff)
						s.backoff = min(s.backoff*2, 5*time.Minute)
					}
					cancel()
				}()
			}
			h.mu.Unlock()
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		var fire <-chan time.Time
		if wait >= 0 {
			timer.Reset(wait)
			fire = timer.C
		}
		select {
		case <-ctx.Done():
			h.mu.Lock()
			for _, s := range h.services {
				if s.cancel != nil {
					s.cancel()
				}
			}
			h.mu.Unlock()
			return
		case <-h.wake:
		case <-h.Store.ServiceSignal():
		case <-fire:
		}
	}
}

// RunCheck runs one read-only check with a bounded budget and keeps a typed
// refusal (missing grant) even when the check swallowed the transport error.
// Errors are reduced to fixed public values; module text never leaves.
func RunCheck(ctx context.Context, env Env, c Check, budget time.Duration) ([]Finding, error) {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	observer := &checkDSM{DSM: env.DSM}
	if env.DSM != nil {
		env.DSM = observer
	}
	type result struct {
		findings []Finding
		err      error
	}
	done := make(chan result, 1)
	go func() {
		got := result{}
		defer func() {
			if recover() != nil {
				got = result{err: errors.New("check_failed")}
			}
			done <- got
		}()
		got.findings, got.err = c.Run(ctx, env)
	}()
	var got result
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case got = <-done:
	}
	if refusal := observer.refusal(); refusal != nil && got.err == nil {
		got.err = refusal
	}
	if got.err == nil {
		return got.findings, nil
	}
	var authority AuthorityRequired
	if errors.As(got.err, &authority) {
		return got.findings, AuthorityRequired{Profile: authority.Profile}
	}
	for _, safe := range []error{ErrNoAdmin, ErrUnavailable, ErrInvalid, ErrConflict, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(got.err, safe) {
			return got.findings, safe
		}
	}
	return nil, errors.New("check_failed")
}

type checkDSM struct {
	DSM
	mu  sync.Mutex
	err error
}

func (d *checkDSM) Call(ctx context.Context, api, method string, version int, params map[string]any, out any) error {
	err := d.DSM.Call(ctx, api, method, version, params, out)
	if errors.Is(err, ErrAuthorityRequired) || errors.Is(err, ErrNoAdmin) {
		d.mu.Lock()
		if d.err == nil {
			d.err = err
		}
		d.mu.Unlock()
	}
	return err
}

func (d *checkDSM) refusal() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}
