package detect

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"

	"SynoMailPlusSetupAssistant/internal/core"
)

// The MailPlus Server precondition. Every flow that needs MailPlus Server
// (setup, the zone step's domain read, the preview and apply, diagnosis)
// checks it first; nothing else that needs MailPlus Server is asked or read
// before it says running. It is decided from SYNO.Core.Package list v2 only:
// the exact MailPlus-Server entry, its additional.status and
// installed_info.is_broken / is_brick. A read that fails is unknown, never a
// guess.

// MailPlusState is the precondition's answer.
type MailPlusState string

const (
	MailPlusNotInstalled MailPlusState = "notInstalled"
	// MailPlusStopped: installed, but not running, or broken (DSM marks the
	// installation broken or bricked; it cannot run until repaired).
	MailPlusStopped MailPlusState = "stopped"
	MailPlusRunning MailPlusState = "running"
	// MailPlusUnknown: the package list could not be read (Cause says why).
	MailPlusUnknown MailPlusState = "unknown"
)

// Fixed causes of the precondition refusal (core.Cause of MailPlusUnavailable).
const (
	CauseMailPlusNotInstalled = "mailplus_not_installed"
	CauseMailPlusNotRunning   = "mailplus_not_running"
	// CauseMailPlusAPIMissing: DSM answered that a MailPlus Server API does
	// not exist (DSM error 102) although the package list said running: it
	// stopped, is being updated or was removed since.
	CauseMailPlusAPIMissing = "mailplus_api_missing"
)

// MailPlusStatus is the precondition as the App shows it.
type MailPlusStatus struct {
	State   MailPlusState `json:"state"`
	Version string        `json:"version,omitempty"`
	// Broken: DSM marks the installed package broken (State is stopped).
	Broken bool `json:"broken,omitempty"`
	// Cause (unknown only) is a fixed cause; CauseKey names it in the catalog.
	Cause       string            `json:"cause,omitempty"`
	CauseKey    string            `json:"causeKey,omitempty"`
	CauseParams map[string]string `json:"causeParams,omitempty"`
	// SetUp (running only) says whether MailPlus Server finished its own
	// first-run setup (SYNO.MailPlusServer.Util initial_check v2,
	// plusserver_initialized); nil when that read failed or was not made.
	// Before the first-run setup MailPlus Server has no mail domain, and its
	// own wizard asks for the domain name and host name the zone step shows.
	SetUp *bool `json:"setUp,omitempty"`
}

// StatusOf reduces the package observation to the precondition.
func StatusOf(p Observation[Package]) MailPlusStatus {
	switch {
	case !p.IsKnown():
		cause := p.Detail
		if cause == "" {
			cause = core.CauseUnavailable
		}
		key, params := CauseKey(cause)
		return MailPlusStatus{State: MailPlusUnknown, Cause: cause, CauseKey: key, CauseParams: params}
	case !p.Value.Installed:
		return MailPlusStatus{State: MailPlusNotInstalled}
	case p.Value.Broken:
		return MailPlusStatus{State: MailPlusStopped, Version: p.Value.Version, Broken: true}
	case !p.Value.Running:
		return MailPlusStatus{State: MailPlusStopped, Version: p.Value.Version}
	}
	return MailPlusStatus{State: MailPlusRunning, Version: p.Value.Version}
}

// Err is nil when MailPlus Server runs, else the typed refusal.
func (s MailPlusStatus) Err() error {
	if s.State == MailPlusRunning {
		return nil
	}
	return MailPlusUnavailable{State: s.State, Detail: s.Cause}
}

// MailPlusUnavailable refuses work that needs MailPlus Server before any
// SYNO.MailPlusServer call is sent. Its Error is a fixed public cause.
type MailPlusUnavailable struct {
	State MailPlusState
	// Detail (unknown only): why the package list could not be read.
	Detail string
}

func (e MailPlusUnavailable) Error() string { return e.PublicCause() }

// PublicCause makes core.Cause report the precondition, not "unavailable".
func (e MailPlusUnavailable) PublicCause() string {
	switch e.State {
	case MailPlusNotInstalled:
		return CauseMailPlusNotInstalled
	case MailPlusStopped:
		return CauseMailPlusNotRunning
	}
	if e.Detail != "" {
		return e.Detail
	}
	return core.CauseUnavailable
}

// Unwrap keeps errors.Is(err, core.ErrUnavailable) true for callers that
// only know "MailPlus Server could not be used".
func (e MailPlusUnavailable) Unwrap() error { return core.ErrUnavailable }

// mailPlusPackage is the MailPlus-Server entry of SYNO.Core.Package list v2.
type mailPlusPackage struct {
	ID         string `json:"id"`
	Version    string `json:"version"`
	Additional struct {
		Status    *string `json:"status"`
		Installed struct {
			Broken bool `json:"is_broken"`
			Brick  bool `json:"is_brick"`
		} `json:"installed_info"`
	} `json:"additional"`
}

// packageListParams is the one package read (mail-read).
var packageListParams = map[string]any{"additional": []string{"status", "installed_info"}, "ignore_hidden": false}

// packageOf finds the exact MailPlus-Server entry in a package list reply.
func packageOf(list *[]mailPlusPackage) Observation[Package] {
	if list == nil {
		return unknown[Package](core.CauseUnavailable)
	}
	for _, v := range *list {
		if v.ID != "MailPlus-Server" {
			continue
		}
		if v.Additional.Status == nil {
			return unknown[Package](core.CauseUnavailable)
		}
		return Fact(Package{Installed: true, Running: *v.Additional.Status == "running", Broken: v.Additional.Installed.Broken || v.Additional.Installed.Brick, Version: v.Version})
	}
	return Fact(Package{})
}

// ReadPackage reads the MailPlus-Server entry with one SYNO.Core.Package
// list v2 call (bounded by ctx).
func ReadPackage(ctx context.Context, dsm core.DSM) Observation[Package] {
	p := read[struct {
		Packages *[]mailPlusPackage `json:"packages"`
	}](ctx, dsm, "SYNO.Core.Package", "list", 2, packageListParams)
	if !p.IsKnown() {
		return unknown[Package](p.Detail)
	}
	return packageOf(p.Value.Packages)
}

// MailPlusStatus reads the precondition (one DSM call). A missing grant or a
// caller who is not an administrator is returned as that refusal, so the
// page asks for access instead of showing unknown.
func (d *Detector) MailPlusStatus(ctx context.Context, env core.Env) (MailPlusStatus, error) {
	if env.DSM == nil {
		return StatusOf(unknown[Package](core.CauseUnavailable)), nil
	}
	var authority core.AuthorityRequired
	var refusal error
	probe := guardRefusal{DSM: env.DSM, seen: func(err error) {
		switch {
		case errors.As(err, &authority):
			refusal = core.AuthorityRequired{Profile: authority.Profile}
		case errors.Is(err, core.ErrNoAdmin):
			refusal = core.ErrNoAdmin
		}
	}}
	s := StatusOf(ReadPackage(ctx, probe))
	if refusal != nil {
		return MailPlusStatus{}, refusal
	}
	logCause(env.Log, "SYNO.Core.Package", s.Cause)
	if s.State == MailPlusRunning {
		s.SetUp = readSetUp(ctx, env)
	}
	return s, nil
}

// readSetUp reads whether MailPlus Server finished its first-run setup. Any
// failure (a refusal, an old MailPlus Server without the API, a time-out)
// leaves it unknown: the precondition itself stays what the package list said.
func readSetUp(ctx context.Context, env core.Env) *bool {
	var out struct {
		PlusServerInitialized *bool `json:"plusserver_initialized"`
	}
	if err := env.DSM.Call(ctx, "SYNO.MailPlusServer.Util", "initial_check", 2, map[string]any{}, &out); err != nil {
		if env.Log != nil {
			env.Log.Info("mailplus initial check not read", "error", err.Error())
		}
		return nil
	}
	return out.PlusServerInitialized
}

// guardRefusal reports the raw error of each call before it is reduced to a
// cause.
type guardRefusal struct {
	core.DSM
	seen func(error)
}

func (g guardRefusal) Call(ctx context.Context, api, method string, version int, params map[string]any, out any) error {
	err := g.DSM.Call(ctx, api, method, version, params, out)
	if err != nil {
		g.seen(err)
	}
	return err
}

// logCause keeps a DSM error code in the worker log; the page names the
// cause in plain words only.
func logCause(log *slog.Logger, api, cause string) {
	if log != nil && strings.HasPrefix(cause, "dsm_") {
		log.Warn("dsm read failed", "api", api, "cause", cause)
	}
}

// Gate wraps a DSM transport so that no SYNO.MailPlusServer call is sent once
// a package read through it said MailPlus Server does not run: such a call
// gets MailPlusUnavailable instead. A MailPlus Server API that DSM says does
// not exist (DSM error 102) is reported the same way (CauseMailPlusAPIMissing),
// never as the raw DSM code; the code goes to the log. The gate never reads
// on its own: each flow reads the precondition first (the detection pass, the
// diagnosis snapshot, the zone step's domain read, mail.mailplus.status).
// One gate serves one request and the background work it starts.
func Gate(dsm core.DSM, log *slog.Logger) core.DSM {
	if dsm == nil {
		return nil
	}
	if _, ok := dsm.(*gate); ok {
		return dsm
	}
	if _, ok := dsm.(*confidentialGate); ok {
		return dsm
	}
	g := &gate{inner: dsm, log: log}
	if c, ok := dsm.(confidential); ok {
		return &confidentialGate{gate: g, c: c}
	}
	return g
}

type confidential interface {
	CallConfidential(context.Context, string, string, int, map[string]any, any) error
}

type gate struct {
	inner core.DSM
	log   *slog.Logger
	mu    sync.Mutex
	// refused is set by the last package read through the gate when
	// MailPlus Server does not run (nil: not read, or running).
	refused error
}

const mailPlusPrefix = "SYNO.MailPlusServer."

func (g *gate) Call(ctx context.Context, api, method string, version int, params map[string]any, out any) error {
	if api == "SYNO.Core.Package" && method == "list" {
		return g.packageList(ctx, version, params, out)
	}
	if !strings.HasPrefix(api, mailPlusPrefix) {
		return g.inner.Call(ctx, api, method, version, params, out)
	}
	if err := g.precondition(); err != nil {
		return err
	}
	return g.after(api, g.inner.Call(ctx, api, method, version, params, out))
}

func (g *gate) precondition() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.refused
}

// after maps DSM's "no such API" on a MailPlus Server call to the typed
// refusal; any other answer passes unchanged.
func (g *gate) after(api string, err error) error {
	var dsm core.DSMError
	if err != nil && errors.As(err, &dsm) && dsm.Code == 102 {
		if g.log != nil {
			g.log.Warn("MailPlus Server API missing", "api", api, "cause", "dsm_102")
		}
		return MailPlusUnavailable{State: MailPlusUnknown, Detail: CauseMailPlusAPIMissing}
	}
	return err
}

// packageList passes the package read through and remembers what it said
// about MailPlus Server; the caller decodes the same reply.
func (g *gate) packageList(ctx context.Context, version int, params map[string]any, out any) error {
	var raw json.RawMessage
	if err := g.inner.Call(ctx, "SYNO.Core.Package", "list", version, params, &raw); err != nil {
		return err
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return core.ErrDSMBadResponse
		}
	}
	var reply struct {
		Packages *[]mailPlusPackage `json:"packages"`
	}
	if json.Unmarshal(raw, &reply) == nil {
		s := StatusOf(packageOf(reply.Packages))
		g.mu.Lock()
		g.refused = nil
		if s.State == MailPlusNotInstalled || s.State == MailPlusStopped {
			g.refused = s.Err()
		}
		g.mu.Unlock()
	}
	return nil
}

type confidentialGate struct {
	*gate
	c confidential
}

func (g *confidentialGate) CallConfidential(ctx context.Context, api, method string, version int, params map[string]any, out any) error {
	if strings.HasPrefix(api, mailPlusPrefix) {
		if err := g.precondition(); err != nil {
			return err
		}
	}
	return g.after(api, g.c.CallConfidential(ctx, api, method, version, params, out))
}
