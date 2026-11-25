// Package core is the small worker core the mail code needs: the shared data
// types, the DSM WebAPI transport behind administrator grants, the sealed
// secret store, a KV store and the relay service host. It was cut down from
// Syno Home Keeper's core (see docs/PROVENANCE.md); there is no module
// registry, scheduler, notifier or server-driven wizard engine.
package core

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"
)

// ---------- Checks and findings ----------

type Severity string

const (
	SeverityOK       Severity = "ok"
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Finding is one result of a check. ID is stable across runs (for example
// "mail.ptr.mismatch") so the store can track first/last seen and dedupe
// notifications. Text is i18n keys plus params; the UI renders it.
type Finding struct {
	ID        string            `json:"id"`
	Module    string            `json:"module"`
	Check     string            `json:"check"`
	Severity  Severity          `json:"severity"`
	TitleKey  string            `json:"titleKey"`
	WhyKey    string            `json:"whyKey,omitempty"`    // why it matters
	FixKey    string            `json:"fixKey,omitempty"`    // what to do
	Params    map[string]string `json:"params,omitempty"`    // i18n placeholders
	Evidence  json.RawMessage   `json:"evidence,omitempty"`  // raw facts, shown folded
	FixWizard string            `json:"fixWizard,omitempty"` // "mail.setup" or "mail.diagnose"
}

// Check is read-only. It must never change DSM, MailPlus or Cloudflare.
// Checks run only on demand, from the diagnose wizard; Interval is kept for
// the ported mail code and is not scheduled by this package.
type Check interface {
	ID() string
	Interval() time.Duration
	Run(ctx context.Context, env Env) ([]Finding, error)
}

// MemoryCheck is an optional Check extension carried over from Home Keeper:
// part of the check can be judged from in-process state alone.
type MemoryCheck interface {
	Check
	MemoryInterval() time.Duration
	Judge(now time.Time) ([]Finding, bool)
}

// ---------- Wizard data shown by the UI ----------
//
// The step flow itself lives in the browser (the UI SDK Wizard). The backend
// only returns typed facts, choices, form fields and planned changes.

type Fact struct {
	LabelKey string   `json:"labelKey"`
	Value    string   `json:"value"`
	Status   Severity `json:"status,omitempty"`
	// Params fill a catalog key in Value (for example a DSM error code).
	Params map[string]string `json:"params,omitempty"`
	// Group, State and Unrelated order a list of facts for the reader (the
	// setup wizard's detection results); a fact without them is shown as is.
	// Group: mailplus, network, dns or cloudflare. State: ok, problem,
	// unknown, notChecked, planned (the decided plan creates it) or optional. Unrelated: not needed by the chosen route and
	// intent (still shown, folded away).
	Group     string `json:"group,omitempty"`
	State     string `json:"state,omitempty"`
	Unrelated bool   `json:"unrelated,omitempty"`
	// NoteKey (state planned or optional) says in a short line why the fact
	// needs no action: what the setup will create, or that it is optional.
	NoteKey string `json:"noteKey,omitempty"`
}

type Option struct {
	Value       string `json:"value"`
	LabelKey    string `json:"labelKey"`
	HintKey     string `json:"hintKey,omitempty"`
	Recommended bool   `json:"recommended,omitempty"`
	Disabled    bool   `json:"disabled,omitempty"`
	DisabledKey string `json:"disabledKey,omitempty"`
}

type Field struct {
	Name     string   `json:"name"`
	Kind     string   `json:"kind"` // text, secret, email, domain, number, select
	LabelKey string   `json:"labelKey"`
	HintKey  string   `json:"hintKey,omitempty"`
	Required bool     `json:"required,omitempty"`
	Default  string   `json:"default,omitempty"`
	Options  []Option `json:"options,omitempty"`
}

// Change is one planned write, shown in preview before anything happens.
type Change struct {
	ID        string            `json:"id"`
	Target    string            `json:"target"` // "cloudflare.dns", "mailplus.delivery", "homekeeper.relay" (the relay this package hosts)
	ActionKey string            `json:"actionKey"`
	Params    map[string]string `json:"params,omitempty"`
	Before    string            `json:"before,omitempty"`
	After     string            `json:"after,omitempty"`
}

// ---------- Services ----------

type ServiceStatus struct {
	Running  bool              `json:"running"`
	Since    time.Time         `json:"since,omitempty"`
	Counters map[string]int64  `json:"counters,omitempty"`
	LastErr  string            `json:"lastError,omitempty"`
	Info     map[string]string `json:"info,omitempty"`
}

// Service is a long-running helper (the mail relay). The service host starts
// enabled services at boot, restarts them with backoff, and reports status.
type Service interface {
	ID() string                               // "mail.relay"
	Start(ctx context.Context, env Env) error // blocks until ctx is done or a fatal error
	Status() ServiceStatus
}

// ---------- Environment given to modules ----------

type Env struct {
	DSM     DSM
	Secrets Secrets
	KV      KV
	Log     *slog.Logger
	DataDir string // package-owned persistent dir (/var/packages/<pkg>/var)
	Now     func() time.Time
	// Client is the signed-in browser's address for this request (REMOTE_ADDR
	// via the SDK); empty in the background. Never stored.
	Client string
}

type clientKey struct{}

// WithClient attaches the browser's address to an interactive request.
func WithClient(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientKey{}, ip)
}

// ClientFrom returns the address WithClient attached, or "".
func ClientFrom(ctx context.Context) string {
	ip, _ := ctx.Value(clientKey{}).(string)
	return ip
}

// DSM calls a DSM WebAPI. Interactive wizard steps run with the signed-in
// administrator's session; scheduled checks run with whatever the core can
// legitimately use (the package account) and must cope with ErrNoAdmin.
type DSM interface {
	Call(ctx context.Context, api, method string, version int, params map[string]any, out any) error
}

// Secrets is the package's encrypted store (Cloudflare tokens, relay AUTH).
// Get returns ("", nil) when the key is absent; any error means fail closed.
type Secrets interface {
	Get(ctx context.Context, key string) (string, error)
	Put(ctx context.Context, key, value string) error
	Delete(ctx context.Context, key string) error
}

// KV is small per-module persistent state (JSON values).
type KV interface {
	Get(ctx context.Context, module, key string, out any) (bool, error)
	Put(ctx context.Context, module, key string, v any) error
}
