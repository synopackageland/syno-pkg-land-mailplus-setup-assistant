package core

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"sync"
	"time"

	"SynoMailPlusSetupAssistant/internal/core/dsmauthority"
	"github.com/synopackageland/syno-pkg-land-sdk/api"
	"github.com/synopackageland/syno-pkg-land-sdk/delegate"
)

type WebAPIProfile = dsmauthority.WebAPIProfile

type AuthorityBinding = dsmauthority.Binding

func AuthorityProfiles() map[string]WebAPIProfile { return dsmauthority.Profiles() }

// authorityProfiles lists every profile that pins this exact tuple, sorted.
func authorityProfiles(apiName, method string, version int) []string {
	out := []string{}
	for name, profile := range AuthorityProfiles() {
		for _, v := range profile.APIs[apiName][method] {
			if v == version {
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// authorityProfile picks the one profile that pins this exact tuple. The two
// mail profiles are disjoint; "" means no profile may carry this call.
func authorityProfile(_ context.Context, apiName, method string, version int) string {
	candidates := authorityProfiles(apiName, method, version)
	if len(candidates) != 1 {
		return ""
	}
	return candidates[0]
}

// Authority stores references only. The executor owns authority, identity
// revalidation, revocation fences and policy/profile pins.
type Authority struct {
	Store  *Store
	Client delegate.ExecutorClient
	Now    func() time.Time
	// ReadTimeout, SlotWait and Slots override DSMReadTimeout, DSMSlotWait and
	// DSMSlots (tests only).
	ReadTimeout time.Duration
	SlotWait    time.Duration
	Slots       int
	mu          sync.Mutex
	slotsOnce   sync.Once
	slots       chan struct{}
}

// acquire waits, bounded by ctx, for one of the executor's JSON WebAPI slots
// so this package never runs more calls than the executor admits.
func (a *Authority) acquire(ctx context.Context) (func(), error) {
	a.slotsOnce.Do(func() {
		n := DSMSlots
		if a.Slots > 0 {
			n = a.Slots
		}
		a.slots = make(chan struct{}, n)
	})
	select {
	case a.slots <- struct{}{}:
		return func() { <-a.slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// readTimeout is the per-call budget of reads and writes alike.
func (a *Authority) readTimeout() time.Duration {
	if a.ReadTimeout > 0 {
		return a.ReadTimeout
	}
	return DSMReadTimeout
}

func (a *Authority) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

var grantID = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Bind is reached only over private IPC after CGI obtained an SDK grant using
// the live caller. A browser cannot supply a grant or an identity to that route.
func (a *Authority) Bind(ctx context.Context, owner string, g delegate.Grant) error {
	_, known := AuthorityProfiles()[g.Scope]
	uid, err := g.Subject.UID.Int64()
	if !known || !grantID.MatchString(g.DelegationID) || g.Subject.Username != owner ||
		owner == "" || err != nil || uid <= 0 || g.Revoked || g.Lifetime != "until-revoked" {
		return ErrInvalid
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Store.Put(ctx, "core.authority", g.Scope, AuthorityBinding{Grant: g, State: "configured"})
}

func (a *Authority) Bindings(ctx context.Context) (map[string]AuthorityBinding, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string]AuthorityBinding{}
	for name := range AuthorityProfiles() {
		var b AuthorityBinding
		found, err := a.Store.Get(ctx, "core.authority", name, &b)
		if err != nil {
			return nil, err
		}
		if !found {
			b.State = "missing"
		} else if !b.Grant.ExpiresAt.IsZero() && !b.Grant.ExpiresAt.After(a.now()) {
			b.State = "expired"
		}
		out[name] = b
	}
	return out, nil
}

// Forget follows protected revoke or verified list readback, never an optimistic
// UI dismissal. An ID comparison prevents an old reply clearing a newer grant.
func (a *Authority) Forget(ctx context.Context, profile, id string) error {
	if _, ok := AuthorityProfiles()[profile]; !ok || !grantID.MatchString(id) {
		return ErrInvalid
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var b AuthorityBinding
	found, err := a.Store.Get(ctx, "core.authority", profile, &b)
	if err != nil || !found || b.Grant.DelegationID != id {
		return err
	}
	b.State = "revoked"
	b.Grant.Revoked = true
	return a.Store.Put(ctx, "core.authority", profile, b)
}

// DSM supplies shared background reads or an interactive caller's own grants.
// Only the latter admits writes. No transport captures a live session.
func (a *Authority) DSM(owner string) WebAPIDSM {
	return WebAPIDSM{Transport: authorityTransport{authority: a, owner: owner}}
}

type authorityTransport struct {
	authority *Authority
	owner     string
}

func (t authorityTransport) Call(ctx context.Context, apiName, method string, version int, params map[string]any) (json.RawMessage, error) {
	a := t.authority
	profile := authorityProfile(ctx, apiName, method, version)
	if profile == "" {
		return nil, ErrInvalid
	}
	if profile == "mail-write" && t.owner == "" {
		return nil, AuthorityRequired{Profile: profile}
	}
	// Keep the read/bind ordering deterministic. Executor revoke fences calls
	// already in flight; never hold this lock while waiting for the executor.
	a.mu.Lock()
	var b AuthorityBinding
	found, err := a.Store.Get(ctx, "core.authority", profile, &b)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !found || b.State != "configured" || b.Grant.Revoked ||
		(!b.Grant.ExpiresAt.IsZero() && !b.Grant.ExpiresAt.After(a.now())) ||
		(t.owner != "" && b.Grant.Subject.Username != t.owner) || a.Client == nil {
		return nil, AuthorityRequired{Profile: profile}
	}
	w := (delegate.JobContext{Client: a.Client, DelegationID: b.Grant.DelegationID}).WebAPI()
	read := profile == "mail-read"
	raw, err, callCtx, done := a.dispatch(ctx, func(c context.Context) (json.RawMessage, error) {
		return w.Call(c, apiName, method, version, params)
	})
	defer done()
	if errors.Is(err, ErrDSMSlotTimeout) {
		return nil, err // never sent
	}
	var unsent notSent
	if errors.As(err, &unsent) {
		return nil, unsent.err // the caller ended before the call was sent
	}
	if err != nil && !read && !refusedBeforeAdmission(err) && !delegate.NotSent(err) {
		// Every other write failure may have happened after the request went
		// out (a lost reply, a transport error, a protocol error): its outcome
		// is unknown, and callers reconcile by reading.
		return nil, ErrDSMWriteUncertain
	}
	if read && err != nil {
		switch {
		case ctx.Err() != nil:
			return nil, ctx.Err() // the caller's whole job ended (deadline or cancel)
		case callCtx.Err() != nil || refusalCode(err) == "EXECUTOR_TIMEOUT":
			return nil, ErrDSMTimeout
		}
	}
	if err != nil {
		var refusal *api.Error
		if errors.As(err, &refusal) {
			switch refusal.Code {
			case "DELEGATION_DENIED", "APP_DENIED", "INELIGIBLE", "disabled", "POLICY_DENIED":
				// Persist invalidation so UI can request fresh approval. Never
				// retry a write or silently select a different administrator.
				a.mu.Lock()
				var current AuthorityBinding
				ok, readErr := a.Store.Get(ctx, "core.authority", profile, &current)
				if readErr == nil && ok && current.Grant.DelegationID == b.Grant.DelegationID {
					current.State = "unavailable"
					_ = a.Store.Put(ctx, "core.authority", profile, current)
				}
				a.mu.Unlock()
				return nil, AuthorityRequired{Profile: profile}
			case "EXECUTOR_UNAVAILABLE", "EXECUTOR_PAUSED", "APP_STOPPED", "APP_STARTING":
				return nil, AuthorityRequired{Profile: profile}
			}
		}
		// In particular, preserve WEBAPI_UNCERTAIN; missing replies must not
		// become a successful write or trigger an automatic resend.
		return nil, err
	}
	return raw, nil
}

// dispatch runs call with its full budget (readTimeout) once it holds an
// executor slot. Since SDK 0.53.18 the delegate client also keeps a 2-slot
// admission queue per socket and retries ROOT_BUSY itself until the call's
// context ends. This semaphore is taken first and has the same size, so the
// SDK queue never waits; the SDK's retry replaces the ROOT_BUSY branch below,
// which stays for older clients and never runs a second layer of retries. Waiting for the slot and backing off after ROOT_BUSY (a
// refusal before dispatch) are bounded separately by DSMSlotWait. A call that
// would start with less than its full budget left in ctx is not sent:
// ErrDSMSlotTimeout. done releases the slot.
func (a *Authority) dispatch(ctx context.Context, call func(context.Context) (json.RawMessage, error)) (json.RawMessage, error, context.Context, func()) {
	waitCtx, stopWait := context.WithTimeout(ctx, a.slotWait())
	defer stopWait()
	backoff := 500 * time.Millisecond
	for {
		release, err := a.acquire(waitCtx)
		if err != nil {
			if ctx.Err() != nil {
				return nil, notSent{ctx.Err()}, ctx, func() {}
			}
			return nil, ErrDSMSlotTimeout, ctx, func() {}
		}
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < a.readTimeout() {
			release()
			return nil, ErrDSMSlotTimeout, ctx, func() {}
		}
		callCtx, cancel := context.WithTimeout(ctx, a.readTimeout())
		raw, err := call(callCtx)
		if refusalCode(err) != "ROOT_BUSY" {
			return raw, err, callCtx, func() { cancel(); release() }
		}
		// Refused before dispatch: nothing ran. Free the slot and retry
		// with exponential backoff, within the slot wait.
		cancel()
		release()
		select {
		case <-waitCtx.Done():
			if ctx.Err() != nil {
				return nil, notSent{ctx.Err()}, ctx, func() {}
			}
			return nil, ErrDSMSlotTimeout, ctx, func() {}
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 8*time.Second)
	}
}

func (a *Authority) slotWait() time.Duration {
	if a.SlotWait > 0 {
		return a.SlotWait
	}
	return DSMSlotWait
}

// notSent is a caller's own end (cancel or deadline) before a call was sent.
type notSent struct{ err error }

func (e notSent) Error() string { return e.err.Error() }
func (e notSent) Unwrap() error { return e.err }

// beforeAdmission are the refusals that protocol v1 marks preAdmission: true
// (SDK v0.53.19 spec/protocol/v1/errors.json): the executor refused before
// admitting the request, so nothing ran. Every other failure of a write,
// including EXECUTOR_PAUSED, ROOT_STAGING_FULL, disabled, APP_STOPPED and
// APP_STARTING (preAdmission: false), leaves its outcome unknown.
var beforeAdmission = map[string]bool{
	"AUTH_DENIED": true, "INELIGIBLE": true, "APP_DENIED": true, "ADMIN_REQUIRED": true,
	"DELEGATION_DENIED": true, "SCOPE_DENIED": true, "POLICY_DENIED": true, "PEER_DENIED": true,
	"PERMISSION_DENIED": true, "UNKNOWN_OP": true, "INVALID_REQUEST": true, "REQUEST_TOO_LARGE": true,
	"EXECUTOR_STARTING": true, "ROOT_BUSY": true, "ROOT_JOB_NOT_FOUND": true,
	"SCOPE_APPROVAL_STALE": true, "IDENTITY_CHANGED": true,
}

func refusedBeforeAdmission(err error) bool { return beforeAdmission[refusalCode(err)] }

func refusalCode(err error) string {
	var refusal *api.Error
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return ""
}
