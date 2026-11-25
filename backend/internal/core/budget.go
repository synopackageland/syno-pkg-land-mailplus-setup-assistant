package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	sdkapi "github.com/synopackageland/syno-pkg-land-sdk/api"
)

// DSMReadTimeout bounds one delegated call once it holds an executor slot.
// Each call starts root processes (account check, administrator check,
// synowebapi), which takes seconds on a loaded NAS. Each hop keeps min(5 s,
// 25 %) of its deadline for the reply (SDK docs/request-deadlines.md): the
// delegate client for its own timeout, again for the deadline_ms it sends,
// and the executor's DSM command layer once more. 136 s here tells the
// executor >= 125 s and leaves the DSM work itself >= 120 s (N + 15 s, plus
// one second for the time spent before sending).
const DSMReadTimeout = 136 * time.Second

// DSMSlotWait bounds waiting for one of the executor's two slots (and for
// ROOT_BUSY refusals), separately from the call's own budget: up to two other
// calls at their full budget. A call that cannot get a slot in time fails with
// ErrDSMSlotTimeout and is never sent.
const DSMSlotWait = 2 * DSMReadTimeout

// DSMWriteTimeout bounds one delegated mail-write call the same way: a write
// starts the same root processes as a read.
const DSMWriteTimeout = DSMReadTimeout

// DSMCallWall is one delegated call's worst wall time: the longest slot wait,
// then its own full budget. Callers size their deadlines with it.
const DSMCallWall = DSMSlotWait + DSMReadTimeout

// DSMCalls is the worst wall time of n delegated calls made one after another.
func DSMCalls(n int) time.Duration { return time.Duration(n) * DSMCallWall }

// DSMSlots matches the executor's JSON WebAPI slots (two per package); a third
// concurrent call would be refused with ROOT_BUSY.
const DSMSlots = 2

// ErrDSMTimeout is a delegated read that did not answer within its budget.
var ErrDSMTimeout = fmt.Errorf("dsm_timeout: %w", context.DeadlineExceeded)

// ErrDSMSlotTimeout is a call that never started: no executor slot within
// DSMSlotWait, or less than its full budget left in the caller's deadline.
// Nothing was sent, so even a write's outcome is known (not applied).
var ErrDSMSlotTimeout = fmt.Errorf("dsm_not_started: %w", context.DeadlineExceeded)

// ErrDSMWriteUncertain is a delegated write without an answer: it may or may
// not have taken effect. Callers reconcile by reading the setting again and
// never send the write again on their own.
var ErrDSMWriteUncertain = fmt.Errorf("dsm_write_uncertain: %w", ErrUnavailable)

// Fixed, public causes of a missing DSM observation. Never an upstream string.
const (
	CauseTimeout     = "probe_timeout"
	CauseUnavailable = "probe_unavailable"
	CauseAuthority   = "authority_required"
	CauseTooLarge    = "dsm_response_too_large"
)

// Cause reduces a DSM read error to a fixed public cause: probe_timeout,
// authority_required, dsm_<code>, dsm_response_too_large or probe_unavailable.
func Cause(err error) string {
	var dsm DSMError
	var refusal *sdkapi.Error
	var public interface{ PublicCause() string }
	switch {
	case err == nil:
		return ""
	case errors.As(err, &public) && public.PublicCause() != "":
		// A module's own fixed cause (the MailPlus Server precondition).
		return public.PublicCause()
	case errors.Is(err, ErrAuthorityRequired):
		return CauseAuthority
	case errors.As(err, &dsm) && dsm.Code > 0:
		return fmt.Sprintf("dsm_%d", dsm.Code)
	case errors.Is(err, ErrDSMReplyTooLarge):
		return CauseTooLarge
	case errors.Is(err, context.DeadlineExceeded):
		return CauseTimeout
	case errors.As(err, &refusal) && refusal.Code == "EXECUTOR_TIMEOUT":
		return CauseTimeout
	}
	return CauseUnavailable
}
