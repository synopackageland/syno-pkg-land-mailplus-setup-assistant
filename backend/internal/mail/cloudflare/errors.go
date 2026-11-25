package cloudflare

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ErrorKind string

const (
	ErrAuth       ErrorKind = "auth"
	ErrPermission ErrorKind = "permission_missing"
	ErrNotFound   ErrorKind = "not_found"
	ErrRateLimit  ErrorKind = "rate_limit"
	ErrPlanLimit  ErrorKind = "plan_limit"
	ErrOwnership  ErrorKind = "not_owned"
	ErrManagedDNS ErrorKind = "managed_dns"
	ErrConflict   ErrorKind = "conflict"
	ErrInvalid    ErrorKind = "invalid"
	ErrTransport  ErrorKind = "transport"
	ErrProtocol   ErrorKind = "protocol"
	ErrAPI        ErrorKind = "api"
)

// Error contains only safe local text and numeric API codes. Permission names
// are the operation's alternatives, not an assertion about the token's policy.
// The UI should translate Kind and render RequiredPermissions as parameters.
type Error struct {
	Kind                ErrorKind     `json:"kind"`
	Operation           string        `json:"operation"`
	Status              int           `json:"status,omitempty"`
	Codes               []int         `json:"codes,omitempty"`
	RequiredPermissions []string      `json:"requiredPermissions,omitempty"`
	RetryAfter          time.Duration `json:"retryAfter,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("cloudflare %s: %s (HTTP %d)", e.Operation, e.Kind, e.Status)
}

func classify(status int, issues []apiIssue) *Error {
	e := &Error{Kind: ErrAPI, Status: status}
	var messages []string
	var visit func([]apiIssue)
	visit = func(items []apiIssue) {
		for _, item := range items {
			e.Codes = append(e.Codes, item.Code)
			messages = append(messages, strings.ToLower(item.Message))
			visit(item.Chain)
		}
	}
	visit(issues)
	message := strings.Join(messages, " ")
	switch {
	case status == 429:
		e.Kind = ErrRateLimit
	case status == 401:
		e.Kind = ErrAuth
	case status == 404:
		e.Kind = ErrNotFound
	case status == 409:
		e.Kind = ErrConflict
	case status == 402 || strings.Contains(message, "entitlement") ||
		strings.Contains(message, "workers paid") || strings.Contains(message, "plan limit") ||
		strings.Contains(message, "quota exceeded") || strings.Contains(message, "upgrade your plan"):
		e.Kind = ErrPlanLimit
	case strings.Contains(message, "managed by email routing"):
		e.Kind = ErrManagedDNS
	case status == 403:
		e.Kind = ErrPermission
	}
	for _, code := range e.Codes {
		switch code {
		case 6003, 6103, 6111, 9106, 9109:
			if e.Kind == ErrAPI || e.Kind == ErrPermission {
				e.Kind = ErrAuth
			}
		case 10000:
			if e.Kind == ErrAPI {
				e.Kind = ErrAuth
			}
		case 1046:
			e.Kind = ErrManagedDNS
		case codeRecipientPlanRestricted, codeSendingNotEntitled:
			e.Kind = ErrPlanLimit
		}
	}
	return e
}

func retryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		// Bound values before conversion to avoid duration overflow.
		if seconds > 86400 {
			seconds = 86400
		}
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		return min(at.Sub(now), 24*time.Hour)
	}
	return 0
}

// HTTPStatus is the HTTP status of a Cloudflare refusal, or 0 when err is
// not one (transport, protocol or local errors).
func HTTPStatus(err error) int {
	if e := asError(err); e != nil {
		return e.Status
	}
	return 0
}

// MalformedCredential reports Cloudflare saying the credential itself is
// malformed: HTTP 400 with an Authorization-format code (6003 "Invalid
// request headers" with 6111 "Invalid format for Authorization header",
// 6103, 9106). Seen on /user/tokens/verify for a token of the wrong shape.
func MalformedCredential(err error) bool {
	e := asError(err)
	if e == nil || e.Status != 400 {
		return false
	}
	for _, code := range e.Codes {
		switch code {
		case 6003, 6103, 6111, 9106:
			return true
		}
	}
	return false
}

// PlanLimited reports a Cloudflare refusal classified as a plan or
// entitlement answer (HTTP 402, or a message naming an entitlement, Workers
// Paid, a plan limit or an upgrade, or code 10208), for example Email Sending
// to a recipient Workers Free does not allow.
func PlanLimited(err error) bool {
	e := asError(err)
	return e != nil && e.Kind == ErrPlanLimit
}

// codeRecipientPlanRestricted is Email Sending's REST refusal of a recipient
// the plan does not allow: on Workers Free, any address that is not one of
// the account's verified destination addresses (HTTP 403,
// email.sending.error.email.recipient_plan_restricted). The Workers binding
// names the same refusal E_RECIPIENT_PLAN_RESTRICTED.
const codeRecipientPlanRestricted = 10208

// codeSendingNotEntitled: the account is not entitled to Email Sending at all
// (HTTP 403, email.sending.error.authentication.not_entitled).
const codeSendingNotEntitled = 10105

// RecipientPlanRestricted reports Email Sending refusing a recipient because
// the account is on Workers Free, which sends only to its verified
// destination addresses. Sending to anyone needs Workers Paid.
func RecipientPlanRestricted(err error) bool {
	e := asError(err)
	if e == nil {
		return false
	}
	for _, code := range e.Codes {
		if code == codeRecipientPlanRestricted {
			return true
		}
	}
	return false
}

// PermissionRefused reports a clear missing-permission answer: HTTP 403 whose
// error codes are only the documented authorization refusals 10000
// (authentication/permission error) or 9109 (unauthorized access), and not a
// plan or entitlement answer. A 403 with any other code (for example a product
// that is not enabled on the account) is not proof of a missing permission:
// callers treat it as unknown.
func PermissionRefused(err error) bool {
	e := asError(err)
	if e == nil || e.Status != 403 || e.Kind == ErrPlanLimit || len(e.Codes) == 0 {
		return false
	}
	for _, code := range e.Codes {
		if code != 10000 && code != 9109 {
			return false
		}
	}
	return true
}
