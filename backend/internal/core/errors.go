package core

import (
	"context"
	"errors"
)

var ErrAuthorityRequired = errors.New("authority_required")

// AuthorityRequired describes a missing or unusable protected grant, not the
// caller's administrator role. Profile is always from the fixed DSM inventory.
type AuthorityRequired struct {
	Profile string
}

func (e AuthorityRequired) Error() string { return "authority_required: " + e.Profile }
func (AuthorityRequired) Unwrap() error   { return ErrAuthorityRequired }

// RPCError is the only error shape that leaves the worker. Module error text
// never does: providers may include secrets.
type RPCError struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
}

func (e *RPCError) Error() string { return e.Code }

// PublicError maps an internal error to a fixed public code.
func PublicError(err error) *RPCError {
	var rpc *RPCError
	if errors.As(err, &rpc) {
		return rpc
	}
	out := &RPCError{Code: "internal", Message: "MailPlus Setup Assistant operation unavailable"}
	var authority AuthorityRequired
	switch {
	case errors.As(err, &authority):
		out.Code = "authority_required"
		out.Details = map[string]string{"profile": authority.Profile}
	case errors.Is(err, ErrInvalid):
		out.Code = "bad_request"
	case errors.Is(err, ErrNotFound):
		out.Code = "not_found"
	case errors.Is(err, ErrConflict):
		out.Code = "conflict"
	case errors.Is(err, ErrNoAdmin):
		out.Code = "admin_required"
	case errors.Is(err, ErrUnavailable):
		out.Code = "unavailable"
	case errors.Is(err, context.DeadlineExceeded):
		out.Code = "request_timeout"
	}
	return out
}

// Coded is implemented by module errors that carry their own fixed public
// code (for example mail.setup.stalePlan); the code is safe to show.
type Coded interface{ PublicCode() string }
