package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	sdkapi "github.com/synopackageland/syno-pkg-land-sdk/api"
	"github.com/synopackageland/syno-pkg-land-sdk/delegate"
)

var ErrNoAdmin = errors.New("admin_required")

// ErrDSMBadResponse is a DSM reply that could not be read: not a JSON
// envelope, data that does not decode, or a failure without an error code.
var ErrDSMBadResponse = errors.New("dsm_bad_response")

// An oversized reply is missing evidence, not a lost grant or a healthy result.
// Keep only a safe local error; executor messages must not reach findings.
var ErrDSMReplyTooLarge = fmt.Errorf("dsm_response_too_large: %w", ErrUnavailable)

// WebAPICaller is supplied only by a supported, separately authorized SDK
// transport (for example a profile-bound delegate.JobWebAPI). It returns a DSM
// envelope. Browser cookies are never accepted by this package.
type WebAPICaller interface {
	Call(context.Context, string, string, int, map[string]any) (json.RawMessage, error)
}

type WebAPIDSM struct{ Transport WebAPICaller }

type DSMError struct{ Code int }

func (e DSMError) Error() string { return fmt.Sprintf("dsm_%d", e.Code) }

// CallConfidential is the mail setup adapter's protected-payload port. The
// profile transport sends JSON directly to the SDK private executor socket;
// params and response bodies never enter logs, history, KV or wizard replies.
func (d WebAPIDSM) CallConfidential(ctx context.Context, api, method string, version int, params map[string]any, out any) error {
	return d.Call(ctx, api, method, version, params, out)
}

func (d WebAPIDSM) Call(ctx context.Context, api, method string, version int, params map[string]any, out any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.Transport == nil {
		if profile := authorityProfile(ctx, api, method, version); profile != "" {
			return AuthorityRequired{Profile: profile}
		}
		return ErrInvalid
	}
	if api == "" || method == "" || version < 1 {
		return ErrInvalid
	}
	raw, err := d.Transport.Call(ctx, api, method, version, params)
	if err != nil {
		var refusal *sdkapi.Error
		if errors.As(err, &refusal) && refusal.Code == delegate.CodeWebapiReplyTooLarge {
			// Never resend: even an oversized mutation may have completed.
			return ErrDSMReplyTooLarge
		}
		return err
	}
	if len(raw) > delegate.MaxWebAPIReply {
		return ErrDSMReplyTooLarge
	}
	var envelope struct {
		Success bool            `json:"success"`
		Data    json.RawMessage `json:"data"`
		Error   struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return ErrDSMBadResponse
	}
	if !envelope.Success {
		return DSMError{Code: envelope.Error.Code}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(envelope.Data, out); err != nil {
		return ErrDSMBadResponse
	}
	return nil
}
