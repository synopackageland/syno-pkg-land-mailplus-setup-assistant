package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/synopackageland/syno-pkg-land-sdk/api"
	"github.com/synopackageland/syno-pkg-land-sdk/delegate"
)

type replyTransport struct {
	raw   json.RawMessage
	err   error
	calls int
}

func (f *replyTransport) Call(context.Context, string, string, int, map[string]any) (json.RawMessage, error) {
	f.calls++
	return f.raw, f.err
}

func TestDSMOversizedRefusalIsUnavailableWithoutRetry(t *testing.T) {
	for _, method := range []string{"get", "set"} {
		t.Run(method, func(t *testing.T) {
			f := &replyTransport{err: fmt.Errorf("wrapped: %w", &api.Error{
				Code: delegate.CodeWebapiReplyTooLarge, Message: "provider-private-value",
			})}
			out := struct{ Value string }{Value: "unchanged"}
			err := (WebAPIDSM{Transport: f}).Call(context.Background(), "SYNO.Core.Network", method, 2, nil, &out)
			if !errors.Is(err, ErrDSMReplyTooLarge) || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("oversized reply must be unknown evidence: %v", err)
			}
			if f.calls != 1 || out.Value != "unchanged" || strings.Contains(err.Error(), "provider-private-value") {
				t.Fatal("refusal was retried, decoded or exposed provider text")
			}
			if PublicError(err).Code != "unavailable" {
				t.Fatal("oversized reply became an internal error or approval request")
			}
		})
	}
}

func TestDSMReplyCapacity(t *testing.T) {
	const prefix = `{"success":true,"data":{"padding":"`
	const suffix = `","count":3}}`
	for _, size := range []int{48<<10 + 1, 4<<20 + 1, 20 << 20, 20<<20 + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			f := &replyTransport{raw: json.RawMessage(prefix + strings.Repeat("x", size-len(prefix)-len(suffix)) + suffix)}
			var out struct{ Count int }
			err := (WebAPIDSM{Transport: f}).Call(context.Background(), "SYNO.API.Info", "query", 1, nil, &out)
			if size > 20<<20 {
				if !errors.Is(err, ErrDSMReplyTooLarge) || !errors.Is(err, ErrUnavailable) || out.Count != 0 {
					t.Fatalf("oversized reply was accepted: %v / %+v", err, out)
				}
			} else if err != nil || out.Count != 3 {
				t.Fatalf("in-limit envelope rejected: %v / %+v", err, out)
			}
			if f.calls != 1 {
				t.Fatal("reply was retried")
			}
		})
	}
}
