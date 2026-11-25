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

// errExecutor answers every executor call with err.
type errExecutor struct {
	err   func(context.Context) error
	calls int
}

func (f *errExecutor) Call(ctx context.Context, _ string, _ map[string]string, _ any, _ any) error {
	f.calls++
	return f.err(ctx)
}

// opaque wraps like the SDK's unexported notSent wrapper: a pointer type with
// Unwrap, so a direct err.(*api.Error) assertion fails.
type opaque struct{ error }

func (e *opaque) Unwrap() error { return e.error }

func boundAuthority(t *testing.T, client delegate.ExecutorClient) (*Authority, string) {
	t.Helper()
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	a := &Authority{Store: store, Client: client}
	id := strings.Repeat("a", 64)
	g := delegate.Grant{DelegationID: id, Scope: "mail-read", Lifetime: "until-revoked",
		Subject: delegate.Subject{Username: "alice", UID: json.Number("1024")}}
	if err := a.Bind(context.Background(), "alice", g); err != nil {
		t.Fatal(err)
	}
	return a, id
}

func bindingState(t *testing.T, a *Authority) string {
	t.Helper()
	b, err := a.Bindings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return b["mail-read"].State
}

// SDK 0.53.19+ wraps executor refusals; the classifier must use errors.As.
func TestAuthorityClassifiesRealSDKWrappedRefusal(t *testing.T) {
	sdk := &delegate.Client{} // no socket: the SDK answers a wrapped EXECUTOR_UNAVAILABLE
	exec := &errExecutor{err: func(ctx context.Context) error { return sdk.Call(ctx, "webapi.call", nil, nil, nil) }}
	probe := exec.err(context.Background())
	if _, direct := probe.(*api.Error); direct {
		t.Fatal("precondition: SDK refusal is no longer wrapped; this test proves nothing")
	}
	var refusal *api.Error
	if !errors.As(probe, &refusal) || refusal.Code != delegate.CodeExecutorUnavailable || !delegate.NotSent(probe) {
		t.Fatalf("precondition: unexpected SDK refusal %v", probe)
	}
	a, _ := boundAuthority(t, exec)
	err := a.DSM("").Call(context.Background(), "SYNO.Core.Package", "list", 2, nil, nil)
	var required AuthorityRequired
	if !errors.As(err, &required) || required.Profile != "mail-read" {
		t.Fatalf("wrapped EXECUTOR_UNAVAILABLE: got %v, want AuthorityRequired", err)
	}
	if got := bindingState(t, a); got != "configured" {
		t.Fatalf("an unavailable executor must not invalidate the grant: %s", got)
	}
}

func TestAuthorityClassifiesWrappedRefusals(t *testing.T) {
	wraps := map[string]func(error) error{
		"opaque": func(err error) error { return &opaque{err} },
		"fmt":    func(err error) error { return fmt.Errorf("executor: %w", err) },
		"both":   func(err error) error { return fmt.Errorf("call: %w", &opaque{err}) },
	}
	for name, wrap := range wraps {
		for _, code := range []string{"DELEGATION_DENIED", "APP_DENIED", "INELIGIBLE", "disabled", "POLICY_DENIED"} {
			t.Run(name+"/"+code, func(t *testing.T) {
				exec := &errExecutor{err: func(context.Context) error { return wrap(&api.Error{Code: code}) }}
				a, _ := boundAuthority(t, exec)
				err := a.DSM("").Call(context.Background(), "SYNO.Core.Package", "list", 2, nil, nil)
				if !errors.As(err, new(AuthorityRequired)) {
					t.Fatalf("got %v, want AuthorityRequired", err)
				}
				if got := bindingState(t, a); got != "unavailable" {
					t.Fatalf("denied grant not invalidated: %s", got)
				}
			})
		}
		for _, code := range []string{"EXECUTOR_UNAVAILABLE", "EXECUTOR_PAUSED", "APP_STOPPED", "APP_STARTING"} {
			t.Run(name+"/"+code, func(t *testing.T) {
				exec := &errExecutor{err: func(context.Context) error { return wrap(&api.Error{Code: code}) }}
				a, _ := boundAuthority(t, exec)
				err := a.DSM("").Call(context.Background(), "SYNO.Core.Package", "list", 2, nil, nil)
				if !errors.As(err, new(AuthorityRequired)) {
					t.Fatalf("got %v, want AuthorityRequired", err)
				}
				if got := bindingState(t, a); got != "configured" {
					t.Fatalf("a stopped executor must not invalidate the grant: %s", got)
				}
			})
		}
		t.Run(name+"/WEBAPI_UNCERTAIN", func(t *testing.T) {
			exec := &errExecutor{err: func(context.Context) error { return wrap(&api.Error{Code: "WEBAPI_UNCERTAIN"}) }}
			a, _ := boundAuthority(t, exec)
			err := a.DSM("").Call(context.Background(), "SYNO.Core.Package", "list", 2, nil, nil)
			var refusal *api.Error
			if errors.As(err, new(AuthorityRequired)) || !errors.As(err, &refusal) || refusal.Code != "WEBAPI_UNCERTAIN" || exec.calls != 1 {
				t.Fatalf("an uncertain outcome must pass through unchanged, once: %v (calls %d)", err, exec.calls)
			}
		})
	}
}

func TestDSMOversizedRefusalBehindSDKWrapper(t *testing.T) {
	f := &replyTransport{err: &opaque{&api.Error{Code: delegate.CodeWebapiReplyTooLarge}}}
	err := (WebAPIDSM{Transport: f}).Call(context.Background(), "SYNO.Core.Package", "list", 2, nil, nil)
	if !errors.Is(err, ErrDSMReplyTooLarge) || f.calls != 1 {
		t.Fatalf("got %v after %d calls", err, f.calls)
	}
}
