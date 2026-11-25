package setup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"SynoMailPlusSetupAssistant/internal/core"
)

type refusingDSM struct{ err error }

func (d refusingDSM) Call(context.Context, string, string, int, map[string]any, any) error {
	return d.err
}
func (d refusingDSM) CallConfidential(context.Context, string, string, int, map[string]any, any) error {
	return d.err
}

// Typed permission refusals keep their code and profile through mail.setup so
// the engine can put them on step.error; anything else stays generic.
func TestPublicErrorPassesOnlyTypedRefusals(t *testing.T) {
	const leak = "password=hunter2 dsm says: raw reply"
	for _, tc := range []struct {
		name    string
		err     error
		profile string
		admin   bool
	}{
		{name: "authority", err: core.AuthorityRequired{Profile: "mail-write"}, profile: "mail-write"},
		{name: "wrapped authority", err: fmt.Errorf("%s: %w", leak, core.AuthorityRequired{Profile: "mail-read"}), profile: "mail-read"},
		{name: "admin", err: core.ErrNoAdmin, admin: true},
		{name: "wrapped admin", err: fmt.Errorf("%s: %w", leak, core.ErrNoAdmin), admin: true},
		{name: "dsm error", err: core.DSMError{Code: 105}},
		{name: "raw error", err: errors.New(leak)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Directly, and through the MailPlus DSM helpers the adapter uses.
			env := core.Env{DSM: refusingDSM{tc.err}}
			_, read := mpRead(context.Background(), env, "SYNO.MailPlusServer.Service.SMTP", "get", 1, map[string]any{})
			write := mpWrite(context.Background(), env, "SYNO.MailPlusServer.Service.SMTP", "set", 1, map[string]any{})
			delivery := mpSetDelivery(context.Background(), core.Env{DSM: refusingDSM{tc.err}, Secrets: secrets{"user": "relay-user", "pass": "relay-pass"}}, mpOperation{Relay: relayConfig{Listen: "127.0.0.1:2525", UsernameRef: "user", PasswordRef: "pass"}})
			for _, got := range []error{publicError(tc.err), read, write, delivery} {
				if strings.Contains(got.Error(), "hunter2") || strings.Contains(got.Error(), "raw reply") {
					t.Fatalf("provider text leaked: %q", got)
				}
				var authority core.AuthorityRequired
				switch {
				case tc.profile != "":
					if !errors.As(got, &authority) || authority.Profile != tc.profile {
						t.Fatalf("want authority_required %s, got %v", tc.profile, got)
					}
				case tc.admin:
					if !errors.Is(got, core.ErrNoAdmin) || errors.As(got, &authority) {
						t.Fatalf("want admin_required, got %v", got)
					}
				default:
					if !errors.Is(got, ErrUnavailable) || errors.Is(got, core.ErrNoAdmin) || errors.As(got, &authority) {
						t.Fatalf("want generic unavailable, got %v", got)
					}
				}
			}
		})
	}
}
