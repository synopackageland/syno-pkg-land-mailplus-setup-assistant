package setup

import (
	"context"
	"strings"
	"sync"

	"SynoMailPlusSetupAssistant/internal/core"
)

// fixtureToken is the pasted token of the tests; it must never appear in a
// flow record, a reply or a plan.
const fixtureToken = "fixture-credential-must-never-appear"

var (
	testAccount = strings.Repeat("a", 32)
	testZone    = strings.Repeat("b", 32)
)

// fakeDirectory is the sign-in's Cloudflare side: one account holding the
// active zone example.test, unless a test sets otherwise.
type fakeDirectory struct {
	mu       sync.Mutex
	accounts []CloudAccount
	zones    map[string][]CloudZone
	missing  []string // refused at Accounts
	unknown  bool     // accepted, but no account named
	zoneMiss []string // refused at Zones
	probe    []string // refused at Probe
	err      error
	tokens   []string // token values seen (resolved from the sealed reference)
	calls    []string
}

func newDirectory() *fakeDirectory {
	return &fakeDirectory{
		accounts: []CloudAccount{{ID: testAccount, Name: "Home"}},
		zones:    map[string][]CloudZone{testAccount: {{ID: testZone, Name: "Example.TEST", Status: "active"}}},
	}
}

func (d *fakeDirectory) seen(env core.Env, ref, call string) {
	v, _ := env.Secrets.Get(context.Background(), ref)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tokens = append(d.tokens, v)
	d.calls = append(d.calls, call)
}

func (d *fakeDirectory) Accounts(_ context.Context, _ core.Env, token string) (CloudAccess, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tokens = append(d.tokens, token) // the token itself: nothing is sealed yet
	d.calls = append(d.calls, "accounts")
	return CloudAccess{Accounts: append([]CloudAccount{}, d.accounts...), Missing: d.missing, AccountUnknown: d.unknown}, d.err
}
func (d *fakeDirectory) Zones(_ context.Context, env core.Env, ref, account string) ([]CloudZone, []string, error) {
	d.seen(env, ref, "zones:"+account)
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]CloudZone{}, d.zones[account]...), d.zoneMiss, d.err
}
func (d *fakeDirectory) Probe(_ context.Context, env core.Env, ref, _, zone string, relay, inbound bool) ([]string, error) {
	call := "probe:" + zone
	if relay {
		call += ":send"
	}
	if inbound {
		call += ":inbound"
	}
	d.seen(env, ref, call)
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.probe, d.err
}

// signIn signs the flow in with the fixture token and chooses the zone.
func signIn(w *Wizard, ctx context.Context, env core.Env, who, id string) error {
	if w.options.Directory == nil {
		w.options.Directory = newDirectory()
	}
	if _, err := w.Connect(ctx, env, who, id, fixtureToken); err != nil {
		return err
	}
	_, err := w.Zones(ctx, env, who, id, testAccount, testZone)
	return err
}

// permissions is the own-domain route's account step: sign in, then bind.
func permissions(w *Wizard, ctx context.Context, env core.Env, who, id, account, zone string) ([]Permission, error) {
	if err := signIn(w, ctx, env, who, id); err != nil {
		return nil, err
	}
	return w.Permissions(ctx, env, who, id, account, zone)
}
