package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/relay"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

// a Cloudflare token deleted or rolled in the dashboard is noticed
// where it is used, shown as one state on the kept setup, and one
// replacement fixes everything that used it.

const newToken = "replacement-value"

// countingKV counts the writes per module (hibernation: a state that does
// not change writes nothing).
type countingKV struct {
	core.KV
	mu   sync.Mutex
	puts map[string]int
}

func (c *countingKV) Put(ctx context.Context, module, key string, v any) error {
	c.mu.Lock()
	c.puts[module]++
	c.mu.Unlock()
	return c.KV.Put(ctx, module, key, v)
}

func (c *countingKV) Keys(ctx context.Context, module, prefix string) ([]string, error) {
	return c.KV.(core.KeyLister).Keys(ctx, module, prefix)
}

// keptWrites starts counting the kept records' writes.
func keptWrites(r *removal) func() int {
	c := &countingKV{KV: r.env.KV, puts: map[string]int{}}
	r.env.KV = c
	return func() int {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.puts[keptModule]
	}
}

func changeOf(target string) core.Change { return core.Change{ID: target, Target: target} }

func logTo(r *removal) *bytes.Buffer {
	var buf bytes.Buffer
	r.env.Log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &buf
}

// noSecret fails when a token reaches the kept record, a view or the log.
func noSecret(t *testing.T, r removal, log *bytes.Buffer) {
	t.Helper()
	raw, _ := json.Marshal(r.record(t))
	list, _ := r.s.Status(context.Background(), r.env)
	view, _ := json.Marshal(list)
	for _, secret := range []string{"fixture-value", newToken} {
		if strings.Contains(string(raw), secret) || strings.Contains(string(view), secret) || strings.Contains(log.String(), secret) {
			t.Fatalf("a token leaked into the record, the view or the log")
		}
	}
}

func TestRelayLoginRefusedMarksTheSetupAndAcceptedClearsIt(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	log := logTo(&r)
	if v, _ := r.s.Status(ctx, r.env); v.Setups[0].TokenInvalid || !v.Setups[0].Relay {
		t.Fatalf("a fresh setup: %+v", v.Setups[0])
	}
	// 535 from smtp.mx.cloudflare.net: the relay reports a refused login.
	r.s.RelayToken(ctx, r.env, true)
	if !r.record(t).TokenInvalid {
		t.Fatal("a refused relay login did not mark the setup")
	}
	v, _ := r.s.Status(ctx, r.env)
	if !v.Setups[0].TokenInvalid {
		t.Fatal("the Overview does not see the refused token")
	}
	// The same state again (every queued message retried): no write.
	writes := keptWrites(&r)
	for range 5 {
		r.s.RelayToken(ctx, r.env, true)
	}
	if n := writes(); n != 0 {
		t.Fatalf("an unchanged state wrote %d times", n)
	}
	// Accepted again (someone restored the token): cleared.
	r.s.RelayToken(ctx, r.env, false)
	if r.record(t).TokenInvalid {
		t.Fatal("an accepted login did not clear the state")
	}
	noSecret(t, r, log)
}

func TestCloudflare401DuringSyncMarksTheToken(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	log := logTo(&r)
	r.cloud.revoked = true
	v, err := r.s.Sync(ctx, r.env, r.id, false)
	if err != nil || v.Last == nil || v.Last.CauseKey != "mail.inbound.cause.token" {
		t.Fatalf("sync with a revoked token: %+v %v", v.Last, err)
	}
	if !r.record(t).TokenInvalid {
		t.Fatal("a 401 confirmed by the verify endpoint did not mark the setup")
	}
	if list, _ := r.s.Status(ctx, r.env); !list.Setups[0].TokenInvalid {
		t.Fatal("the Overview does not see it")
	}
	if d := r.s.InvalidDomains(ctx, r.env); strings.Join(d, ",") != "example.test" {
		t.Fatalf("diagnosis domains: %v", d)
	}
	noSecret(t, r, log)
}

func TestMissingPermissionIsNotADeadToken(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	r.cloud.fail = map[string][2]int{"POST /zones/" + testZone + "/email/routing/rules": {403, 10000}}
	r.s.reader = &mailboxes{users: users("alice@example.test", "bob@example.test")}
	if v, err := r.s.Sync(ctx, r.env, r.id, false); err != nil || v.Last == nil || v.Last.CauseKey != "mail.inbound.cause.token" {
		t.Fatalf("a refused write: %+v %v", v.Last, err)
	}
	if r.record(t).TokenInvalid {
		t.Fatal("a refused write with an active token was taken for a dead token")
	}
}

func TestReplacementFixesEverythingThatUsedTheToken(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	log := logTo(&r)
	r.cloud.revoked = true
	if _, err := r.s.Sync(ctx, r.env, r.id, false); err != nil {
		t.Fatal(err)
	}
	r.s.RelayToken(ctx, r.env, true)
	if !r.record(t).TokenInvalid {
		t.Fatal("not marked")
	}
	// The administrator creates a new token and enters it once.
	r.cloud.revoked, r.cloud.token = false, newToken
	v, err := r.s.SetToken(ctx, r.env, r.id, newToken)
	if err != nil {
		t.Fatalf("replacement: %v", err)
	}
	if v.TokenInvalid || r.record(t).TokenInvalid {
		t.Fatal("the replacement did not clear the state")
	}
	// The relay's SMTP password is the new token: MailPlus's next retry
	// logs in with it (the relay reads it for every message).
	if got, _ := r.env.Secrets.Get(ctx, relay.TokenSecretKey); got != newToken {
		t.Fatal("the relay still logs in with the old token")
	}
	if got, _ := r.env.Secrets.Get(ctx, r.record(t).TokenRef); got != newToken {
		t.Fatal("the kept token was not replaced")
	}
	// The sync works again with it.
	if v, err := r.s.Sync(ctx, r.env, r.id, false); err != nil || v.Last.State != "done" {
		t.Fatalf("sync after the replacement: %+v %v", v.Last, err)
	}
	// The removal answers the journal's sign-in reference with the new
	// token (the alias): every Cloudflare step is undone with it.
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal == nil || view.Removal.State != "done" {
		t.Fatalf("removal after the replacement: %+v %v", view.Removal, err)
	}
	if len(r.cloud.rules) != 0 || len(r.cloud.workers) != 0 || len(r.cloud.services) != 0 {
		t.Fatal("the removal left this setup's resources")
	}
	for _, secret := range []string{"fixture-value", newToken} {
		if strings.Contains(log.String(), secret) {
			t.Fatal("a token reached the log")
		}
	}
}

func TestReplacementNamesEveryMissingPermission(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	r.s.RelayToken(ctx, r.env, true)
	r.cloud.token = newToken
	r.cloud.fail = map[string][2]int{
		"GET /accounts/" + testAccount + "/workers/scripts":                 {403, 10000},
		"GET /accounts/" + testAccount + "/connectivity/directory/services": {403, 10000},
	}
	_, err := r.s.SetToken(ctx, r.env, r.id, newToken)
	var missing setup.PermissionsMissing
	if !errors.As(err, &missing) || strings.Join(missing.Codes, ",") != setup.PermWorkersEdit+","+setup.PermVPCAdmin {
		t.Fatalf("missing permissions: %v", err)
	}
	// Nothing changed: the old token stays, the state stays.
	if got, _ := r.env.Secrets.Get(ctx, relay.TokenSecretKey); got != "fixture-value" {
		t.Fatal("a refused replacement reached the relay")
	}
	if rec := r.record(t); !rec.TokenInvalid || rec.TokenRef == keptTokenRef(r.id) {
		t.Fatal("a refused replacement changed the record")
	}
	// A dead replacement is refused as invalid, and nothing is sealed.
	r.cloud.fail, r.cloud.revoked = nil, true
	if _, err := r.s.SetToken(ctx, r.env, r.id, newToken); !errors.Is(err, setup.ErrTokenInvalid) {
		t.Fatalf("a dead replacement: %v", err)
	}
	if got, _ := r.env.Secrets.Get(ctx, keptTokenRef(r.id)); got != "" {
		t.Fatal("a dead replacement was sealed")
	}
}

func TestNeededPermissionsFollowTheJournal(t *testing.T) {
	send := keptRecord{Applied: []setup.AppliedChange{{Change: changeOf("homekeeper.relay")}, {Change: changeOf("cloudflare.dns")}}}
	if got := strings.Join(neededPermissions(send), ","); got != "zoneRead,dnsEdit,sendingEdit" {
		t.Fatalf("send-only: %s", got)
	}
	receive := keptRecord{Inbound: &keptInbound{Mode: setup.ReceiveDomain}}
	if got := strings.Join(neededPermissions(receive), ","); got != "zoneRead,routingRulesEdit,workersEdit,vpcAdmin" {
		t.Fatalf("receive-only: %s", got)
	}
}

func TestCloudflare401DuringRemovalMarksTheToken(t *testing.T) {
	ctx := context.Background()
	r := removable(t, newInboundCloud(), setup.ReceiveAddresses, "alice@example.test")
	log := logTo(&r)
	r.cloud.revoked = true
	view, err := r.s.Remove(ctx, r.env, r.id, false, false)
	if err != nil || view.Removal == nil || view.Removal.State != "failed" || view.Removal.CauseKey != "mail.inbound.cause.token" {
		t.Fatalf("removal with a revoked token: %+v %v", view.Removal, err)
	}
	if !r.record(t).TokenInvalid {
		t.Fatal("a 401 during the removal did not mark the setup")
	}
	noSecret(t, r, log)
}
