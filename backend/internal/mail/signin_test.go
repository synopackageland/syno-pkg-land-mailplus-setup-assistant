package mail

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/cloudflare"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

// loopbackCloudflare is a fake Cloudflare API v4 on 127.0.0.1. refuse maps a
// path to the HTTP status it answers with (401 token refused, 403 permission).
type loopbackCloudflare struct {
	mu sync.Mutex
	// accountTokens maps an account-owned token to the account that owns it;
	// the user verify endpoint refuses those (HTTP 401) and the owner's
	// account verify endpoint accepts them.
	accountTokens map[string]string
	// verifyStatus, when set, is what every account verify endpoint answers.
	verifyStatus int
	// code is the Cloudflare error code of a refusal (default 10000).
	code     map[string]int
	refuse   map[string]int
	accounts []map[string]string
	zones    []map[string]any
	paths    []string
}

func (f *loopbackCloudflare) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, r.URL.Path+"?"+r.URL.RawQuery)
	w.Header().Set("Content-Type", "application/json")
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	owner, accountToken := f.accountTokens[token]
	deny := func(status int) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}`))
	}
	if token != "fixture-value" && !accountToken {
		deny(401)
		return
	}
	if accountToken && r.URL.Path == "/user/tokens/verify" {
		deny(401)
		return
	}
	if accountToken && strings.HasPrefix(r.URL.Path, "/accounts/") && strings.HasSuffix(r.URL.Path, "/tokens/verify") {
		if f.verifyStatus != 0 {
			deny(f.verifyStatus)
			return
		}
		if r.URL.Path != "/accounts/"+owner+"/tokens/verify" {
			deny(401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "acct-token", "status": "active"}})
		return
	}
	if status := f.refuse[r.URL.Path]; status != 0 {
		w.WriteHeader(status)
		code := 10000 // Cloudflare's missing-permission answer: HTTP 403, code 10000
		if status >= 500 {
			code = 10001
		}
		if c := f.code[r.URL.Path]; c != 0 {
			code = c
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": code, "message": "refused"}}})
		return
	}
	var result any
	switch {
	case r.URL.Path == "/user/tokens/verify":
		result = map[string]string{"id": "token", "status": "active"}
	case r.URL.Path == "/accounts":
		result = f.accounts
	case r.URL.Path == "/zones":
		out := []map[string]any{}
		for _, z := range f.zones {
			if id := r.URL.Query().Get("account.id"); id == "" || z["account"].(map[string]string)["id"] == id {
				out = append(out, z)
			}
		}
		result = out
	case r.URL.Path == "/zones/"+testZone+"/dns_records", r.URL.Path == "/zones/"+testZone+"/email/sending/subdomains",
		r.URL.Path == "/zones/"+testZone+"/email/routing/rules", r.URL.Path == "/accounts/"+testAccount+"/workers/scripts",
		r.URL.Path == "/accounts/"+testAccount+"/connectivity/directory/services", r.URL.Path == "/accounts/"+testAccount+"/cfd_tunnel":
		result = []any{}
	case r.URL.Path == "/zones/"+testZone+"/email/routing":
		result = map[string]any{"name": "example.test", "enabled": false}
	default:
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":7003,"message":"not found"}]}`))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
}

// accountsOf unpacks Accounts for the assertions.
// Accounts takes the token itself (nothing is sealed before a verify); the
// tests keep their fixtures sealed and read them here.
func accountsOf(adapter *cloudflareAdapter, ctx context.Context, env core.Env, ref string) ([]setup.CloudAccount, []string, error) {
	a, err := accessOf(adapter, ctx, env, ref)
	return a.Accounts, a.Missing, err
}

func accessOf(adapter *cloudflareAdapter, ctx context.Context, env core.Env, ref string) (setup.CloudAccess, error) {
	token, err := env.Secrets.Get(ctx, ref)
	if err != nil {
		return setup.CloudAccess{}, err
	}
	return adapter.Accounts(ctx, env, token)
}

func signInFixture(t *testing.T, token string) (*cloudflareAdapter, *loopbackCloudflare, string) {
	t.Helper()
	fake := &loopbackCloudflare{refuse: map[string]int{}, code: map[string]int{}, accountTokens: map[string]string{},
		accounts: []map[string]string{{"id": testAccount, "name": "Home"}},
		zones: []map[string]any{
			{"id": testZone, "name": "example.test", "status": "active", "account": map[string]string{"id": testAccount, "name": "Home"}},
			{"id": "cccccccccccccccccccccccccccccccc", "name": "pending.test", "status": "pending", "account": map[string]string{"id": testAccount, "name": "Home"}},
			{"id": "dddddddddddddddddddddddddddddddd", "name": "foreign.test", "status": "active", "account": map[string]string{"id": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "name": "Other"}},
		}}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	adapter := &cloudflareAdapter{newClient: func(cfg cloudflare.Config) (*cloudflare.Client, error) {
		cfg.BaseURL = server.URL // loopback HTTP only
		return cloudflare.New(cfg)
	}}
	return adapter, fake, token
}

func TestSignInAgainstLoopbackCloudflare(t *testing.T) {
	ctx := context.Background()
	adapter, fake, _ := signInFixture(t, "fixture-value")
	env := wiringEnv(t)
	ref := "secret:mail.setup.flow.token"
	if err := env.Secrets.Put(ctx, ref, "fixture-value"); err != nil {
		t.Fatal(err)
	}
	accounts, missing, err := accountsOf(adapter, ctx, env, ref)
	if err != nil || len(missing) != 0 || len(accounts) != 1 || accounts[0].ID != testAccount || accounts[0].Name != "Home" {
		t.Fatalf("accounts: %+v %v %v", accounts, missing, err)
	}
	zones, missing, err := adapter.Zones(ctx, env, ref, testAccount)
	if err != nil || len(missing) != 0 || len(zones) != 2 {
		t.Fatalf("zones (the other account's zone must not be offered): %+v %v", zones, err)
	}
	if !strings.Contains(strings.Join(fake.paths, " "), "/zones?account.id="+testAccount) {
		t.Fatalf("zones not filtered by account: %v", fake.paths)
	}
	if missing, err = adapter.Probe(ctx, env, ref, testAccount, testZone, true, false); err != nil || len(missing) != 0 {
		t.Fatalf("probe: %v %v", missing, err)
	}

	// /accounts refused: the zones' accounts stand in.
	fake.refuse["/accounts"] = 403
	if accounts, missing, err = accountsOf(adapter, ctx, env, ref); err != nil || len(missing) != 0 || len(accounts) != 2 {
		t.Fatalf("fallback accounts: %+v %v %v", accounts, missing, err)
	}
	// Zone Read refused.
	fake.refuse["/zones"] = 403
	if _, missing, err = accountsOf(adapter, ctx, env, ref); err != nil || len(missing) != 1 || missing[0] != setup.PermZoneRead {
		t.Fatalf("zone read: %v %v", missing, err)
	}
	if _, missing, err = adapter.Zones(ctx, env, ref, testAccount); err != nil || len(missing) != 1 || missing[0] != setup.PermZoneRead {
		t.Fatalf("zones zone read: %v %v", missing, err)
	}
	// DNS and Email Sending refused: both named; receive only reads DNS alone.
	fake.refuse["/zones/"+testZone+"/dns_records"] = 403
	fake.refuse["/zones/"+testZone+"/email/sending/subdomains"] = 403
	if missing, err = adapter.Probe(ctx, env, ref, testAccount, testZone, true, false); err != nil || strings.Join(missing, ",") != setup.PermDNSEdit+","+setup.PermSendingEdit {
		t.Fatalf("probe refused: %v %v", missing, err)
	}
	if missing, err = adapter.Probe(ctx, env, ref, testAccount, testZone, false, false); err != nil || strings.Join(missing, ",") != setup.PermDNSEdit {
		t.Fatalf("receive probe: %v %v", missing, err)
	}
	// Anything but a clear refusal is unknown: unavailable, not "missing".
	fake.refuse["/zones/"+testZone+"/dns_records"] = 500
	if _, err = adapter.Probe(ctx, env, ref, testAccount, testZone, false, false); !errors.Is(err, setup.ErrCloudflareUnavailable) {
		t.Fatalf("server error: %v", err)
	}
}

func TestSignInRefusedTokenIsInvalid(t *testing.T) {
	ctx := context.Background()
	adapter, _, _ := signInFixture(t, "")
	env := wiringEnv(t)
	ref := "secret:mail.setup.flow.token"
	if err := env.Secrets.Put(ctx, ref, "revoked-value"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := accountsOf(adapter, ctx, env, ref); !errors.Is(err, setup.ErrTokenInvalid) {
		t.Fatalf("refused token: %v", err)
	}
	// Only a verify endpoint says "invalid": a later read refused with 401 is unavailable.
	if _, _, err := adapter.Zones(ctx, env, ref, testAccount); !errors.Is(err, setup.ErrCloudflareUnavailable) {
		t.Fatalf("refused token on zones: %v", err)
	}
	// No token at all is not one, and makes no request.
	if _, _, err := accountsOf(adapter, ctx, env, "secret:none"); !errors.Is(err, setup.ErrTokenInvalid) {
		t.Fatalf("nothing sealed: %v", err)
	}
}

// An account-owned token (the account token URL creates one) is verified
// through /accounts/{id}/tokens/verify of the account that owns it.
func TestSignInWithAnAccountOwnedToken(t *testing.T) {
	ctx := context.Background()
	adapter, fake, _ := signInFixture(t, "")
	other := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	fake.accounts = append(fake.accounts, map[string]string{"id": other, "name": "Other"})
	env := wiringEnv(t)
	for _, token := range []string{"cfat_scannable-value", "older-account-value"} {
		fake.accountTokens[token] = testAccount
		ref := "secret:mail.setup.flow." + token
		if err := env.Secrets.Put(ctx, ref, token); err != nil {
			t.Fatal(err)
		}
		fake.paths = nil
		accounts, missing, err := accountsOf(adapter, ctx, env, ref)
		if err != nil || len(missing) != 0 || len(accounts) != 1 || accounts[0].ID != testAccount {
			t.Fatalf("%s: %+v %v %v", token, accounts, missing, err)
		}
		joined := strings.Join(fake.paths, " ")
		if !strings.Contains(joined, "/accounts/"+testAccount+"/tokens/verify") {
			t.Fatalf("%s: not verified through the account endpoint: %v", token, fake.paths)
		}
		// The user endpoint is always asked first: only a verify endpoint decides.
		if !strings.Contains(joined, "/user/tokens/verify") {
			t.Fatalf("%s: user endpoint not asked: %v", token, fake.paths)
		}
		// The token works for the zones and the probe like a user token.
		if zones, _, err := adapter.Zones(ctx, env, ref, testAccount); err != nil || len(zones) != 2 {
			t.Fatalf("%s zones: %+v %v", token, zones, err)
		}
	}
	// /accounts refused: the zones' account stands in, and verifies it.
	fake.refuse["/accounts"] = 403
	if accounts, _, err := accountsOf(adapter, ctx, env, "secret:mail.setup.flow.cfat_scannable-value"); err != nil || len(accounts) != 1 || accounts[0].ID != testAccount {
		t.Fatalf("zones' account: %+v %v", accounts, err)
	}
	delete(fake.refuse, "/accounts")
	// No account verifies it, every refusal clear: invalid.
	fake.accountTokens["cfat_scannable-value"] = "ffffffffffffffffffffffffffffffff"
	if _, _, err := accountsOf(adapter, ctx, env, "secret:mail.setup.flow.cfat_scannable-value"); !errors.Is(err, setup.ErrTokenInvalid) {
		t.Fatalf("owned by no listed account: %v", err)
	}
	// An unclear answer from an account verify endpoint: unavailable, never a guess.
	fake.accountTokens["cfat_scannable-value"] = testAccount
	fake.verifyStatus = 500
	if _, _, err := accountsOf(adapter, ctx, env, "secret:mail.setup.flow.cfat_scannable-value"); !errors.Is(err, setup.ErrCloudflareUnavailable) {
		t.Fatalf("server error: %v", err)
	}
	fake.verifyStatus = 0
	// A token Cloudflare knows nowhere: the user endpoint and /accounts refuse it.
	if err := env.Secrets.Put(ctx, "secret:mail.setup.flow.unknown", "cfat_unknown"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := accountsOf(adapter, ctx, env, "secret:mail.setup.flow.unknown"); !errors.Is(err, setup.ErrTokenInvalid) {
		t.Fatalf("unknown account token: %v", err)
	}
}

// After a successful verify, a sign-in read refused with HTTP 403
// is a missing permission whatever its code (9109 included), never "token
// invalid"; 401 or anything else on such a read is unavailable.
func TestSignInReadsAfterVerify(t *testing.T) {
	ctx := context.Background()
	adapter, fake, _ := signInFixture(t, "")
	env := wiringEnv(t)
	ref := "secret:mail.setup.flow.token"
	if err := env.Secrets.Put(ctx, ref, "fixture-value"); err != nil {
		t.Fatal(err)
	}
	// 403 {code: 9109} on /accounts: the zones' accounts stand in.
	fake.refuse["/accounts"], fake.code["/accounts"] = 403, 9109
	if accounts, missing, err := accountsOf(adapter, ctx, env, ref); err != nil || len(missing) != 0 || len(accounts) != 2 {
		t.Fatalf("/accounts 9109: %+v %v %v", accounts, missing, err)
	}
	// 403 {code: 9109} on dns_records: DNS Edit is missing.
	dns := "/zones/" + testZone + "/dns_records"
	fake.refuse[dns], fake.code[dns] = 403, 9109
	if missing, err := adapter.Probe(ctx, env, ref, testAccount, testZone, false, false); err != nil || len(missing) != 1 || missing[0] != setup.PermDNSEdit {
		t.Fatalf("dns_records 9109: %v %v", missing, err)
	}
	// 401 on a read after verify: unavailable, not invalid.
	fake.refuse[dns] = 401
	if _, err := adapter.Probe(ctx, env, ref, testAccount, testZone, false, false); !errors.Is(err, setup.ErrCloudflareUnavailable) {
		t.Fatalf("dns_records 401: %v", err)
	}
	fake.refuse["/zones"] = 401
	if _, _, err := adapter.Zones(ctx, env, ref, testAccount); !errors.Is(err, setup.ErrCloudflareUnavailable) {
		t.Fatalf("zones 401: %v", err)
	}
	if _, _, err := accountsOf(adapter, ctx, env, ref); !errors.Is(err, setup.ErrCloudflareUnavailable) {
		t.Fatalf("accounts with zones 401: %v", err)
	}
}

// Accepted, /accounts refused, no zone yet: account unknown.
func TestSignInAccountUnknownWithoutZones(t *testing.T) {
	ctx := context.Background()
	adapter, fake, _ := signInFixture(t, "")
	fake.zones = nil
	fake.refuse["/accounts"] = 403
	env := wiringEnv(t)
	ref := "secret:mail.setup.flow.token"
	if err := env.Secrets.Put(ctx, ref, "fixture-value"); err != nil {
		t.Fatal(err)
	}
	access, err := accessOf(adapter, ctx, env, ref)
	if err != nil || !access.AccountUnknown || len(access.Accounts) != 0 || len(access.Missing) != 0 {
		t.Fatalf("user token (verified): %+v %v", access, err)
	}
	// An account-owned token with no account to verify it against: no verify
	// endpoint accepted it, so it is invalid (not "account unknown").
	fake.accountTokens["cfat_new"] = testAccount
	if err := env.Secrets.Put(ctx, "secret:mail.setup.flow.acct", "cfat_new"); err != nil {
		t.Fatal(err)
	}
	if access, err = accessOf(adapter, ctx, env, "secret:mail.setup.flow.acct"); !errors.Is(err, setup.ErrTokenInvalid) {
		t.Fatalf("account token without an account: %+v %v", access, err)
	}
}

// NAS, build 20: Cloudflare's exact answers for a token that is not one.
// A token of the wrong shape: HTTP 400, code 6003 with 6111 in its chain, on
// the verify endpoint and on /accounts alike; it is invalid at once, with no
// account probe. A well-formed unknown token: HTTP 401, code 1000; nothing
// accepts it anywhere, so it is invalid too.
func TestSignInMalformedAndUnknownTokensAreInvalid(t *testing.T) {
	ctx := context.Background()
	malformed := `{"success":false,"errors":[{"code":6003,"message":"Invalid request headers","error_chain":[{"code":6111,"message":"Invalid format for Authorization header"}]}],"messages":[],"result":null}`
	unknown := `{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}],"messages":[],"result":null}`
	for _, tc := range []struct {
		name, token, body string
		status            int
		probes            bool // whether /accounts is asked after verify
	}{
		{"malformed", "fake-not-a-real-token-0000", malformed, 400, false},
		{"unknown", "0123456789abcdefghijklmnopqrstuvwxyzABCD", unknown, 401, true},
	} {
		var paths []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			paths = append(paths, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		adapter := &cloudflareAdapter{newClient: func(cfg cloudflare.Config) (*cloudflare.Client, error) {
			cfg.BaseURL = server.URL
			return cloudflare.New(cfg)
		}}
		env := wiringEnv(t)
		ref := "secret:mail.setup.flow.token"
		if err := env.Secrets.Put(ctx, ref, tc.token); err != nil {
			t.Fatal(err)
		}
		if _, err := accessOf(adapter, ctx, env, ref); !errors.Is(err, setup.ErrTokenInvalid) {
			t.Fatalf("%s: %v (paths %v)", tc.name, err, paths)
		}
		if paths[0] != "/user/tokens/verify" {
			t.Fatalf("%s: verify not asked first: %v", tc.name, paths)
		}
		if probed := len(paths) > 1; probed != tc.probes {
			t.Fatalf("%s: account probe %v: %v", tc.name, probed, paths)
		}
		server.Close()
	}
}

// An unclear Cloudflare answer is Cloudflare-unavailable, never the
// "missing integration" text of setup.ErrUnavailable.
func TestSignInUnclearAnswerIsCloudflareUnavailable(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(502)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10001,"message":"bad gateway"}]}`))
	}))
	defer server.Close()
	adapter := &cloudflareAdapter{newClient: func(cfg cloudflare.Config) (*cloudflare.Client, error) {
		cfg.BaseURL = server.URL
		return cloudflare.New(cfg)
	}}
	env := wiringEnv(t)
	if err := env.Secrets.Put(ctx, "secret:mail.setup.flow.token", "fixture-value"); err != nil {
		t.Fatal(err)
	}
	_, err := accessOf(adapter, ctx, env, "secret:mail.setup.flow.token")
	if !errors.Is(err, setup.ErrCloudflareUnavailable) || errors.Is(err, setup.ErrUnavailable) {
		t.Fatalf("unclear: %v", err)
	}
}

// NAS, build 21: Cloudflare's exact answers for a well-formed unknown token:
// 401 {1000} on the user verify endpoint, 403 {9109} on /accounts and /zones.
// No verify endpoint accepted it: invalid, with no permission reported missing.
func TestSignInUnknownTokenWith9109ReadsIsInvalid(t *testing.T) {
	ctx := context.Background()
	verify := `{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}],"messages":[],"result":null}`
	reads := `{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}],"messages":[],"result":null}`
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/user/tokens/verify" || strings.HasSuffix(r.URL.Path, "/tokens/verify") {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(verify))
			return
		}
		w.WriteHeader(403)
		_, _ = w.Write([]byte(reads))
	}))
	defer server.Close()
	adapter := &cloudflareAdapter{newClient: func(cfg cloudflare.Config) (*cloudflare.Client, error) {
		cfg.BaseURL = server.URL
		return cloudflare.New(cfg)
	}}
	access, err := adapter.Accounts(ctx, wiringEnv(t), "abcdefghijklmnopqrstuvwxyz0123456789ABCE")
	if !errors.Is(err, setup.ErrTokenInvalid) || len(access.Missing) != 0 || len(access.Accounts) != 0 {
		t.Fatalf("unknown token: %+v %v (paths %v)", access, err, paths)
	}
	if paths[0] != "/user/tokens/verify" {
		t.Fatalf("verify not asked first: %v", paths)
	}
}

// Inbound adds one read per inbound permission group; a 403 names its code
// (the token link fills them all in, so a refusal means a replaced token).
func TestSignInProbeInbound(t *testing.T) {
	ctx := context.Background()
	adapter, fake, _ := signInFixture(t, "fixture-value")
	env := wiringEnv(t)
	ref := "secret:mail.setup.flow.token"
	if err := env.Secrets.Put(ctx, ref, "fixture-value"); err != nil {
		t.Fatal(err)
	}
	if missing, err := adapter.Probe(ctx, env, ref, testAccount, testZone, false, true); err != nil || len(missing) != 0 {
		t.Fatalf("inbound probe: %v %v", missing, err)
	}
	for path, code := range map[string]string{
		"/zones/" + testZone + "/email/routing":                         setup.PermZoneSettingsEdit,
		"/zones/" + testZone + "/email/routing/rules":                   setup.PermRoutingRulesEdit,
		"/accounts/" + testAccount + "/workers/scripts":                 setup.PermWorkersEdit,
		"/accounts/" + testAccount + "/connectivity/directory/services": setup.PermVPCAdmin,
		"/accounts/" + testAccount + "/cfd_tunnel":                      setup.PermTunnelRead,
	} {
		fake.refuse[path] = 403
		missing, err := adapter.Probe(ctx, env, ref, testAccount, testZone, false, true)
		if err != nil || len(missing) != 1 || missing[0] != code {
			t.Fatalf("%s: %v %v", path, missing, err)
		}
		delete(fake.refuse, path)
	}
	fake.refuse["/accounts/"+testAccount+"/cfd_tunnel"] = 500
	if _, err := adapter.Probe(ctx, env, ref, testAccount, testZone, false, true); !errors.Is(err, setup.ErrCloudflareUnavailable) {
		t.Fatalf("server error: %v", err)
	}
}

// Email Sending on Workers Free: the sign-in check names the plan in plain
// words before any preview, instead of a missing permission or "unavailable".
func TestSignInProbeSendingPlan(t *testing.T) {
	ctx := context.Background()
	adapter, fake, _ := signInFixture(t, "fixture-value")
	env := wiringEnv(t)
	ref := "secret:mail.setup.flow.token"
	if err := env.Secrets.Put(ctx, ref, "fixture-value"); err != nil {
		t.Fatal(err)
	}
	fake.refuse["/zones/"+testZone+"/email/sending/subdomains"] = 402
	if missing, err := adapter.Probe(ctx, env, ref, testAccount, testZone, true, false); !errors.Is(err, setup.ErrSendingPlan) || len(missing) != 0 {
		t.Fatalf("plan refusal: %v %v", missing, err)
	}
	// Receiving alone never reads Email Sending: the plan does not matter.
	if missing, err := adapter.Probe(ctx, env, ref, testAccount, testZone, false, false); err != nil || len(missing) != 0 {
		t.Fatalf("receive only: %v %v", missing, err)
	}
}

// A 403 whose code is not a documented authorization refusal (for example a
// product that is not enabled) is unknown: never listed as missing.
func TestSignInProbeOtherForbiddenIsUnknown(t *testing.T) {
	ctx := context.Background()
	adapter, fake, _ := signInFixture(t, "fixture-value")
	env := wiringEnv(t)
	ref := "secret:mail.setup.flow.token"
	if err := env.Secrets.Put(ctx, ref, "fixture-value"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/zones/" + testZone + "/dns_records",
		"/accounts/" + testAccount + "/connectivity/directory/services",
		"/zones/" + testZone + "/email/routing",
	} {
		fake.refuse[path], fake.code[path] = 403, 1002
		missing, err := adapter.Probe(ctx, env, ref, testAccount, testZone, false, true)
		if !errors.Is(err, setup.ErrCloudflareUnavailable) || len(missing) != 0 {
			t.Fatalf("%s: %v %v", path, missing, err)
		}
		delete(fake.refuse, path)
		delete(fake.code, path)
	}
}
