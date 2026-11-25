package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	appapi "SynoMailPlusSetupAssistant/internal/api"
	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/core/dsmauthority"
	"SynoMailPlusSetupAssistant/internal/worker"
	"github.com/synopackageland/syno-pkg-land-sdk/api"
	"github.com/synopackageland/syno-pkg-land-sdk/delegate"
)

type grantExecutor struct {
	grants  map[string]delegate.Grant
	counter int
	revoked int
	badPins bool
}

func (f *grantExecutor) Call(_ context.Context, op string, auth map[string]string, p any, out any) error {
	if op != "webapi.call" && (auth["dsm_cookie"] != "fixture-session" || auth["dsm_synotoken"] != "fixture-token" || auth["remote_addr"] == "") {
		return &api.Error{Code: "session_required"}
	}
	var result any
	switch op {
	case "status":
		digest := "fixture-executor"
		if f.badPins {
			digest = "different-executor"
		}
		result = map[string]any{"ready": true, "state": "ready", "version": "fixture", "disabled": false, "allowed": true,
			"executor_digest": digest, "policy_digest": "fixture-policy"}
	case "delegate.create":
		values := p.(map[string]any)
		if values["lifetime"] != "until-revoked" || values["job_id"] != nil {
			return &api.Error{Code: "INVALID_REQUEST"}
		}
		f.counter++
		g := delegate.Grant{DelegationID: fmt.Sprintf("%064x", f.counter), Scope: values["scope"].(string),
			Lifetime: "until-revoked", Subject: delegate.Subject{Username: "alice", UID: json.Number("1024")}}
		f.grants[g.DelegationID] = g
		result = g
	case "delegate.list":
		grants := []delegate.Grant{}
		for _, g := range f.grants {
			grants = append(grants, g)
		}
		result = map[string]any{"delegations": grants}
	case "delegate.revoke":
		id := p.(map[string]string)["delegation_id"]
		g := f.grants[id]
		g.Revoked = true
		f.grants[id] = g
		f.revoked++
		return nil
	case "webapi.call":
		if auth != nil {
			return fmt.Errorf("worker retained a live session")
		}
		id := p.(map[string]any)["delegation_id"].(string)
		g, ok := f.grants[id]
		if !ok || g.Revoked {
			return &api.Error{Code: "DELEGATION_DENIED"}
		}
		result = map[string]any{"success": true, "data": map[string]any{"enabled": true}}
	default:
		return fmt.Errorf("unexpected executor operation")
	}
	b, _ := json.Marshal(result)
	return json.Unmarshal(b, out)
}

func TestAuthorityAdminGrantLifecycle(t *testing.T) {
	ctx := context.Background()
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	executor := &grantExecutor{grants: map[string]delegate.Grant{}}
	authority := &core.Authority{Store: store, Client: executor}
	host, err := core.NewHost(store, core.Env{DSM: authority.DSM("")})
	if err != nil {
		t.Fatal(err)
	}
	host.Authority = authority
	daemon := &worker.Worker{Host: host}
	cfg := testConfig(t)
	cfg.WebAPIExecutor, cfg.ExecutorDigest, cfg.PolicyDigest = executor, "fixture-executor", "fixture-policy"
	cfg.coreTransport = func(ctx context.Context, c api.Caller, method string, raw json.RawMessage) (any, error) {
		if strings.Contains(string(raw), "fixture-session") || strings.Contains(string(raw), "fixture-token") {
			t.Fatal("live authentication reached the daemon")
		}
		return daemon.Invoke(ctx, c.User(), method, raw)
	}
	permissions, err := appapi.Permissions()
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(method, params string) (string, map[string]any) {
		req := apiRequest(method, params)
		req.AddCookie(&http.Cookie{Name: "id", Value: "fixture-session"})
		req.Header.Set("X-SYNO-TOKEN", "fixture-token")
		return serve(t, cfg, alice, req, permissions)
	}
	if code, _ := invoke("dsm.authority.grant", `{"profile":"mail-read","confirmed":false}`); code != "bad_request" {
		t.Fatalf("unconfirmed consent: %s", code)
	}
	if code, _ := invoke("dsm.authority.grant", `{"profile":"mail-read","confirmed":true,"username":"alice"}`); code != "bad_request" {
		t.Fatalf("request-selected identity: %s", code)
	}
	executor.badPins = true
	if code, _ := invoke("dsm.authority.grant", `{"profile":"mail-read","confirmed":true}`); code != "authority_required" {
		t.Fatalf("unapproved executor: %s", code)
	}
	if executor.counter != 0 {
		t.Fatal("grant created before pin approval")
	}
	executor.badPins = false
	code, response := invoke("dsm.authority.grant", `{"profile":"mail-read","confirmed":true}`)
	if code != "" {
		t.Fatalf("grant: %s %v", code, response)
	}
	id := response["data"].(map[string]any)["grantId"].(string)
	restarted := &core.Authority{Store: store, Client: executor}
	if err := restarted.DSM("").Call(ctx, "SYNO.Core.Package", "list", 2, nil, nil); err != nil {
		t.Fatalf("scheduled use after restart: %v", err)
	}
	code, response = invoke("dsm.authority.status", `{}`)
	if code != "" || !strings.Contains(fmt.Sprint(response), "granted") {
		t.Fatalf("Settings did not show live grant: %s %v", code, response)
	}
	code, response = invoke("dsm.authority.revoke", `{"profile":"mail-read","id":"`+id+`"}`)
	if code != "" || executor.revoked != 1 {
		t.Fatalf("protected revoke: %s %v", code, response)
	}
	if err := restarted.DSM("").Call(ctx, "SYNO.Core.Package", "list", 2, nil, nil); !errors.Is(err, core.ErrAuthorityRequired) {
		t.Fatalf("revoked evidence: %v", err)
	}
	code, response = invoke("dsm.authority.status", `{}`)
	if code != "" || strings.Contains(fmt.Sprint(response), "state:granted") {
		t.Fatalf("Settings claimed revoked grant active: %s %v", code, response)
	}
}

// grant and revoke take every declared profile and nothing else.
func TestAuthorityOperationEnumsNameEveryProfile(t *testing.T) {
	var doc struct {
		Operations map[string]struct {
			ParamsSchema struct {
				Properties map[string]struct {
					Enum []any `json:"enum"`
				} `json:"properties"`
			} `json:"paramsSchema"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(appapi.Operations(), &doc); err != nil {
		t.Fatal(err)
	}
	want := []string{}
	for name := range dsmauthority.Profiles() {
		want = append(want, name)
	}
	sort.Strings(want)
	for _, op := range []string{"dsm.authority.grant", "dsm.authority.revoke"} {
		got := []string{}
		for _, v := range doc.Operations[op].ParamsSchema.Properties["profile"].Enum {
			got = append(got, fmt.Sprint(v))
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s profile enum %v, want %v", op, got, want)
		}
	}
}
