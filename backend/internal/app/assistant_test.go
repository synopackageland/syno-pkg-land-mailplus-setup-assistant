package app

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/synopackageland/syno-pkg-land-sdk/api"
)

func TestWorkerAuthorityDetailsSurviveCGIBridge(t *testing.T) {
	cfg := testConfig(t)
	called := false
	cfg.coreTransport = func(context.Context, api.Caller, string, json.RawMessage) (any, error) {
		called = true
		return decodeCoreReply([]byte(`{"error":{"code":"authority_required","message":"operation unavailable","details":{"profile":"mail-read"}}}`))
	}
	code, response := call(t, cfg, alice, "mail.relay.status", `{}`)
	if code != "authority_required" {
		t.Fatalf("authority code lost: %s", code)
	}
	details := response["error"].(map[string]any)["details"].(map[string]any)
	if details["profile"] != "mail-read" {
		t.Fatal("authority profile lost")
	}
	called = false
	code, _ = call(t, cfg, bob, "mail.relay.status", `{}`)
	if code != "admin_required" || called {
		t.Fatal("non-administrator reached the worker")
	}
}
