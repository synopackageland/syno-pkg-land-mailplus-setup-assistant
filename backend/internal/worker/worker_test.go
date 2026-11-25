package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail"
	"SynoMailPlusSetupAssistant/internal/mail/diagnose"
	"SynoMailPlusSetupAssistant/internal/mail/relay"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

func newWorker(t *testing.T) (*Worker, *core.Store) {
	t.Helper()
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	d := diagnose.New(diagnose.Dependencies{})
	service := relay.New(store.DataDir)
	assistant := &mail.Assistant{Setup: setup.New(setup.Options{}), Diagnostics: d, Diagnose: &diagnose.Runner{D: d}, Relay: service}
	host, err := core.NewHost(store, core.Env{}, assistant.Services()...)
	if err != nil {
		t.Fatal(err)
	}
	return &Worker{Host: host, Mail: assistant}, store
}

func rpc(t *testing.T, w *Worker, owner, method, params string) (map[string]any, *core.RPCError) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/"+method, bytes.NewBufferString(params))
	if owner != "" {
		req.Header.Set(OwnerHeader, owner)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return nil, &core.RPCError{Code: http.StatusText(rec.Code)}
	}
	var reply struct {
		Result map[string]any `json:"result"`
		Error  *core.RPCError `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	return reply.Result, reply.Error
}

func TestOwnerIsRequiredAndUnknownMethodsRefused(t *testing.T) {
	w, _ := newWorker(t)
	if _, e := rpc(t, w, "", "mail.setup.start", `{}`); e == nil || e.Code != "Forbidden" {
		t.Fatalf("anonymous IPC accepted: %+v", e)
	}
	if _, e := rpc(t, w, "admin", "wizards.answer", `{}`); e == nil || e.Code != "not_found" {
		t.Fatalf("unknown method: %+v", e)
	}
	if _, e := rpc(t, w, "admin", "mail.setup.start", `{"extra":1}`); e == nil || e.Code != "bad_request" {
		t.Fatalf("unknown field accepted: %+v", e)
	}
}

func TestSignInNeverEchoesTheToken(t *testing.T) {
	w, store := newWorker(t)
	flow, e := rpc(t, w, "admin", "mail.setup.start", `{}`)
	if e != nil {
		t.Fatal(e)
	}
	id := flow["id"].(string)
	const token = "fixture-cloudflare-token-value"
	// This worker has no Cloudflare directory: the sign-in is unavailable,
	// with a fixed reason, before anything is sealed (the setup package's
	// tests cover sealing, promotion and deletion).
	result, e := rpc(t, w, "admin", "mail.setup.cloudflare", `{"id":"`+id+`","token":"`+token+`"}`)
	if e == nil || e.Code != "unavailable" || e.Details["reason"] != setup.ErrUnavailable.Error() || result != nil {
		t.Fatalf("sign-in without a directory: %+v %+v", result, e)
	}
	b, _ := json.Marshal(e)
	if strings.Contains(string(b), token) {
		t.Fatal("token echoed in an error")
	}
	var f setup.Flow
	if _, err := store.Get(context.Background(), "mail.setup", setup.FlowKey("admin"), &f); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(f)
	if strings.Contains(string(raw), token) {
		t.Fatal("token stored in the flow record")
	}
	// Another administrator cannot use or seal into this flow.
	if _, e := rpc(t, w, "other", "mail.setup.cloudflare", `{"id":"`+id+`","token":"x"}`); e == nil || e.Code != "not_found" {
		t.Fatalf("other administrator reached the flow: %+v", e)
	}
	for _, bad := range []string{`"with space"`, `""`} {
		if _, e := rpc(t, w, "admin", "mail.setup.cloudflare", `{"id":"`+id+`","token":`+bad+`}`); e == nil || e.Code != "bad_request" {
			t.Fatalf("malformed token %s accepted: %+v", bad, e)
		}
	}
	// The preview takes no token any more: one token, pasted once at sign-in.
	if _, e := rpc(t, w, "admin", "mail.setup.preview", `{"id":"`+id+`","token":"`+token+`"}`); e == nil || e.Code != "bad_request" {
		t.Fatalf("preview took a token: %+v", e)
	}
	if _, e := rpc(t, w, "admin", "mail.setup.zones", `{"id":"`+id+`","accountId":"x"}`); e == nil || e.Code != "unavailable" {
		t.Fatalf("zones without a directory: %+v", e)
	}
}

func TestDiagnoseOperations(t *testing.T) {
	w, _ := newWorker(t)
	got, e := rpc(t, w, "admin", "mail.diagnose.symptoms", `{}`)
	if e != nil || len(got["symptoms"].([]any)) != 5 {
		t.Fatalf("symptoms: %+v %+v", got, e)
	}
	if _, e := rpc(t, w, "admin", "mail.diagnose.start", `{"symptom":"invented"}`); e == nil || e.Code != "bad_request" {
		t.Fatalf("invented symptom: %+v", e)
	}
	run, e := rpc(t, w, "admin", "mail.diagnose.start", `{"symptom":"cannot-receive"}`)
	if e != nil || run["done"].(float64) != 0 {
		t.Fatalf("start: %+v %+v", run, e)
	}
	if _, e := rpc(t, w, "other", "mail.diagnose.next", `{"id":"`+run["id"].(string)+`"}`); e == nil || e.Code != "not_found" {
		t.Fatalf("other administrator advanced the run: %+v", e)
	}
	for i := 0; i < int(run["total"].(float64)); i++ {
		run, e = rpc(t, w, "admin", "mail.diagnose.next", `{"id":"`+run["id"].(string)+`"}`)
		if e != nil {
			t.Fatal(e)
		}
	}
	if run["complete"] != true {
		t.Fatalf("run incomplete: %+v", run)
	}
}

func TestRelayStatusAndSet(t *testing.T) {
	w, _ := newWorker(t)
	got, e := rpc(t, w, "admin", "mail.relay.status", `{}`)
	if e != nil || got["id"] != relay.ID || got["enabled"] != false {
		t.Fatalf("status: %+v %+v", got, e)
	}
	if _, e := rpc(t, w, "admin", "mail.relay.set", `{}`); e == nil || e.Code != "bad_request" {
		t.Fatal("set without enabled accepted")
	}
	if _, e := rpc(t, w, "admin", "mail.relay.set", `{"enabled":false}`); e != nil {
		t.Fatal(e)
	}
}

// A plan prepared for other answers is a conflict with its own reason, not
// the generic stalePlan text.
func TestPlanChangedIsAConflictWithItsOwnReason(t *testing.T) {
	e := publicError(setup.ErrPlanChanged)
	if e.Code != "conflict" || e.Details["reason"] != "mail.setup.planChanged" {
		t.Fatalf("%+v", e)
	}
}

// A poll carries only the flow, for the zone step as for the preview: a
// choice sent with a poll would be ignored, so it is refused and nothing runs.
func TestPollsRefuseExtraParams(t *testing.T) {
	w, _ := newWorker(t)
	flow, e := rpc(t, w, "admin", "mail.setup.start", `{}`)
	if e != nil {
		t.Fatal(e)
	}
	id := flow["id"].(string)
	acct, zone := strings.Repeat("a", 32), strings.Repeat("b", 32)
	for _, c := range []struct{ method, extra string }{
		{"mail.setup.zones", `"accountId":"` + acct + `"`},
		{"mail.setup.zones", `"zoneId":"` + zone + `"`},
		{"mail.setup.zones", `"accountId":"` + acct + `","zoneId":"` + zone + `"`},
		{"mail.setup.preview", `"addresses":"admin@example.test"`},
		{"mail.setup.preview", `"members":"admin"`},
		{"mail.setup.preview", `"tunnel":"t"`},
	} {
		if _, e := rpc(t, w, "admin", c.method, `{"id":"`+id+`","poll":true,`+c.extra+`}`); e == nil || e.Code != "bad_request" {
			t.Fatalf("%s poll with %s: %+v", c.method, c.extra, e)
		}
	}
	// The plain zone poll is accepted: no sign-in yet, an empty view.
	if v, e := rpc(t, w, "admin", "mail.setup.zones", `{"id":"`+id+`","poll":true}`); e != nil || v["zones"] == nil || v["zoneId"] != nil {
		t.Fatalf("plain zone poll: %+v %+v", v, e)
	}
}
