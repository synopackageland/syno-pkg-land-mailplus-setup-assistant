package mail

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/cloudflare"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
	"SynoMailPlusSetupAssistant/internal/mail/diagnose"
	"SynoMailPlusSetupAssistant/internal/mail/relay"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

type fakeCloud struct {
	records         []cloudflare.DNSRecord
	senders         []cloudflare.SendingDomain
	creates         int
	loseSenderReply bool
	previewIssues   []cloudflare.DNSCheckIssue
}

const testAccount = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testZone = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func (f *fakeCloud) Do(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Authorization") != "Bearer fixture-value" {
		return nil, errors.New("unexpected credential")
	}
	zone := "/zones/" + testZone
	// Production clients retain the documented API v4 base-path prefix.
	req.URL.Path = strings.TrimPrefix(req.URL.Path, "/client/v4")
	var result any
	switch {
	case req.URL.Path == zone && req.Method == "GET":
		result = map[string]any{"id": testZone, "name": "example.test", "account": map[string]string{"id": testAccount}}
	case req.URL.Path == zone+"/dns_records" && req.Method == "GET":
		result = f.records
		if f.records == nil {
			result = []any{}
		}
	case req.URL.Path == zone+"/dns_records" && req.Method == "POST":
		f.creates++
		var fields cloudflare.DNSFields
		if json.NewDecoder(req.Body).Decode(&fields) != nil {
			return nil, errors.New("invalid fixture request")
		}
		record := cloudflare.DNSRecord{DNSFields: fields, ID: "record"}
		f.records = append(f.records, record)
		result = record
	case req.URL.Path == zone+"/dns_records/record" && req.Method == "GET":
		if len(f.records) != 1 {
			return nil, errors.New("fixture record unavailable")
		}
		result = f.records[0]
	case req.URL.Path == zone+"/dns_records/record" && req.Method == "DELETE":
		f.records = nil
		result = map[string]string{"id": "record"}
	case req.URL.Path == zone+"/email/sending/subdomains" && req.Method == "GET":
		result = f.senders
		if f.senders == nil {
			result = []any{}
		}
	case req.URL.Path == zone+"/email/sending/subdomains/preview" && req.Method == "POST":
		result = cloudflare.DNSCheck{Records: []cloudflare.DNSFields{{Type: "TXT", Name: "cf-bounce.example.test", Content: "v=spf1 include:_spf.mx.cloudflare.net ~all", TTL: 1}}, Errors: f.previewIssues}
	case req.URL.Path == zone+"/email/sending/subdomains" && req.Method == "POST":
		f.creates++
		sender := cloudflare.SendingDomain{ID: "sender", Name: "example.test", Enabled: true}
		f.senders = []cloudflare.SendingDomain{sender}
		if f.loseSenderReply {
			return nil, errors.New("fixture lost reply")
		}
		result = sender
	default:
		return nil, errors.New("unexpected fixture request")
	}
	raw, _ := json.Marshal(map[string]any{"success": true, "result": result})
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
}

func wiringEnv(t *testing.T) core.Env {
	t.Helper()
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return core.Env{DataDir: store.DataDir, KV: store, Secrets: core.SecretStore{Store: store}}
}

func cfFixture(t *testing.T, fake *fakeCloud) (*cloudflareAdapter, core.Env, setup.PlanRequest) {
	t.Helper()
	env := wiringEnv(t)
	ref := "secret:fixture.cloudflare"
	if err := env.Secrets.Put(context.Background(), ref, "fixture-value"); err != nil {
		t.Fatal(err)
	}
	adapter := &cloudflareAdapter{newClient: func(cfg cloudflare.Config) (*cloudflare.Client, error) {
		cfg.HTTPClient = fake
		return cloudflare.New(cfg)
	}}
	request := setup.PlanRequest{SessionID: "fixture", Domain: "example.test", Intent: setup.Send,
		AccountID: testAccount, ZoneID: testZone, TokenRef: ref,
		Decision: setup.Decision{Send: setup.DirectSend, Needs: []string{"dns.dmarc"}}}
	return adapter, env, request
}

func TestCloudflareDNSWiringReconcilesAndRefusesRollbackDrift(t *testing.T) {
	ctx := context.Background()
	fake := &fakeCloud{}
	adapter, env, request := cfFixture(t, fake)
	prepared, err := adapter.Plan(ctx, env, request)
	if err != nil || !prepared.Restorable || len(prepared.Changes) != 1 {
		t.Fatalf("plan: %v", err)
	}
	change := prepared.Changes[0]
	if strings.Contains(change.After, "fixture-value") {
		t.Fatal("credential leaked")
	}
	snapshot, err := adapter.Snapshot(ctx, env, change)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Apply(ctx, env, change); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Apply(ctx, env, change); err != nil {
		t.Fatal(err)
	}
	if fake.creates != 1 {
		t.Fatal("same change created twice")
	}
	fake.records[0].Content = "v=DMARC1; p=reject"
	if err := adapter.Rollback(ctx, env, change, snapshot); !errors.Is(err, setup.ErrStale) {
		t.Fatal("external drift was overwritten")
	}
	fake.records[0].Content = "v=DMARC1; p=none"
	if err := adapter.Rollback(ctx, env, change, snapshot); err != nil {
		t.Fatal(err)
	}
	if len(fake.records) != 0 {
		t.Fatal("owned DNS was not rolled back")
	}
}

func TestCloudflareSenderLostReplyCannotRetryOrDeleteWithoutReceipt(t *testing.T) {
	ctx := context.Background()
	fake := &fakeCloud{loseSenderReply: true}
	adapter, env, request := cfFixture(t, fake)
	request.Decision = setup.Decision{Send: setup.RelaySend, Needs: []string{"cloudflare.sending"}}
	prepared, err := adapter.Plan(ctx, env, request)
	if err != nil || len(prepared.Changes) != 1 {
		t.Fatalf("plan: %v", err)
	}
	change := prepared.Changes[0]
	snapshot, err := adapter.Snapshot(ctx, env, change)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Apply(ctx, env, change); err == nil {
		t.Fatal("lost reply claimed success")
	}
	if err := adapter.Apply(ctx, env, change); err == nil {
		t.Fatal("uncertain sender was adopted")
	}
	if fake.creates != 1 {
		t.Fatal("uncertain sender create retried")
	}
	if err := adapter.Rollback(ctx, env, change, snapshot); err == nil {
		t.Fatal("sender deleted without receipt")
	}
	if len(fake.senders) != 1 {
		t.Fatal("unknown sender was deleted")
	}
}

// A working Email Sending domain set up earlier (by hand or another tool) is
// reused: nothing is created, and rollback and removal never delete it.
// (Cloudflare's preview of an existing healthy domain answered 200 with no
// issues.)
func TestCloudflareSenderAlreadyWorkingIsReusedAndNeverDeleted(t *testing.T) {
	ctx := context.Background()
	fake := &fakeCloud{senders: []cloudflare.SendingDomain{{ID: "theirs", Name: "example.test", Enabled: true}}}
	adapter, env, request := cfFixture(t, fake)
	request.Decision = setup.Decision{Send: setup.RelaySend, Needs: []string{"cloudflare.sending"}}
	prepared, err := adapter.Plan(ctx, env, request)
	if err != nil || len(prepared.Changes) != 1 {
		t.Fatalf("existing sender refused: %v", err)
	}
	change := prepared.Changes[0]
	if change.Before != sendingExisting || change.After != sendingExisting {
		t.Fatalf("reuse not recorded as existing: %q -> %q", change.Before, change.After)
	}
	snapshot, err := adapter.Snapshot(ctx, env, change)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Apply(ctx, env, change); err != nil {
		t.Fatal(err)
	}
	if fake.creates != 0 {
		t.Fatal("an existing sender was created again")
	}
	var wired cloudOperation
	if found, err := env.KV.Get(ctx, "mail.wiring", "cloudflare.example.test", &wired); err != nil || !found {
		t.Fatal("reused sender not wired for the diagnosis's selector read")
	}
	if err := adapter.Rollback(ctx, env, change, snapshot); err != nil {
		t.Fatal(err)
	}
	if len(fake.senders) != 1 || fake.senders[0].ID != "theirs" {
		t.Fatal("rollback deleted a sender the setup did not create")
	}
	rec := keptRecord{Applied: []setup.AppliedChange{{Change: change}}}
	for _, item := range removes(rec) {
		if item == "ui.remove.item.sending" {
			t.Fatal("removal promises to delete a sender it will keep")
		}
	}
	// Disabled between the preview and the apply: stale, never re-enabled.
	fake.senders[0].Enabled = false
	if err := adapter.Apply(ctx, env, change); !errors.Is(err, setup.ErrStale) {
		t.Fatalf("disabled sender accepted: %v", err)
	}
}

// An existing Email Sending domain that is disabled or has DNS Cloudflare
// reports as wrong is refused with one plain reason, not "unavailable".
func TestCloudflareSenderAlreadyBrokenIsRefusedPlainly(t *testing.T) {
	for name, fake := range map[string]*fakeCloud{
		"disabled":  {senders: []cloudflare.SendingDomain{{ID: "theirs", Name: "example.test", Enabled: false}}},
		"dns-wrong": {senders: []cloudflare.SendingDomain{{ID: "theirs", Name: "example.test", Enabled: true}}, previewIssues: []cloudflare.DNSCheckIssue{{Code: "dkim.missing"}}},
	} {
		t.Run(name, func(t *testing.T) {
			adapter, env, request := cfFixture(t, fake)
			request.Decision = setup.Decision{Send: setup.RelaySend, Needs: []string{"cloudflare.sending"}}
			if _, err := adapter.Plan(context.Background(), env, request); !errors.Is(err, setup.ErrSendingExisting) {
				t.Fatalf("broken sender: %v", err)
			}
			if fake.creates != 0 {
				t.Fatal("wrote while refusing")
			}
		})
	}
}

func TestRelayPlanUsesExistingCredentialsAndRefusesConfiguredService(t *testing.T) {
	ctx := context.Background()
	env := wiringEnv(t)
	service := relay.New(env.DataDir)
	adapter := &relayAdapter{service: service}
	request := setup.PlanRequest{SessionID: "fixture", Domain: "example.test", SMTPTokenRef: "secret:fixture.smtp"}
	if err := env.Secrets.Put(ctx, request.SMTPTokenRef, "smtp-fixture"); err != nil {
		t.Fatal(err)
	}
	prepared, err := adapter.Plan(ctx, env, request)
	if err != nil || len(prepared.Changes) != 1 {
		t.Fatalf("relay plan: %v", err)
	}
	change := prepared.Changes[0]
	if change.Params["listen"] != "127.0.0.1:2525" || change.Params["starttls"] != "required" {
		t.Fatal("relay endpoint is not concrete")
	}
	raw, err := env.Secrets.Get(ctx, change.Params["credentialRef"])
	if err != nil {
		t.Fatal(err)
	}
	var planned relay.AuthCredentials
	if json.Unmarshal([]byte(raw), &planned) != nil {
		t.Fatal("credential reference unavailable")
	}
	actual, err := relay.Credentials(ctx, env)
	if err != nil || planned != actual {
		t.Fatal("MailPlus would receive different relay credentials")
	}
	snapshot, err := adapter.Snapshot(ctx, env, change)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Rollback(ctx, env, change, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := env.KV.Put(ctx, "core.services", relay.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Plan(ctx, env, request); !errors.Is(err, setup.ErrUnsafe) {
		t.Fatal("configured relay was overwritten")
	}
}

type detectorFunc func(context.Context, core.Env, detect.Request) detect.State

func (f detectorFunc) Detect(ctx context.Context, env core.Env, request detect.Request) detect.State {
	return f(ctx, env, request)
}

func TestVerificationDoesNotTreatTLSOrConfigurationAsDelivery(t *testing.T) {
	detector := detectorFunc(func(context.Context, core.Env, detect.Request) detect.State {
		return detect.State{SMTP: detect.Fact(detect.SMTP{Enabled: true})}
	})
	v := verifier{detector: detector}
	if _, err := v.Verify(context.Background(), core.Env{}, setup.PlanRequest{Decision: setup.Decision{Send: setup.RelaySend}}, nil); !errors.Is(err, setup.ErrUnavailable) {
		t.Fatal("missing delivery evidence claimed success")
	}
	result, err := v.Verify(context.Background(), core.Env{}, setup.PlanRequest{Decision: setup.Decision{Gate: setup.Minimal}}, nil)
	if err != nil || !result.Readback || result.Delivery {
		t.Fatal("minimal readback was conflated with delivery")
	}
}

func TestRelayPublicErrorsAndNineLocaleCatalogs(t *testing.T) {
	service := relayService{}
	codes := []string{}
	for code := range relayErrors {
		if service.PublicErrorCode(code) != code {
			t.Fatalf("safe error hidden: %s", code)
		}
		codes = append(codes, code)
	}
	for stage := range relayUpstreamStages {
		code := "mail.relay.upstream_" + stage
		for _, suffix := range []string{"/0", "/550", ""} {
			if service.PublicErrorCode(code+suffix) != code {
				t.Fatalf("upstream code hidden: %s", code+suffix)
			}
		}
		codes = append(codes, code)
	}
	for _, unsafe := range []string{"credential-private-value", "mail.relay.upstream_auth/550 private-value", "mail.relay.upstream_unknown/550"} {
		if service.PublicErrorCode(unsafe) != "service_failed" {
			t.Fatal("unknown provider text published")
		}
	}
	codes = append(codes, "error.authority_required", "service_failed", "service_stopped")
	for _, locale := range []string{"en", "zh-TW", "zh-CN", "ja", "ko", "de", "fr", "es", "it"} {
		raw, err := os.ReadFile(filepath.Join("../../../i18n/messages", locale+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var catalog map[string]string
		if err = json.Unmarshal(raw, &catalog); err != nil {
			t.Fatal(err)
		}
		for _, code := range codes {
			text := catalog[code]
			if text == "" || strings.HasSuffix(text, ".") || strings.HasSuffix(text, "。") {
				t.Fatalf("%s: missing or invalid %s", locale, code)
			}
		}
		if !strings.Contains(catalog["error.authority_required"], "{profile}") {
			t.Fatalf("%s: profile placeholder missing", locale)
		}
	}
}

type routedState struct{}

func (routedState) Snapshot(context.Context, core.Env) (diagnose.State, error) {
	on := true
	return diagnose.State{Relay: diagnose.RelayState{Enabled: &on}}, nil
}

// S1 (review of #39): after the relay step is rolled back, the relay is
// stopped and MailPlus no longer routes through it. The 15-minute memory
// judgement must not report relay_stopped from the route the last full run saw.
func TestRelayRollbackClearsMemoryRoute(t *testing.T) {
	ctx := context.Background()
	env := wiringEnv(t)
	service := relay.New(env.DataDir)
	d := diagnose.New(diagnose.Dependencies{State: routedState{}, RelayStatus: service})
	adapter := &relayAdapter{service: service, routeChanged: d.ForgetRelayRoute}
	var judge core.MemoryCheck
	for _, c := range d.Checks() {
		if c.ID() == string(diagnose.Relay) {
			judge = c.(core.MemoryCheck)
		}
	}
	if _, err := d.Run(ctx, env, diagnose.Relay); err != nil {
		t.Fatal(err)
	}
	if _, final := judge.Judge(time.Now()); !final {
		t.Fatal("fixture: a stopped relay on a routed MailPlus should be judged")
	}
	request := setup.PlanRequest{SessionID: "fixture", Domain: "example.test", SMTPTokenRef: "secret:fixture.smtp"}
	if err := env.Secrets.Put(ctx, request.SMTPTokenRef, "smtp-fixture"); err != nil {
		t.Fatal(err)
	}
	prepared, err := adapter.Plan(ctx, env, request)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := adapter.Snapshot(ctx, env, prepared.Changes[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Rollback(ctx, env, prepared.Changes[0], snapshot); err != nil {
		t.Fatal(err)
	}
	if got, final := judge.Judge(time.Now()); final {
		t.Fatalf("rollback left a stale route: memory judgement %+v", got)
	}
}
