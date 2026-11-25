package mail

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
	"github.com/synopackageland/syno-pkg-land-sdk/delegate"
)

// domainExecutor stands in for the SDK executor behind core.Authority: it
// answers webapi.call for MailPlus's domain list with a DSM envelope.
type domainExecutor struct {
	mu    sync.Mutex
	calls []string
	delay time.Duration
	// packages is the SYNO.Core.Package list reply's package array (default:
	// MailPlus Server installed and running).
	packages string
}

func (e *domainExecutor) Call(ctx context.Context, op string, _ map[string]string, in, out any) error {
	p, _ := in.(map[string]any)
	e.mu.Lock()
	e.calls = append(e.calls, op+" "+p["api"].(string)+" "+p["method"].(string))
	e.mu.Unlock()
	select {
	case <-time.After(e.delay):
	case <-ctx.Done():
		return ctx.Err()
	}
	if op == "webapi.call" && p["api"] == "SYNO.Core.Package" && p["method"] == "list" {
		pkgs := e.packages
		if pkgs == "" {
			pkgs = `[{"id":"MailPlus-Server","version":"4.1.1-31785","additional":{"status":"running","installed_info":{}}}]`
		}
		*out.(*json.RawMessage) = json.RawMessage(`{"success":true,"data":{"packages":` + pkgs + `}}`)
		return nil
	}
	if op != "webapi.call" || p["api"] != "SYNO.MailPlusServer.Domain" || p["method"] != "list" {
		raw := json.RawMessage(`{"success":false,"error":{"code":103}}`)
		*out.(*json.RawMessage) = raw
		return nil
	}
	*out.(*json.RawMessage) = json.RawMessage(`{"success":true,"data":{"domains":[{"domain_id":1,"name":"sample-nas.test"},{"domain_id":2,"name":"mail.example.test"},{"domain_id":3,"name":"in.example.test"}]}}`)
	return nil
}

// The zone step's MailPlus domain read goes through the production DSM path:
// core.Authority (executor slots, the full per-call budget check) and the
// delegate WebAPI transport, as on the NAS. A read whose budget is shorter
// than DSMReadTimeout is never sent (ErrDSMSlotTimeout): that was the build
// 26 "probe_timeout".
func TestZonesReadsMailPlusDomainsThroughTheAuthority(t *testing.T) {
	v, exec := zoneDomains(t, &domainExecutor{delay: 50 * time.Millisecond}, nil)
	if v.MailDomainsState != "read" || strings.Join(v.MailDomains, ",") != "in.example.test,mail.example.test" || len(exec.calls) != 2 ||
		exec.calls[0] != "webapi.call SYNO.Core.Package list" {
		t.Fatalf("zone mail domains: state=%q cause=%q domains=%v calls=%v", v.MailDomainsState, v.MailDomainsCause, v.MailDomains, exec.calls)
	}
}

// The zone step checks the MailPlus Server precondition first: not installed,
// stopped or broken, it never asks MailPlus Server for its domains and names
// the precondition (never a raw DSM 102).
func TestZonesDomainReadChecksMailPlusFirst(t *testing.T) {
	for name, tc := range map[string]struct{ packages, cause, key string }{
		"not installed": {`[{"id":"SynoFinder","version":"1","additional":{"status":"running","installed_info":{}}}]`, detect.CauseMailPlusNotInstalled, "mail.setup.cause.mailplusNotInstalled"},
		"stopped":       {`[{"id":"MailPlus-Server","version":"4.1.1","additional":{"status":"stop","installed_info":{}}}]`, detect.CauseMailPlusNotRunning, "mail.setup.cause.mailplusStopped"},
		"broken":        {`[{"id":"MailPlus-Server","version":"4.1.1","additional":{"status":"running","installed_info":{"is_broken":true}}}]`, detect.CauseMailPlusNotRunning, "mail.setup.cause.mailplusStopped"},
	} {
		t.Run(name, func(t *testing.T) {
			v, exec := zoneDomains(t, &domainExecutor{packages: tc.packages}, nil)
			if v.MailDomainsState != "unknown" || v.MailDomainsCause != tc.cause || v.MailDomainsCauseKey != tc.key || len(exec.calls) != 1 || exec.calls[0] != "webapi.call SYNO.Core.Package list" {
				t.Fatalf("state=%q cause=%q key=%q calls=%v", v.MailDomainsState, v.MailDomainsCause, v.MailDomainsCauseKey, exec.calls)
			}
		})
	}
	t.Run("unknown", func(t *testing.T) {
		v, exec := zoneDomains(t, &domainExecutor{packages: `null`}, nil)
		if v.MailDomainsState != "unknown" || v.MailDomainsCause != core.CauseUnavailable || len(exec.calls) != 1 {
			t.Fatalf("state=%q cause=%q calls=%v", v.MailDomainsState, v.MailDomainsCause, exec.calls)
		}
	})
}

// probe_timeout is reachable only by a call that was sent and did not answer
// in its budget; a call that never got an executor slot is not_started.
func TestZonesDomainReadCauses(t *testing.T) {
	t.Run("sent, no answer in time", func(t *testing.T) {
		v, exec := zoneDomains(t, &domainExecutor{delay: time.Second}, func(a *core.Authority) { a.ReadTimeout = 100 * time.Millisecond })
		if v.MailDomainsState != "unknown" || v.MailDomainsCause != core.CauseTimeout || len(exec.calls) != 1 {
			t.Fatalf("state=%q cause=%q calls=%v", v.MailDomainsState, v.MailDomainsCause, exec.calls)
		}
	})
	t.Run("never sent: no slot", func(t *testing.T) {
		v, exec := zoneDomains(t, &domainExecutor{delay: 3 * time.Second}, func(a *core.Authority) {
			a.Slots, a.SlotWait = 1, 200*time.Millisecond
			go func() {
				_ = a.DSM("alice").Call(context.Background(), "SYNO.MailPlusServer.Domain", "list", 1, nil, nil)
			}()
			time.Sleep(50 * time.Millisecond) // the slot is taken
		})
		if v.MailDomainsState != "unknown" || v.MailDomainsCause != setup.CauseNotStarted || len(exec.calls) != 1 {
			t.Fatalf("state=%q cause=%q calls=%v", v.MailDomainsState, v.MailDomainsCause, exec.calls)
		}
	})
}

// zoneDomains signs in, chooses the zone and polls until the domain read
// has an answer, all through core.Authority and the delegate transport.
func zoneDomains(t *testing.T, exec *domainExecutor, tune func(*core.Authority)) (setup.CloudView, *domainExecutor) {
	t.Helper()
	ctx := context.Background()
	adapter, _, _ := signInFixture(t, "fixture-value")
	env := wiringEnv(t)
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	authority := &core.Authority{Store: store, Client: exec}
	g := delegate.Grant{DelegationID: strings.Repeat("a", 64), Scope: "mail-read", Lifetime: "until-revoked",
		Subject: delegate.Subject{Username: "alice", UID: json.Number("1024")}}
	if err := authority.Bind(ctx, "alice", g); err != nil {
		t.Fatal(err)
	}
	if tune != nil {
		tune(authority)
	}
	env.DSM = authority.DSM("alice")
	w := setup.New(setup.Options{Detector: detect.New(), Directory: adapter, Background: &core.Background{}})
	flow, err := w.Start(ctx, env, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Connect(ctx, env, "alice", flow.ID, "fixture-value"); err != nil {
		t.Fatal(err)
	}
	v, err := w.Zones(ctx, env, "alice", flow.ID, testAccount, testZone)
	for i := 0; err == nil && v.MailDomainsState == "reading" && i < 100; i++ {
		v, err = w.PollZone(ctx, env, "alice", flow.ID)
	}
	if err != nil || v.MailDomainsState == "reading" {
		t.Fatalf("no answer: %+v %v", v, err)
	}
	exec.mu.Lock()
	defer exec.mu.Unlock()
	return v, exec
}

// A missing read grant (or a caller who is not an administrator) is the
// approval prompt, as at detection, never "unknown, check again".
func TestZonesDomainReadNeedsTheGrant(t *testing.T) {
	ctx := context.Background()
	adapter, _, _ := signInFixture(t, "fixture-value")
	env := wiringEnv(t)
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	env.DSM = (&core.Authority{Store: store, Client: &domainExecutor{}}).DSM("alice") // no grant bound
	w := setup.New(setup.Options{Detector: detect.New(), Directory: adapter, Background: &core.Background{}})
	flow, _ := w.Start(ctx, env, "alice")
	if _, err := w.Connect(ctx, env, "alice", flow.ID, "fixture-value"); err != nil {
		t.Fatal(err)
	}
	_, err = w.Zones(ctx, env, "alice", flow.ID, testAccount, testZone)
	var authority core.AuthorityRequired
	if !errors.As(err, &authority) || authority.Profile != "mail-read" {
		t.Fatalf("got %v", err)
	}
	// The refusal is kept as an unknown with the authority cause (not "reading").
	v, err := w.PollZone(ctx, env, "alice", flow.ID)
	if err != nil || v.MailDomainsState != "unknown" || v.MailDomainsCause != core.CauseAuthority || v.MailDomainsCauseKey != "mail.setup.cause.authority" {
		t.Fatalf("after: %+v %v", v, err)
	}
}

func TestZonesDomainReadNoAdmin(t *testing.T) {
	ctx := context.Background()
	adapter, _, _ := signInFixture(t, "fixture-value")
	env := wiringEnv(t)
	env.DSM = noAdminDSM{}
	w := setup.New(setup.Options{Detector: detect.New(), Directory: adapter, Background: &core.Background{}})
	flow, _ := w.Start(ctx, env, "alice")
	if _, err := w.Connect(ctx, env, "alice", flow.ID, "fixture-value"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Zones(ctx, env, "alice", flow.ID, testAccount, testZone); !errors.Is(err, core.ErrNoAdmin) {
		t.Fatalf("got %v", err)
	}
}

type noAdminDSM struct{}

func (noAdminDSM) Call(context.Context, string, string, int, map[string]any, any) error {
	return core.ErrNoAdmin
}
