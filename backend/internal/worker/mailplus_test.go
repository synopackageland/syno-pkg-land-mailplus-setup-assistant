package worker

import (
	"SynoMailPlusSetupAssistant/internal/mail/setup"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

// packageDSM answers SYNO.Core.Package list with packages and records calls.
type packageDSM struct {
	mu       sync.Mutex
	packages string
	calls    []string
}

func (d *packageDSM) Call(_ context.Context, api, method string, _ int, _ map[string]any, out any) error {
	d.mu.Lock()
	d.calls = append(d.calls, api+" "+method)
	d.mu.Unlock()
	if api != "SYNO.Core.Package" {
		return core.DSMError{Code: 102}
	}
	return json.Unmarshal([]byte(`{"packages":`+d.packages+`}`), out)
}

// mail.mailplus.status reads the precondition (one package read) and names
// the state; only a running MailPlus Server is asked one more thing, whether
// its first-run setup is done. A failed read leaves setUp absent.
func TestMailPlusStatusOperation(t *testing.T) {
	for want, packages := range map[string]string{
		"notInstalled": `[]`,
		"stopped":      `[{"id":"MailPlus-Server","version":"4.1.1","additional":{"status":"stop","installed_info":{}}}]`,
		"running":      `[{"id":"MailPlus-Server","version":"4.1.1","additional":{"status":"running","installed_info":{}}}]`,
		"unknown":      `null`,
	} {
		w, _ := newWorker(t)
		dsm := &packageDSM{packages: packages}
		w.Host.Env.DSM = dsm
		w.Mail.MailPlus = &mail.Precondition{Reader: detect.New()}
		got, e := rpc(t, w, "admin", "mail.mailplus.status", `{}`)
		calls := []string{"SYNO.Core.Package list"}
		if want == "running" {
			calls = append(calls, "SYNO.MailPlusServer.Util initial_check")
		}
		if e != nil || got["state"] != want || strings.Join(dsm.calls, ",") != strings.Join(calls, ",") {
			t.Fatalf("%s: %v %+v %v", want, got, e, dsm.calls)
		}
		if _, ok := got["setUp"]; ok {
			t.Fatalf("%s: setUp without an answer: %v", want, got)
		}
		if want == "unknown" && got["causeKey"] == "" {
			t.Fatalf("unknown without its cause: %v", got)
		}
		if _, e := rpc(t, w, "admin", "mail.mailplus.status", `{"x":1}`); e == nil || e.Code != "bad_request" {
			t.Fatalf("extra params: %+v", e)
		}
	}
}

// The precondition refusal is typed: its own code and catalog reason, never
// DSM's code.
func TestMailPlusRefusalIsTyped(t *testing.T) {
	for state, want := range map[detect.MailPlusState][2]string{
		detect.MailPlusNotInstalled: {"mailplus_not_installed", "mail.mailplus.notInstalled"},
		detect.MailPlusStopped:      {"mailplus_not_running", "mail.mailplus.stopped"},
		detect.MailPlusUnknown:      {"mailplus_unknown", "mail.mailplus.unknown"},
	} {
		e := publicError(detect.MailPlusUnavailable{State: state, Detail: "dsm_102"})
		if e.Code != want[0] || e.Details["reason"] != want[1] || strings.Contains(e.Message, "102") {
			t.Fatalf("%s: %+v", state, e)
		}
	}
}

// Every request's DSM goes through the gate: after a package read that says
// MailPlus Server is not installed, a MailPlus Server call is refused, typed.
func TestRequestsGoThroughTheMailPlusGate(t *testing.T) {
	dsm := detect.Gate(&packageDSM{packages: `[]`}, nil)
	_ = detect.ReadPackage(context.Background(), dsm)
	err := dsm.Call(context.Background(), "SYNO.MailPlusServer.Domain", "list", 1, nil, &struct{}{})
	if e := publicError(err); e.Code != "mailplus_not_installed" {
		t.Fatalf("%+v", e)
	}
}

// A plan refusal of Email Sending reaches the browser as its plain reason.
func TestSendingPlanReason(t *testing.T) {
	e := publicError(setup.ErrSendingPlan)
	if e.Code != "unavailable" || e.Details["reason"] != "mail.setup.sendingPlan" {
		t.Fatalf("%+v", e)
	}
}

// the inbound refusals keep their fixed keys; a missing Cloudflare
// permission is its own code, so the Overview asks for a token again.
func TestInboundRefusalsKeepTheirKeys(t *testing.T) {
	for err, want := range map[error][2]string{
		setup.ErrCatchAllInUse:                                    {"unavailable", "mail.setup.receive.domainUnavailable"},
		setup.ErrSyncTokenRequired:                                {"unavailable", "mail.inbound.tokenRequired"},
		setup.PermissionRefused{Code: setup.PermRoutingRulesEdit}: {"permission_refused", "mail.setup.permissionRefused.routingRulesEdit"},
	} {
		e := publicError(err)
		if e.Code != want[0] || e.Details["reason"] != want[1] {
			t.Errorf("%v: %+v", err, e)
		}
	}
}

// a replacement token missing permissions names all of them.
func TestMissingPermissionsAreNamed(t *testing.T) {
	e := publicError(setup.PermissionsMissing{Codes: []string{setup.PermWorkersEdit, setup.PermVPCAdmin}})
	if e.Code != "permission_refused" || e.Details["reason"] != "mail.inbound.tokenMissing" || e.Details["permissions"] != "workersEdit,vpcAdmin" {
		t.Fatalf("%+v", e)
	}
}
