package setup

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

type dsmFixture struct {
	smtp           map[string]any
	security       map[string]any
	typ            map[string]any
	hosts          []any
	calls          []string
	confidential   int
	failActivation bool
	// notStarted makes the next call to this method refuse before sending
	// (no executor slot): core.ErrDSMSlotTimeout.
	notStarted string
	// domains: MailPlus mail domains (Domain list/create/delete v1).
	domains []map[string]any
	// loseCreate: the domain is created but the reply is lost.
	loseCreate bool
}

func dsmFake() *dsmFixture {
	return &dsmFixture{
		smtp:     map[string]any{"account_type": "local", "account_domain_name": "", "enable_smtp": false, "smtp_port": 25, "enable_smtp_ssl": true, "smtp_ssl_port": 465, "enable_smtp_tls": true, "smtp_tls_port": 587},
		security: map[string]any{"enable_dkim_sign": true, "dkim_selector": "mail", "dkim_public_key": "public"},
		typ:      map[string]any{"host_type": "none", "enable_fallback_relay": false}, hosts: []any{},
	}
}
func (f *dsmFixture) Call(_ context.Context, api, method string, _ int, params map[string]any, out any) error {
	if f.notStarted != "" && f.notStarted == api+"."+method {
		f.notStarted = ""
		return core.ErrDSMSlotTimeout
	}
	f.calls = append(f.calls, api+"."+method)
	var v any
	switch api + "." + method {
	case "SYNO.MailPlusServer.Service.SMTP.get":
		v = f.smtp
	case "SYNO.MailPlusServer.Service.SMTP.set":
		f.smtp = params
		v = nil // MailPlus writes answer {"success":true} with no data
	case "SYNO.MailPlusServer.Domain.list":
		v = map[string]any{"domains": f.domains, "total": len(f.domains)}
	case "SYNO.MailPlusServer.Domain.create":
		id := len(f.domains) + 10
		f.domains = append(f.domains, map[string]any{"domain_id": id, "name": params["name"], "desc": params["desc"], "user_num": 0})
		if f.loseCreate {
			f.loseCreate = false
			return core.ErrDSMSlotTimeout
		}
		v = map[string]any{"domain_id": id}
	case "SYNO.MailPlusServer.Domain.delete":
		ids, _ := params["domain_ids"].([]int)
		kept := []map[string]any{}
		for _, d := range f.domains {
			gone := false
			for _, id := range ids {
				gone = gone || d["domain_id"] == id
			}
			if !gone {
				kept = append(kept, d)
			}
		}
		f.domains = kept
		v = nil
	case "SYNO.MailPlusServer.Domain.get_security":
		v = f.security
	case "SYNO.MailPlusServer.Domain.set_security":
		for k, v := range params {
			if k != "domain_id" {
				f.security[k] = v
			}
		}
		v = nil // MailPlus writes answer {"success":true} with no data
	case "SYNO.MailPlusServer.SMTP.Delivery.get_type":
		v = f.typ
	case "SYNO.MailPlusServer.SMTP.Delivery.get_multiple":
		v = map[string]any{"host_list": f.hosts}
	case "SYNO.MailPlusServer.SMTP.Delivery.set_multiple":
		hs, ok := params["host_list"].([]any)
		if !ok || len(hs) != 0 {
			return errors.New("AUTH must use confidential transport")
		}
		f.hosts = hs
		v = nil // MailPlus writes answer {"success":true} with no data
	case "SYNO.MailPlusServer.SMTP.Delivery.set_type":
		if f.failActivation && params["host_type"] == "list" {
			f.failActivation = false
			return errors.New("lost activation reply")
		}
		for k, value := range params {
			f.typ[k] = value
		}
		v = nil // MailPlus writes answer {"success":true} with no data
	default:
		return errors.New("unexpected DSM method")
	}
	if v == nil {
		// core.WebAPIDSM cannot decode a missing data field into out.
		if out != nil {
			return core.ErrDSMBadResponse
		}
		return nil
	}
	b, _ := json.Marshal(v)
	return json.Unmarshal(b, out)
}
func (f *dsmFixture) CallConfidential(_ context.Context, api, method string, _ int, params map[string]any, out any) error {
	if api != "SYNO.MailPlusServer.SMTP.Delivery" || method != "set_multiple" {
		return errors.New("unexpected confidential method")
	}
	f.confidential++
	hs := params["host_list"].([]any)
	// GET intentionally omits the password, just like the real API
	f.hosts = nil
	for _, v := range hs {
		h := map[string]any{}
		for k, v := range v.(map[string]any) {
			if k != "auth_password" {
				h[k] = v
			}
		}
		f.hosts = append(f.hosts, h)
	}
	if out != nil {
		return core.ErrDSMBadResponse // the real reply has no data either
	}
	return nil
}
func TestSMTPOnlyChangePreservesPortsAndRollback(t *testing.T) {
	ctx := context.Background()
	env := fakeEnv()
	dsm := dsmFake()
	env.DSM = dsm
	state := healthy()
	state.SMTP.Value.Enabled = false
	r := PlanRequest{SessionID: "smtp", Domain: state.Domain, Intent: Send, State: state, Decision: Decide(state, Send, yes)}
	mp := NewMailPlus()
	p, e := mp.Plan(ctx, env, r, nil)
	if e != nil || len(p.Changes) != 1 {
		t.Fatalf("SMTP plan: %v", e)
	}
	original := raw(dsm.smtp)
	snap, e := mp.Snapshot(ctx, env, p.Changes[0])
	if e != nil {
		t.Fatal(e)
	}
	if e = mp.Apply(ctx, env, p.Changes[0]); e != nil {
		t.Fatal(e)
	}
	if dsm.smtp["enable_smtp"] != true || dsm.smtp["smtp_port"] != float64(25) || dsm.smtp["smtp_tls_port"] != float64(587) || dsm.smtp["enable_smtp_ssl"] != true {
		t.Fatal("SMTP update lost existing settings")
	}
	if e = mp.Rollback(ctx, env, p.Changes[0], snap); e != nil {
		t.Fatal(e)
	}
	if digest(raw(dsm.smtp)) != digest(original) {
		t.Fatal("SMTP rollback changed original settings")
	}
}
func TestDKIMOnlySelectedDomainAndDriftRefusal(t *testing.T) {
	ctx := context.Background()
	env := fakeEnv()
	dsm := dsmFake()
	env.DSM = dsm
	state := healthy()
	r := PlanRequest{SessionID: "dkim", Domain: state.Domain, State: state, Decision: Decision{Needs: []string{"mailplus.dkim.disable"}}}
	mp := NewMailPlus()
	p, e := mp.Plan(ctx, env, r, nil)
	if e != nil {
		t.Fatal(e)
	}
	c := p.Changes[0]
	snap, e := mp.Snapshot(ctx, env, c)
	if e != nil {
		t.Fatal(e)
	}
	if e = mp.Apply(ctx, env, c); e != nil || dsm.security["enable_dkim_sign"] != false {
		t.Fatal("selected outbound signing not disabled")
	}
	dsm.security["dkim_selector"] = "changed-by-another-admin"
	if !errors.Is(mp.Rollback(ctx, env, c, snap), ErrStale) {
		t.Fatal("rollback overwrote external drift")
	}
	for _, call := range dsm.calls {
		if strings.Contains(call, "Security.") {
			t.Fatal("inbound DKIM validation touched")
		}
	}
}
func relayPrior() []core.Change {
	return []core.Change{{Target: "homekeeper.relay", Params: map[string]string{"listen": "127.0.0.1:2525", "starttls": "required", "usernameRef": "secret:auth-name", "passwordRef": "secret:auth-password"}}}
}
func TestDeliveryUsesConfidentialSTARTTLSAuthAndRestoresEmptyRoute(t *testing.T) {
	ctx := context.Background()
	env := fakeEnv()
	dsm := dsmFake()
	env.DSM = dsm
	store := env.Secrets.(secrets)
	store["secret:auth-name"] = "fixture-auth-user"
	store["secret:auth-password"] = "fixture-auth-password"
	state := healthy()
	r := PlanRequest{SessionID: "delivery", Domain: state.Domain, State: state, Decision: Decision{Needs: []string{"mailplus.delivery"}}}
	mp := NewMailPlus()
	p, e := mp.Plan(ctx, env, r, relayPrior())
	if e != nil {
		t.Fatal(e)
	}
	c := p.Changes[0]
	snap, e := mp.Snapshot(ctx, env, c)
	if e != nil {
		t.Fatal(e)
	}
	if e = mp.Apply(ctx, env, c); e != nil {
		t.Fatal(e)
	}
	if dsm.confidential != 1 || dsm.typ["host_type"] != "list" || dsm.typ["enable_fallback_relay"] != false {
		t.Fatal("Delivery did not use protected AUTH with no fallback")
	}
	h := dsm.hosts[0].(map[string]any)
	if h["server"] != "127.0.0.1" || h["security_connection"] != true || h["enable_auth"] != true {
		t.Fatal("wrong SMTP security settings")
	}
	b := string(raw([]any{c, snap}))
	if strings.Contains(b, "fixture-auth-user") || strings.Contains(b, "fixture-auth-password") {
		t.Fatal("AUTH leaked into public plan or snapshot")
	}
	if e = mp.Apply(ctx, env, c); e != nil || dsm.confidential != 1 {
		t.Fatal("repeated Delivery apply resent credentials")
	}
	if e = mp.Rollback(ctx, env, c, snap); e != nil {
		t.Fatal(e)
	}
	if dsm.typ["host_type"] != "none" || len(dsm.hosts) != 0 {
		t.Fatal("Delivery not restored")
	}
}
func TestDeliveryPartialApplyIsReconciledWithoutResubmittingAUTH(t *testing.T) {
	ctx := context.Background()
	env := fakeEnv()
	dsm := dsmFake()
	env.DSM = dsm
	store := env.Secrets.(secrets)
	store["secret:auth-name"] = "fixture-auth-user"
	store["secret:auth-password"] = "fixture-auth-password"
	state := healthy()
	r := PlanRequest{SessionID: "partial", Domain: state.Domain, State: state, Decision: Decision{Needs: []string{"mailplus.delivery"}}}
	mp := NewMailPlus()
	p, e := mp.Plan(ctx, env, r, relayPrior())
	if e != nil {
		t.Fatal(e)
	}
	c := p.Changes[0]
	if _, e = mp.Snapshot(ctx, env, c); e != nil {
		t.Fatal(e)
	}
	dsm.failActivation = true
	if e = mp.Apply(ctx, env, c); e == nil {
		t.Fatal("activation failure lost")
	}
	if e = mp.Apply(ctx, env, c); e != nil || dsm.confidential != 1 || dsm.typ["host_type"] != "list" {
		t.Fatalf("partial activation not reconciled: %v", e)
	}
}
func TestDeliveryRefusesForeignHostsAndNonLoopback(t *testing.T) {
	for _, name := range []string{"existing-host", "non-loopback"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			env := fakeEnv()
			dsm := dsmFake()
			env.DSM = dsm
			prior := relayPrior()
			if name == "existing-host" {
				dsm.hosts = []any{map[string]any{"server": "other.test", "enable_auth": true}}
			} else {
				prior[0].Params["listen"] = "0.0.0.0:2525"
			}
			state := healthy()
			r := PlanRequest{SessionID: name, Domain: state.Domain, State: state, Decision: Decision{Needs: []string{"mailplus.delivery"}}}
			_, e := NewMailPlus().Plan(ctx, env, r, prior)
			if !errors.Is(e, ErrUnsafe) {
				t.Fatalf("unsafe existing route accepted: %v", e)
			}
			if !reflect.DeepEqual(dsm.typ, map[string]any{"host_type": "none", "enable_fallback_relay": false}) {
				t.Fatal("planning changed Delivery")
			}
		})
	}
}

func domainPlan(t *testing.T, env core.Env, dsm *dsmFixture) (*MailPlusAdapter, core.Change, json.RawMessage) {
	t.Helper()
	ctx := context.Background()
	state := healthy()
	state.Domains.Value = []detect.Domain{{ID: 1, Name: "other.test"}}
	dsm.domains = []map[string]any{{"domain_id": 1, "name": "other.test", "desc": "", "user_num": 4}}
	r := PlanRequest{SessionID: "domain", Domain: state.Domain, State: state, Decision: Decision{Needs: []string{"mailplus.domain"}}}
	mp := NewMailPlus()
	p, e := mp.Plan(ctx, env, r, nil)
	if e != nil || len(p.Changes) != 1 || p.Changes[0].Target != "mailplus.domain" {
		t.Fatalf("domain plan: %v %+v", e, p.Changes)
	}
	snap, e := mp.Snapshot(ctx, env, p.Changes[0])
	if e != nil {
		t.Fatal(e)
	}
	return mp, p.Changes[0], snap
}

// the App creates the missing mail domain and removes only the one it
// created, and only while nobody uses it.
func TestDomainCreatedAndRemovedOnlyIfOurs(t *testing.T) {
	ctx := context.Background()
	env := fakeEnv()
	dsm := dsmFake()
	env.DSM = dsm
	mp, c, snap := domainPlan(t, env, dsm)
	if e := mp.Apply(ctx, env, c); e != nil {
		t.Fatal(e)
	}
	if len(dsm.domains) != 2 || dsm.domains[1]["desc"] != domainMarker {
		t.Fatalf("domain not created: %+v", dsm.domains)
	}
	if e := mp.Apply(ctx, env, c); e != nil || len(dsm.domains) != 2 {
		t.Fatalf("second apply: %v", e)
	}
	// In use: removal refuses and leaves the domain.
	dsm.domains[1]["user_num"] = 1
	if e := mp.Rollback(ctx, env, c, snap); !errors.Is(e, ErrDomainInUse) || len(dsm.domains) != 2 {
		t.Fatalf("in-use domain: %v", e)
	}
	dsm.domains[1]["user_num"] = 0
	if e := mp.Rollback(ctx, env, c, snap); e != nil || len(dsm.domains) != 1 || dsm.domains[0]["name"] != "other.test" {
		t.Fatalf("rollback: %v %+v", e, dsm.domains)
	}
	if e := mp.Rollback(ctx, env, c, snap); e != nil {
		t.Fatalf("already removed: %v", e)
	}
	for _, call := range dsm.calls {
		if call == "SYNO.MailPlusServer.Domain.set" || call == "SYNO.MailPlusServer.Domain.set_security" {
			t.Fatalf("unexpected write %s", call)
		}
	}
}

func TestDomainRemovalLeavesAnotherDomainOfTheSameName(t *testing.T) {
	ctx := context.Background()
	env := fakeEnv()
	dsm := dsmFake()
	env.DSM = dsm
	mp, c, snap := domainPlan(t, env, dsm)
	if e := mp.Apply(ctx, env, c); e != nil {
		t.Fatal(e)
	}
	// Someone deleted ours and made their own with the same name.
	dsm.domains[1] = map[string]any{"domain_id": 99, "name": c.Params["domain"], "desc": "mine", "user_num": 0}
	if e := mp.Rollback(ctx, env, c, snap); !errors.Is(e, ErrStale) || len(dsm.domains) != 2 {
		t.Fatalf("foreign domain: %v", e)
	}
}

func TestDomainCreateWithALostReplyIsRecorded(t *testing.T) {
	ctx := context.Background()
	env := fakeEnv()
	dsm := dsmFake()
	env.DSM = dsm
	mp, c, snap := domainPlan(t, env, dsm)
	dsm.loseCreate = true
	if e := mp.Apply(ctx, env, c); e == nil {
		t.Fatal("lost reply reported success")
	}
	if e := mp.Apply(ctx, env, c); e != nil || len(dsm.domains) != 2 {
		t.Fatalf("reconcile: %v", e)
	}
	if e := mp.Rollback(ctx, env, c, snap); e != nil || len(dsm.domains) != 1 {
		t.Fatalf("rollback after reconcile: %v", e)
	}
}

func TestDomainPlanRefusesAnExistingDomain(t *testing.T) {
	env := fakeEnv()
	env.DSM = dsmFake()
	state := healthy()
	r := PlanRequest{SessionID: "domain", Domain: state.Domain, State: state, Decision: Decision{Needs: []string{"mailplus.domain"}}}
	if _, e := NewMailPlus().Plan(context.Background(), env, r, nil); !errors.Is(e, ErrStale) {
		t.Fatalf("existing domain: %v", e)
	}
}
