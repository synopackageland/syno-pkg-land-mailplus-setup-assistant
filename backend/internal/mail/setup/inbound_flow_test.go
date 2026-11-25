package setup

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

// sequenceVerifier answers each verification with the next result.
type sequenceVerifier struct {
	mu      sync.Mutex
	results []Verification
	calls   int
}

func (v *sequenceVerifier) Verify(context.Context, core.Env, PlanRequest, []core.Change) (Verification, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	r := v.results[min(v.calls, len(v.results)-1)]
	v.calls++
	return r, nil
}

func TestCheckAgainReverifiesWithoutWritingOrRollingBack(t *testing.T) {
	env := fakeEnv()
	ctx := context.Background()
	f := &fakeCloud{restorable: true, value: "original"}
	check := core.Finding{ID: "mail.setup.inbound", Severity: core.SeverityWarning, TitleKey: "mail.setup.inbound.checkMail", Params: map[string]string{"code": "MPSA-1"}}
	v := &sequenceVerifier{results: []Verification{
		{Readback: true, Findings: []core.Finding{check}},
		{Readback: true, Delivery: true, Findings: []core.Finding{{ID: "mail.setup.inbound", Severity: core.SeverityOK, TitleKey: "mail.setup.inbound.delivered"}}},
	}}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: f, Verifier: v})
	id, _ := ready(t, w, env, Send)
	if _, e := w.Decide(ctx, env, owner, id, "verify"); !errors.Is(e, ErrBusy) {
		t.Fatal("check again accepted before apply")
	}
	preview(t, w, env, id)
	if _, e := w.Apply(ctx, env, owner, id); e != nil {
		t.Fatal(e)
	}
	first := wait(t, w, env, id)
	if first.Phase != PhaseDecision || first.Verified || first.Findings[0].Params["code"] != "MPSA-1" {
		t.Fatalf("first verification: %+v", first)
	}
	writes := f.writes
	started, e := w.Decide(ctx, env, owner, id, "verify")
	if e != nil || started.Phase != PhaseVerifying {
		t.Fatalf("check again: %+v %v", started, e)
	}
	second := wait(t, w, env, id)
	if second.Phase != PhaseDecision || !second.Verified || f.writes != writes || f.undos != 0 {
		t.Fatalf("second verification: %+v writes=%d undos=%d", second, f.writes, f.undos)
	}
	if _, e := w.Decide(ctx, env, owner, id, "verify"); !errors.Is(e, ErrBusy) {
		t.Fatal("check again offered after success")
	}
	if kept, e := w.Decide(ctx, env, owner, id, "keep"); e != nil || kept.Outcome != "ok" {
		t.Fatalf("keep: %+v %v", kept, e)
	}
}

func TestInterruptedCheckAgainKeepsTheDecision(t *testing.T) {
	env := fakeEnv()
	ctx := context.Background()
	w := directWizard(&fakeCloud{restorable: true}, verifier{result: Verification{Readback: true}})
	id, _ := ready(t, w, env, Send)
	preview(t, w, env, id)
	if _, e := w.Apply(ctx, env, owner, id); e != nil {
		t.Fatal(e)
	}
	wait(t, w, env, id)
	// A worker restart during check again: verifying with nobody running.
	if _, e := w.update(ctx, env, owner, id, func(f *Flow) error { f.Phase = PhaseVerifying; return nil }); e != nil {
		t.Fatal(e)
	}
	v, e := w.Status(ctx, env, owner, id)
	if e != nil || v.Phase != PhaseDecision {
		t.Fatalf("interrupted check again: %+v %v", v, e)
	}
}

func TestPreviewOffersTunnelChoice(t *testing.T) {
	env := fakeEnv()
	ctx := context.Background()
	options := []TunnelOption{{ID: "11111111-2222-4333-8444-555555555555", Name: "synopkgconnect-nas-1", Connect: true, Match: true},
		{ID: "66666666-7777-4888-8999-aaaaaaaaaaaa", Name: "office", Match: true}}
	f := &fakeCloud{restorable: true, planErr: TunnelChoice{Options: options}}
	w := directWizard(f, verifier{result: Verification{Readback: true, Delivery: true}})
	id, _ := ready(t, w, env, Send)
	if _, e := permissions(w, ctx, env, owner, id, strings.Repeat("a", 32), strings.Repeat("b", 32)); e != nil {
		t.Fatal(e)
	}
	p, e := w.Preview(ctx, env, owner, id, Configuration{})
	if e != nil || p.Pending || len(p.Tunnels) != 2 || !p.Tunnels[0].Connect || len(p.Changes) != 0 {
		t.Fatalf("tunnel choice: %+v %v", p, e)
	}
	if _, e := w.Apply(ctx, env, owner, id); !errors.Is(e, ErrBusy) {
		t.Fatal("a tunnel choice is not a plan")
	}
	// A tunnel pick belongs to the inbound path only.
	if _, e := w.Preview(ctx, env, owner, id, Configuration{Tunnel: options[0].ID}); !errors.Is(e, ErrInvalid) {
		t.Fatalf("tunnel accepted for a send-only flow: %v", e)
	}
}

func TestInboundPermissionsAreNamedNotCounted(t *testing.T) {
	account, zone := strings.Repeat("a", 32), strings.Repeat("b", 32)
	d := Decision{Receive: RoutingReceive}
	base := []Permission{{Scope: "zone", Resource: zone, Name: "Zone Read"}, {Scope: "zone", Resource: zone, Name: "DNS Write"}}
	five := append([]Permission{}, base...)
	for i := 0; i < 5; i++ {
		five = append(five, Permission{Scope: "account", Resource: account, Name: "Connectivity Directory Admin"})
	}
	if validPermissions(five, account, zone, d) {
		t.Fatal("five permissions of the wrong names accepted")
	}
	all := append([]Permission{}, base...)
	for _, p := range InboundPermissions {
		p.Resource = account
		if p.Scope == "zone" {
			p.Resource = zone
		}
		all = append(all, p)
	}
	if !validPermissions(all, account, zone, d) {
		t.Fatal("the exact inbound inventory refused")
	}
	for _, p := range InboundPermissions {
		if strings.Contains(p.Name, "Email Routing Settings") {
			t.Fatal("permission group that does not exist")
		}
	}
}

func TestTunnelIDShape(t *testing.T) {
	for v, want := range map[string]bool{
		"11111111-2222-4333-8444-555555555555": true, "11111111-2222-4333-8444-55555555555": false,
		"11111111-2222-4333-8444-55555555555G": false, "1111111122224333844455555555555555": false,
	} {
		if tunnelID(v) != want {
			t.Errorf("%s", v)
		}
	}
}

func TestPermissionRefusalKeepsOnlyKnownCodes(t *testing.T) {
	refused := PermissionRefused{Code: PermVPCAdmin}
	if got := publicCode(publicError(refused)); got != "mail.setup.permissionRefused.vpcAdmin" {
		t.Fatalf("got %q", got)
	}
	if got := publicCode(publicError(PermissionRefused{Code: "invented"})); got != ErrUnavailable.Error() {
		t.Fatalf("unknown code published: %q", got)
	}
}

// The addresses that receive through Cloudflare come from MailPlus Server's
// Domain.User list for the selected domain: enabled accounts only, addresses
// of exactly that domain, no "*" or relay-shaped local part, each once.
func TestMailboxesFromDomainUsers(t *testing.T) {
	s := healthy()
	s.Accounts[s.Domain] = detect.Fact([]detect.Account{
		{ID: 1, Name: "alice", Addresses: []string{"alice@example.test", "ALICE@example.test", "a.lice@example.test"}, Active: true},
		{ID: 2, Name: "bob", Addresses: []string{"bob@example.test"}, Active: false},
		{ID: 3, Name: "carol", Addresses: []string{"carol@other.test", "carol@sub.example.test", "*@example.test", "x%y@example.test", "x!y@example.test", "Carol <carol@example.test>"}, Active: true},
		{ID: 4, Name: "dave", Addresses: []string{"dave@EXAMPLE.TEST"}, Active: true},
	})
	s.Accounts["other.test"] = detect.Fact([]detect.Account{{ID: 9, Name: "zed", Addresses: []string{"zed@other.test"}, Active: true}})
	got := Mailboxes(s)
	want := []string{"a.lice@example.test", "alice@example.test", "dave@example.test"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	d := Decision{Receive: RoutingReceive, Needs: []string{"cloudflare.inbound"}}
	f := form{AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), TokenRef: "secret:t"}
	r, err := makeRequest(strings.Repeat("c", 32), s, Receive, d, f)
	if err != nil || !reflect.DeepEqual(r.Addresses, want) {
		t.Fatalf("request addresses %q, %v", r.Addresses, err)
	}
	// No enabled mailbox, or an unread list: nothing to receive, no plan.
	s.Accounts[s.Domain] = detect.Fact([]detect.Account{{ID: 2, Name: "bob", Addresses: []string{"bob@example.test"}, Active: false}})
	if _, err := makeRequest(strings.Repeat("c", 32), s, Receive, d, f); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no mailbox: %v", err)
	}
	s.Accounts[s.Domain] = detect.Observation[[]detect.Account]{Status: detect.Unknown}
	if Mailboxes(s) != nil {
		t.Fatal("unknown list gave mailboxes")
	}
	// More than one setup's rule budget is the plain rules-limit refusal.
	many := []detect.Account{}
	for i := 0; i < maxMailboxes+1; i++ {
		many = append(many, detect.Account{ID: i, Name: fmt.Sprint("u", i), Addresses: []string{fmt.Sprintf("u%d@example.test", i)}, Active: true})
	}
	s.Accounts[s.Domain] = detect.Fact(many)
	if _, err := makeRequest(strings.Repeat("c", 32), s, Receive, d, f); !errors.Is(err, ErrRulesLimit) {
		t.Fatalf("over the limit: %v", err)
	}
	// the whole domain needs no rule per mailbox, so no limit.
	whole := f
	whole.Receive = ReceiveDomain
	if r, err := makeRequest(strings.Repeat("c", 32), s, Receive, d, whole); err != nil || r.ReceiveMode != ReceiveDomain || len(r.Addresses) != maxMailboxes {
		t.Fatalf("whole domain: %v %d", err, len(r.Addresses))
	}
}

// the receiving mode is a choice of receiving through Cloudflare only.
func TestReceiveModeInTheRequest(t *testing.T) {
	s := healthy()
	s.Accounts[s.Domain] = detect.Fact([]detect.Account{{ID: 1, Name: "alice", Addresses: []string{"alice@example.test"}, Active: true}})
	d := Decision{Receive: RoutingReceive, Needs: []string{"cloudflare.inbound"}}
	f := form{AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), TokenRef: "secret:t"}
	for receive, want := range map[string]string{"": ReceiveAddresses, "addresses": ReceiveAddresses, "domain": ReceiveDomain} {
		f.Receive = receive
		if r, err := makeRequest(strings.Repeat("c", 32), s, Receive, d, f); err != nil || r.ReceiveMode != want {
			t.Errorf("%q: %q %v", receive, r.ReceiveMode, err)
		}
	}
	f.Receive = "catchall"
	if _, err := makeRequest(strings.Repeat("c", 32), s, Receive, d, f); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown mode: %v", err)
	}
	// Not receiving through Cloudflare: no mode at all.
	f.Receive = "domain"
	if _, err := makeRequest(strings.Repeat("c", 32), s, Send, Decision{Send: DirectSend, Needs: []string{"dns.dmarc"}}, f); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mode without Cloudflare receiving: %v", err)
	}
}

// Email Sending refused by the Cloudflare plan keeps its plain key through the
// preview/apply refusal and the sign-in check (wrapped or not).
func TestSendingPlanKeepsItsKey(t *testing.T) {
	wrapped := fmt.Errorf("prepare: %w", ErrSendingPlan)
	if got := publicCode(publicError(wrapped)); got != "mail.setup.sendingPlan" {
		t.Fatalf("publicError: %q", got)
	}
	if got := directoryError(wrapped); !errors.Is(got, ErrSendingPlan) {
		t.Fatalf("directoryError: %v", got)
	}
}

// While applying (the sender's onboarding refused), the flow's error is the same key.
func TestSendingPlanIsTheApplyError(t *testing.T) {
	if got := publicCode(fmt.Errorf("onboard: %w", ErrSendingPlan)); got != "mail.setup.sendingPlan" {
		t.Fatalf("%q", got)
	}
}
