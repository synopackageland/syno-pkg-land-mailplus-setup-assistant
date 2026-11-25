package setup

import (
	"reflect"
	"slices"
	"testing"

	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

func healthy() detect.State {
	domain := "example.test"
	return detect.State{
		Domain:   domain,
		Package:  detect.Fact(detect.Package{Installed: true, Running: true}),
		SMTP:     detect.Fact(detect.SMTP{Enabled: true, Port: 25}),
		Domains:  detect.Fact([]detect.Domain{{ID: 1, Name: domain}}),
		Accounts: map[string]detect.Observation[[]detect.Account]{domain: detect.Fact([]detect.Account{{ID: 1, Name: "alice", Addresses: []string{"alice@" + domain}, Active: true}})},
		Signing:  map[string]detect.Observation[detect.Signing]{domain: detect.Fact(detect.Signing{Enabled: true, Selector: "mail", PublicKey: "public"})},
		Delivery: detect.Fact(detect.Delivery{Type: "none"}),
		Network:  detect.Network{EgressIPv4: detect.Fact("192.0.2.1"), Addressing: detect.Fact(detect.Fixed), PTR: detect.Fact([]string{"mail.example.test"}), FCrDNS: detect.Fact(true), Outbound25: detect.Fact(true), Inbound25: detect.Fact(true), DNSBL: []detect.DNSBL{{Provider: "fake", Status: "not_listed"}}, Tunnel: detect.Fact(detect.Tunnel{ID: "test-tunnel", Ready: true, SMTPHost: "10.0.0.2"})},
		DNS:      detect.DNS{Cloudflare: detect.Fact(true), MX: detect.Check{Status: "missing"}, SPF: detect.Check{Status: "missing"}, DMARC: detect.Check{Status: "missing"}, ParentDMARC: detect.Check{Status: "missing"}, DKIM: []detect.DKIM{{Selector: "mail", Status: "missing"}}},
	}
}

// yes answers every question "yes": the direct paths depend on the checks.
var yes = Answers{Route: RouteDirect}

func TestDecisionTable(t *testing.T) {
	direct := []string{"dns.spf", "dns.dmarc", "dns.dkim"}
	relay := []string{"cloudflare.sending", "relay.configure", "mailplus.delivery", "mailplus.dkim.disable"}
	cases := []struct {
		name    string
		intent  Intent
		mutate  func(*detect.State)
		gate    Branch
		send    Branch
		receive Branch
		reason  string
		needs   []string
	}{
		{name: "send-direct-only-DNS", intent: Send, send: DirectSend, needs: direct},
		{name: "receive-direct-only-A-MX", intent: Receive, receive: DirectReceive, needs: []string{"dns.a", "dns.mx"}},
		{name: "both-combines-independent-DNS", intent: Both, send: DirectSend, receive: DirectReceive, needs: append(append([]string{}, direct...), "dns.a", "dns.mx")},
		{name: "diagnose-without-package-probes", intent: Diagnose, gate: Handoff, needs: []string{}},
		{name: "check-handoff", intent: Check, gate: Handoff, needs: []string{}},
		{name: "invalid-intent", intent: Intent("other"), gate: Stop, reason: "invalidIntent"},
		{name: "package-unknown", intent: Send, mutate: func(s *detect.State) { s.Package = detect.Unavailable[detect.Package]() }, gate: Stop, reason: "unknown"},
		{name: "not-installed", intent: Both, mutate: func(s *detect.State) { s.Package = detect.Fact(detect.Package{}) }, gate: Stop, reason: "notInstalled"},
		{name: "stopped", intent: Receive, mutate: func(s *detect.State) { s.Package.Value.Running = false }, gate: Stop, reason: "stopped"},
		{name: "broken", intent: Send, mutate: func(s *detect.State) { s.Package.Value.Broken = true }, gate: Stop, reason: "broken"},
		{name: "smtp-only-minimal", intent: Send, mutate: func(s *detect.State) { s.SMTP.Value.Enabled = false }, gate: Minimal, reason: "configureMailPlus", needs: []string{"mailplus.smtp"}},
		{name: "new-domain-existing-users-needed", intent: Receive, mutate: func(s *detect.State) { s.Domains = detect.Fact([]detect.Domain{}) }, gate: Minimal, reason: "configureMailPlus", needs: []string{"mailplus.domain", "mailplus.members"}},
		// MailPlus Server is set up (it has another domain): the App
		// creates the missing one. Sending goes on, receiving waits for a
		// member; receiving alone stays with MailPlus Server's wizard; the own-IP
		// route needs DKIM, which a new domain does not sign.
		{name: "creatable-domain-relay-send", intent: Send, mutate: func(s *detect.State) {
			s.Network.Outbound25 = detect.Fact(false)
			s.Domains = detect.Fact([]detect.Domain{{ID: 7, Name: "other.test"}})
			delete(s.Accounts, s.Domain)
			delete(s.Signing, s.Domain)
		}, send: RelaySend, needs: []string{"mailplus.domain", "cloudflare.sending", "relay.configure", "mailplus.delivery"}},
		{name: "creatable-domain-receive-only-guides", intent: Receive, mutate: func(s *detect.State) {
			s.Domains = detect.Fact([]detect.Domain{{ID: 7, Name: "other.test"}})
			delete(s.Accounts, s.Domain)
		}, gate: Minimal, reason: "configureMailPlus", needs: []string{"mailplus.domain", "mailplus.members"}},
		{name: "creatable-domain-direct-needs-dkim", intent: Send, mutate: func(s *detect.State) {
			s.Domains = detect.Fact([]detect.Domain{{ID: 7, Name: "other.test"}})
			delete(s.Accounts, s.Domain)
			delete(s.Signing, s.Domain)
		}, gate: Stop, send: DirectSend, reason: "dkimRequired"},
		// Receiving needs an enabled mailbox; sending does not.
		{name: "no-active-accounts-receive", intent: Receive, mutate: func(s *detect.State) { s.Accounts[s.Domain].Value[0].Active = false }, gate: Minimal, reason: "configureMailPlus", needs: []string{"mailplus.members"}},
		{name: "no-active-accounts-send-goes-on", intent: Send, mutate: func(s *detect.State) { s.Accounts[s.Domain].Value[0].Active = false }, send: DirectSend, needs: direct},
		{name: "no-active-accounts-both-sends-only", intent: Both, mutate: func(s *detect.State) { s.Accounts[s.Domain].Value[0].Active = false }, send: DirectSend, needs: direct},
		{name: "accounts-unknown", intent: Send, mutate: func(s *detect.State) { delete(s.Accounts, s.Domain) }, gate: Stop, reason: "unknown"},
		{name: "dynamic-send", intent: Send, mutate: func(s *detect.State) { s.Network.Addressing = detect.Fact(detect.Changing) }, send: RelaySend, needs: relay},
		{name: "bad-ptr-send", intent: Send, mutate: func(s *detect.State) { s.Network.FCrDNS = detect.Fact(false) }, send: RelaySend, needs: relay},
		{name: "blocked-send", intent: Send, mutate: func(s *detect.State) { s.Network.Outbound25 = detect.Fact(false) }, send: RelaySend, needs: relay},
		{name: "listed-send", intent: Send, mutate: func(s *detect.State) { s.Network.DNSBL[0].Status = "listed" }, send: RelaySend, needs: relay},
		{name: "unknown-DNSBL-is-not-usable", intent: Send, mutate: func(s *detect.State) { s.Network.DNSBL[0].Status = "unknown" }, send: RelaySend, needs: relay},
		{name: "empty-DNSBL-is-not-usable", intent: Send, mutate: func(s *detect.State) { s.Network.DNSBL = nil }, send: RelaySend, needs: relay},
		{name: "unchecked-static-answer-stands", intent: Send, mutate: func(s *detect.State) { s.Network.Addressing = detect.Unavailable[detect.Addressing]() }, send: DirectSend, needs: direct},
		{name: "unknown-port-is-not-usable", intent: Send, mutate: func(s *detect.State) { s.Network.Outbound25 = detect.Unavailable[bool]() }, send: RelaySend, needs: relay},
		{name: "existing-relay-protected", intent: Send, mutate: func(s *detect.State) { s.Network.Outbound25 = detect.Fact(false); s.Delivery.Value.Type = "list" }, gate: Stop, send: RelaySend, reason: "existingRelay"},
		{name: "relay-signing-already-off", intent: Send, mutate: func(s *detect.State) {
			s.Network.Outbound25 = detect.Fact(false)
			v := s.Signing[s.Domain]
			v.Value.Enabled = false
			s.Signing[s.Domain] = v
		}, send: RelaySend, needs: relay[:3]},
		{name: "dynamic-receive-only-routing", intent: Receive, mutate: func(s *detect.State) { s.Network.Addressing = detect.Fact(detect.Changing) }, receive: RoutingReceive, needs: []string{"cloudflare.inbound"}},
		{name: "blocked-receive-only-routing", intent: Receive, mutate: func(s *detect.State) { s.Network.Inbound25 = detect.Fact(false) }, receive: RoutingReceive, needs: []string{"cloudflare.inbound"}},
		// The tunnel is read from Cloudflare by the plan (after the token), so an
		// unknown tunnel in detection no longer stops the decision.
		{name: "unknown-tunnel-decided-at-plan", intent: Receive, mutate: func(s *detect.State) {
			s.Network.Inbound25 = detect.Fact(false)
			s.Network.Tunnel = detect.Unavailable[detect.Tunnel]()
		}, receive: RoutingReceive, needs: []string{"cloudflare.inbound"}},
		{name: "unchecked-inbound-answer-stands", intent: Receive, mutate: func(s *detect.State) { s.Network.Inbound25 = detect.Unavailable[bool]() }, receive: DirectReceive, needs: []string{"dns.a", "dns.mx"}},
		{name: "send-ignores-inbound", intent: Send, mutate: func(s *detect.State) { s.Network.Inbound25 = detect.Unavailable[bool]() }, send: DirectSend, needs: direct},
		{name: "receive-ignores-outbound-and-DNSBL", intent: Receive, mutate: func(s *detect.State) { s.Network.Outbound25 = detect.Unavailable[bool](); s.Network.DNSBL = nil }, receive: DirectReceive, needs: []string{"dns.a", "dns.mx"}},
		{name: "manual-DNS-direct", intent: Send, mutate: func(s *detect.State) { s.DNS.Cloudflare = detect.Fact(false) }, gate: Stop, send: DirectSend, reason: "manualDNS", needs: direct},
		{name: "non-cloudflare-relay-needs-migration", intent: Send, mutate: func(s *detect.State) {
			s.DNS.Cloudflare = detect.Fact(false)
			s.Network.Outbound25 = detect.Fact(false)
		}, gate: Stop, send: RelaySend, reason: "moveDNS"},
		{name: "non-cloudflare-inbound-needs-migration", intent: Receive, mutate: func(s *detect.State) { s.DNS.Cloudflare = detect.Fact(false); s.Network.Inbound25 = detect.Fact(false) }, gate: Stop, receive: RoutingReceive, reason: "moveDNS"},
		{name: "already-verified-send-no-network-needed", intent: Send, mutate: func(s *detect.State) { s.SendReady = detect.Fact(true); s.Network = detect.Network{} }, send: Already, reason: "alreadyCorrect", needs: []string{}},
		{name: "already-both", intent: Both, mutate: func(s *detect.State) { s.SendReady = detect.Fact(true); s.ReceiveReady = detect.Fact(true) }, send: Already, receive: Already, reason: "alreadyCorrect", needs: []string{}},
		{name: "both-preserves-already-send", intent: Both, mutate: func(s *detect.State) { s.SendReady = detect.Fact(true) }, send: Already, receive: DirectReceive, needs: []string{"dns.a", "dns.mx"}},
		{name: "both-blocks-hidden-partial-send", intent: Both, mutate: func(s *detect.State) { s.DNS.MX.Status = "unknown" }, gate: Stop, send: DirectSend, receive: DirectReceive, reason: "unknown"},
		{name: "both-mixed-direct-and-routing", intent: Both, mutate: func(s *detect.State) { s.Network.Inbound25 = detect.Fact(false) }, send: DirectSend, receive: RoutingReceive, needs: append(append([]string{}, direct...), "cloudflare.inbound")},
		{name: "existing-MX-is-not-delivery-evidence", intent: Receive, mutate: func(s *detect.State) { s.DNS.MX.Status = "present" }, gate: Stop, receive: DirectReceive, reason: "dnsConflict"},
		{name: "confirmed-existing-MX", intent: Receive, mutate: func(s *detect.State) { s.DNS.MX.Status = "present"; s.DNS.ReceiveRecords = detect.Fact(true) }, receive: DirectReceive, reason: "dnsReady", needs: []string{}},
		{name: "existing-DNS-no-false-delivery-success", intent: Send, mutate: func(s *detect.State) {
			s.DNS.SPF.Status = "present"
			s.DNS.DMARC.Status = "present"
			s.DNS.DKIM[0].Status = "present"
		}, send: DirectSend, reason: "dnsReady", needs: []string{}},
		{name: "invalid-SPF", intent: Send, mutate: func(s *detect.State) { s.DNS.SPF.Status = "fail" }, gate: Stop, send: DirectSend, reason: "dnsConflict"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := healthy()
			if tc.mutate != nil {
				tc.mutate(&s)
			}
			d := Decide(s, tc.intent, yes)
			if d.Gate != tc.gate || d.Send != tc.send || d.Receive != tc.receive || d.Reason != tc.reason || !reflect.DeepEqual(d.Needs, tc.needs) {
				t.Fatalf("got %+v; want gate=%s send=%s receive=%s reason=%s needs=%v", d, tc.gate, tc.send, tc.receive, tc.reason, tc.needs)
			}
		})
	}
}

// A domain without an enabled mailbox: receive alone stops at MailPlus
// Server, naming the missing mailbox; both sets up sending alone and says
// receiving waits; send alone is not held up at all. A missing domain stops
// every intent, naming the domain.
func TestMailboxOnlyHoldsReceiving(t *testing.T) {
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: &fakeCloud{}, Verifier: verifier{}})
	noMailbox := healthy()
	noMailbox.Accounts[noMailbox.Domain].Value[0].Active = false
	for _, route := range routes {
		a := Answers{Route: route}
		b := w.branch(noMailbox, Receive, a)
		if b.Kind != "configureMailPlus" || b.TitleKey != "mail.setup.prereq.noMailbox" || b.BodyKey != "mail.setup.prereq.noMailboxBody" || b.Params["domain"] != noMailbox.Domain || b.ReceivePending {
			t.Fatalf("receive %q: %+v", route, b)
		}
		d := Decide(noMailbox, Both, a)
		if !d.ReceivePending || d.Receive != "" || d.ReceiveWhy != nil || d.Send == "" || hasPrefixNeed(d, "cloudflare.inbound") {
			t.Fatalf("both %q: %+v", route, d)
		}
		if b := w.branch(noMailbox, Both, a); !b.ReceivePending || len(b.Paths) != 1 || b.Paths[0].Direction != "send" {
			t.Fatalf("both branch %q: %+v", route, b)
		}
		if d := Decide(noMailbox, Send, a); d.ReceivePending || d.Gate == Minimal || d.Send == "" {
			t.Fatalf("send %q: %+v", route, d)
		}
	}
	// Already-correct sending with receiving pending is not "already correct" for receiving.
	ready := healthy()
	ready.Accounts[ready.Domain].Value[0].Active = false
	ready.SendReady = detect.Fact(true)
	if d := Decide(ready, Both, yes); !d.ReceivePending || d.Send != Already || d.Receive != "" || d.Reason != "alreadyCorrect" {
		t.Fatalf("already send: %+v", d)
	}
	// own IP, no DMARC of its own: a parent's policy applies, so no
	// p=none is planned; an unknown parent waits for a check, never guesses.
	inherit := healthy()
	inherit.DNS.ParentDMARC = detect.Check{Status: "present", Values: []string{"v=DMARC1; p=reject"}, Detail: "example.test"}
	if d := Decide(inherit, Send, yes); d.Gate != "" || d.Send != DirectSend || slices.Contains(d.Needs, "dns.dmarc") || !slices.Contains(d.Needs, "dns.spf") {
		t.Fatalf("parent DMARC: %+v", d)
	}
	if d := Decide(healthy(), Send, yes); !slices.Contains(d.Needs, "dns.dmarc") {
		t.Fatalf("no policy: %+v", d)
	}
	inherit.DNS.ParentDMARC = detect.Check{Status: "unknown"}
	if d := Decide(inherit, Send, yes); d.Gate == "" || slices.Contains(d.Needs, "dns.dmarc") {
		t.Fatalf("unknown parent DMARC: %+v", d)
	}
	creatable := healthy()
	creatable.Network.Outbound25 = detect.Fact(false)
	creatable.Domains = detect.Fact([]detect.Domain{{ID: 7, Name: "other.test"}})
	delete(creatable.Accounts, creatable.Domain)
	if d := Decide(creatable, Both, yes); !d.ReceivePending || d.Send != RelaySend || d.Receive != "" || d.Gate != "" || d.Needs[0] != "mailplus.domain" {
		t.Fatalf("creatable both: %+v", d)
	}
	missing := healthy()
	missing.Domains = detect.Fact([]detect.Domain{})
	for _, i := range []Intent{Send, Receive, Both} {
		if b := w.branch(missing, i, yes); b.Kind != "configureMailPlus" || b.TitleKey != "mail.setup.prereq.noDomain" || b.Params["domain"] != missing.Domain {
			t.Fatalf("missing domain %s: %+v", i, b)
		}
	}
}
