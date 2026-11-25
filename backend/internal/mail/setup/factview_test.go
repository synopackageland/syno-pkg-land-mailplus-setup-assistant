package setup

import (
	"strings"
	"testing"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

func factByLabel(facts []core.Fact, label string) core.Fact {
	for _, f := range facts {
		if f.LabelKey == "mail.setup.fact."+label {
			return f
		}
	}
	return core.Fact{}
}

// Every detection fact gets a group and a state, and nothing is dropped: an
// unrelated fact stays in the list, only marked.
func TestAnnotateFactsKeepsEveryFact(t *testing.T) {
	s := healthy()
	raw := detect.Facts(s)
	for _, route := range routes {
		for _, i := range []Intent{Send, Receive, Both} {
			got := annotateFacts(raw, s, i, Answers{Route: route})
			if len(got) != len(raw) {
				t.Fatalf("%s/%q dropped facts: %d of %d", i, route, len(got), len(raw))
			}
			for k, f := range got {
				if f.LabelKey != raw[k].LabelKey || f.Value != raw[k].Value {
					t.Fatalf("fact %d changed: %+v", k, f)
				}
				if f.Group == "" || f.State == "" {
					t.Fatalf("%s has no group or state: %+v", f.LabelKey, f)
				}
				if route == "" && f.Unrelated {
					t.Fatalf("before a route is chosen every fact is related: %+v", f)
				}
			}
		}
	}
}

func TestAnnotateFactsStates(t *testing.T) {
	s := healthy()
	s.Network.PTR = detect.Fact([]string{})
	s.Network.Inbound25 = detect.Observation[bool]{Status: detect.Unknown, Detail: detect.CauseNotChecked}
	s.Network.FCrDNS = detect.Unavailable[bool]()
	s.Accounts[s.Domain].Value[0].Active = false
	facts := annotateFacts(detect.Facts(s), s, Both, yes)
	for label, want := range map[string]string{
		"package": FactOK, "ptr": FactProblem, "inbound": FactNotChecked, "fcrdns": FactUnknown, "accounts": FactProblem,
	} {
		if f := factByLabel(facts, label); f.State != want {
			t.Fatalf("%s: state %q, want %q (%+v)", label, f.State, want, f)
		}
	}
	if f := factByLabel(facts, "ptr"); f.Status != core.SeverityWarning || f.Group != GroupNetwork {
		t.Fatalf("ptr: %+v", f)
	}
	// Sending alone needs no mailbox: no enabled account is not a problem there.
	if f := factByLabel(annotateFacts(detect.Facts(s), s, Send, yes), "accounts"); f.State != FactOK {
		t.Fatalf("send accounts: %+v", f)
	}
	// A domain MailPlus Server does not have is a certain negative, not
	// unknown, where the plan does not create it (receiving alone).
	s = healthy()
	s.Domains = detect.Fact([]detect.Domain{{Name: "other.test"}})
	delete(s.Accounts, s.Domain)
	if f := factByLabel(annotateFacts(detect.Facts(s), s, Receive, yes), "accounts"); f.State != FactProblem || !strings.HasSuffix(f.Value, "notInMailPlus") {
		t.Fatalf("not in MailPlus: %+v", f)
	}
}

// a plan that creates the MailPlus Server mail domain does not warn
// about what only the new domain lacks. The domain list is planned; the new
// domain's accounts and DKIM are unrelated (planned by the domain step, never
// a problem); receiving waits, so MX is unrelated too.
func TestAnnotateFactsNewDomain(t *testing.T) {
	s := healthy()
	s.Domains = detect.Fact([]detect.Domain{{Name: "other.test"}})
	delete(s.Accounts, s.Domain)
	delete(s.Signing, s.Domain)
	s.DNS.Exists = detect.Check{Status: "missing"}
	for _, i := range []Intent{Send, Both} {
		facts := annotateFacts(detect.Facts(s), s, i, Answers{Route: RouteCloudflare})
		if d := Decide(s, i, Answers{Route: RouteCloudflare}); !hasNeed(d, "mailplus.domain") || d.Blocked() {
			t.Fatalf("%s: the decision does not create the domain: %+v", i, d)
		}
		for _, f := range facts {
			if mine := map[string]bool{"mail.setup.fact.domains": true, "mail.setup.fact.accounts": true, "mail.setup.fact.dkim": true}; mine[f.LabelKey] && !f.Unrelated && (f.State == FactProblem || f.State == FactUnknown) {
				t.Fatalf("%s: MailPlus fact needs attention: %+v", i, f)
			}
			if f.LabelKey == "mail.setup.fact.mx" && !f.Unrelated && f.State == FactProblem {
				t.Fatalf("%s: MX is a problem while receiving waits: %+v", i, f)
			}
		}
		if f := factByLabel(facts, "domains"); f.State != FactPlanned || f.NoteKey != noteMailPlusDomain || f.Unrelated || f.Status != core.SeverityInfo {
			t.Fatalf("%s domains: %+v", i, f)
		}
		for _, label := range []string{"accounts", "dkim"} {
			if f := factByLabel(facts, label); !f.Unrelated || f.State != FactPlanned || f.NoteKey != noteMailPlusDomain || f.Status != core.SeverityInfo {
				t.Fatalf("%s %s: %+v", i, label, f)
			}
		}
		if i == Both && !factByLabel(facts, "mx").Unrelated {
			t.Fatalf("both: MX is related while receiving waits")
		}
	}
	// A plan that stops (own IP: a new domain has no DKIM key) plans nothing.
	for _, f := range annotateFacts(detect.Facts(s), s, Send, yes) {
		if f.State == FactPlanned && f.Group == GroupMailPlus {
			t.Fatalf("stopped plan planned %+v", f)
		}
	}
}

// Only the facts the chosen route and intent need are related; the rest stay,
// marked unrelated.
func TestAnnotateFactsRelevance(t *testing.T) {
	s := healthy()
	related := func(i Intent, r Route) map[string]bool {
		out := map[string]bool{}
		for _, f := range annotateFacts(detect.Facts(s), s, i, Answers{Route: r}) {
			out[strings.TrimPrefix(f.LabelKey, "mail.setup.fact.")] = !f.Unrelated
		}
		return out
	}
	cf := related(Both, RouteCloudflare)
	for _, label := range []string{"ptr", "fcrdns", "dnsbl", "outbound", "inbound", "addressing", "ip"} {
		if cf[label] {
			t.Fatalf("cloudflare route: %s is related", label)
		}
	}
	if !cf["tunnel"] || !cf["accounts"] || !cf["dns"] {
		t.Fatalf("cloudflare route: %v", cf)
	}
	d := related(Send, RouteDirect)
	if !d["ptr"] || !d["outbound"] || d["inbound"] || d["tunnel"] || d["mx"] {
		t.Fatalf("direct send: %v", d)
	}
	r := related(Receive, RouteDirect)
	if r["ptr"] || r["outbound"] || !r["inbound"] || !r["mx"] || r["spf"] {
		t.Fatalf("direct receive: %v", r)
	}
}

// What the decided plan will create is not a problem: on a name DNS does not
// know yet, the Cloudflare route's records show as planned, with the reason.
func TestAnnotateFactsPlanned(t *testing.T) {
	fresh := func() detect.State {
		s := healthy()
		s.DNS.Exists = detect.Check{Status: "missing"}
		return s
	}
	state := func(facts []core.Fact, label string) (string, string, core.Severity) {
		f := factByLabel(facts, label)
		return f.State, f.NoteKey, f.Status
	}
	s := fresh()
	cf := annotateFacts(detect.Facts(s), s, Both, Answers{Route: RouteCloudflare})
	for label, note := range map[string]string{"mx": noteRouting, "spf": noteRouting, "domainDNS": noteRouting} {
		if st, n, sev := state(cf, label); st != FactPlanned || n != note || sev != core.SeverityInfo {
			t.Fatalf("cloudflare both %s: %q %q %q", label, st, n, sev)
		}
	}
	if st, n, _ := state(cf, "dmarc"); st != FactOptional || n != noteDMARC {
		t.Fatalf("cloudflare dmarc: %q %q", st, n)
	}
	for _, f := range cf {
		if f.State == FactProblem && absent(f) {
			t.Fatalf("absent record still a problem: %+v", f)
		}
	}
	// Sending alone: Email Sending writes its own records under the name, not
	// the name's SPF or MX; the name's SPF is not needed by the relay.
	snd := annotateFacts(detect.Facts(s), s, Send, Answers{Route: RouteCloudflare})
	if st, n, _ := state(snd, "domainDNS"); st != FactPlanned || n != noteSending {
		t.Fatalf("cloudflare send domainDNS: %q %q", st, n)
	}
	if st, n, _ := state(snd, "spf"); st != FactOptional || n != noteSPF {
		t.Fatalf("cloudflare send spf: %q %q", st, n)
	}
	if st, _, _ := state(snd, "mx"); st == FactPlanned {
		t.Fatalf("cloudflare send plans no MX")
	}
	// Own IP: the dns.* steps create SPF and DMARC.
	s = healthy()
	d := annotateFacts(detect.Facts(s), s, Send, yes)
	for _, label := range []string{"spf", "dmarc"} {
		if st, n, _ := state(d, label); st != FactPlanned || n != noteDNS {
			t.Fatalf("direct send %s: %q %q", label, st, n)
		}
	}
	// own IP with a parent's DMARC policy: DMARC is optional, as on
	// the Cloudflare route, and nothing creates it.
	s = healthy()
	s.DNS.ParentDMARC = detect.Check{Status: "present", Values: []string{"v=DMARC1; p=reject"}, Detail: "example.test"}
	if st, n, _ := state(annotateFacts(detect.Facts(s), s, Send, yes), "dmarc"); st != FactOptional || n != noteDMARC {
		t.Fatalf("direct send inherited dmarc: %q %q", st, n)
	}
	// A plan that cannot run plans nothing: MailPlus Server has no domain at
	// all (its first-run setup is not done).
	s = fresh()
	s.Domains = detect.Fact([]detect.Domain{})
	delete(s.Accounts, s.Domain)
	for _, f := range annotateFacts(detect.Facts(s), s, Both, Answers{Route: RouteCloudflare}) {
		if f.State == FactPlanned {
			t.Fatalf("minimal gate planned %+v", f)
		}
	}
	// Before a route is chosen nothing is planned either.
	for _, f := range annotateFacts(detect.Facts(s), s, Both, Answers{}) {
		if f.State == FactPlanned {
			t.Fatalf("no route planned %+v", f)
		}
	}
}
