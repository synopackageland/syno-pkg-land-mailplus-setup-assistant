package diagnose

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

func summarize(t *testing.T, symptom Symptom, d *Diagnostics, state State) Summary {
	t.Helper()
	plan, _ := PlanFor(symptom)
	fs, err := d.Evaluate(context.Background(), core.Env{Now: func() time.Time { return testNow }}, state, nil, plan.Checks...)
	if err != nil {
		t.Fatal(err)
	}
	return Summarize(plan.Checks, Rank(symptom, fs))
}

func problemKeys(ps []Problem) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.Key)
	}
	return out
}

func otherByKey(s Summary, key string) []Other {
	out := []Other{}
	for _, o := range s.Others {
		if o.Key == key {
			out = append(out, o)
		}
	}
	return out
}

// The owner's case (2026-11-12): "not sure" on a NAS with three domains that
// have no DMARC of their own, and nothing this version can observe for the
// mail path, accounts, inbound or phone. It listed a dozen info cards; now
// there is no problem, one DMARC line for all domains and one not-checked line.
func TestSummaryNotSureShowsNoNoise(t *testing.T) {
	dns := goodDNS()
	domains := []string{"sample-nas.test", "testmail.example.test", "zz.example.test"}
	state := State{Installed: ptr(true), Running: ptr(true), SMTPEnabled: ptr(true),
		Queue: QueueState{Total: ptr(0)}, Relay: RelayState{Enabled: ptr(false)}}
	for _, name := range domains {
		state.Domains = append(state.Domains, MailDomain{Name: name, Selectors: []string{"mail"}})
		dns.txt[name] = []string{"v=spf1 ip4:203.0.113.8 -all"}
		dns.txt["mail._domainkey."+name] = dns.txt["mail._domainkey.example.test"]
		dns.mx[name] = dns.mx["example.test"]
	}
	licensed, active := 5, 2
	state.Access.Licensed, state.Access.Activated = &licensed, &active
	d := New(Dependencies{DNS: dns, Network: &fakeNetwork{}})
	s := summarize(t, NotSure, d, state)

	if s.Verdict != "unclear" || len(s.Problems) != 0 || len(s.More) != 0 {
		t.Fatalf("verdict %q problems %v more %v", s.Verdict, problemKeys(s.Problems), problemKeys(s.More))
	}
	dmarc := otherByKey(s, "dmarc_missing")
	if len(dmarc) != 1 || !reflect.DeepEqual(dmarc[0].Targets, domains) {
		t.Fatalf("one DMARC line for every domain: %+v", dmarc)
	}
	notChecked := otherByKey(s, "not_checked")
	if len(notChecked) != 1 || !reflect.DeepEqual(notChecked[0].Targets, []string{"access", "autoblock", "certificate", "client", "inbound", "license"}) {
		t.Fatalf("one not-checked line naming the areas: %+v", notChecked)
	}
	for _, o := range s.Others {
		if strings.HasPrefix(o.Key, "path") || o.Key == "mtasts" || o.Key == "tlsrpt" {
			t.Fatalf("hidden line shown: %+v", o)
		}
	}
	// Each line once; at most one per check and kind.
	seen := map[string]bool{}
	for _, o := range s.Others {
		id := o.Key + "|" + o.Check
		if seen[id] {
			t.Fatalf("duplicate line %s", id)
		}
		seen[id] = true
	}
	if len(s.Others) > 8 {
		t.Fatalf("too many lines: %+v", s.Others)
	}
	// MailPlus Server, relay and network ran and found nothing.
	ok := []string{}
	for _, o := range otherByKey(s, "ok") {
		ok = append(ok, o.Check)
	}
	if !reflect.DeepEqual(ok, []string{"mailplus", "relay", "network"}) {
		t.Fatalf("ok lines %v", ok)
	}
}

func TestSummaryHealthyRunIsClear(t *testing.T) {
	d := New(Dependencies{DNS: goodDNS(), Network: &fakeNetwork{}})
	plan, _ := PlanFor(CannotSend)
	// Transport and access have no observation in a healthy fixture either:
	// leave them out to test the clear verdict on what was observed.
	checks := []CheckID{MailPlus, Relay, Network, DomainDNS}
	fs, err := d.Evaluate(context.Background(), core.Env{Now: func() time.Time { return testNow }}, healthy(), nil, checks...)
	if err != nil {
		t.Fatal(err)
	}
	s := Summarize(checks, Rank(plan.Symptom, fs))
	if s.Verdict != "clear" || len(s.Problems) != 0 || len(s.Others) != 4 {
		t.Fatalf("%+v", s)
	}
	for _, o := range s.Others {
		if o.Key != "ok" {
			t.Fatalf("%+v", o)
		}
	}
}

// A queue reason and the relay hop's failure category are one cause: one card.
func TestSummaryMergesTheSameCauseFromSeveralPaths(t *testing.T) {
	state := State{Installed: ptr(true), Running: ptr(true), SMTPEnabled: ptr(true),
		Queue:     QueueState{Total: ptr(2), Reasons: []DeferredReason{DeferredAuth}},
		Relay:     RelayState{Enabled: ptr(false)},
		Transport: TransportState{Send: PathProvider, RelayFailure: DeferredAuth}}
	d := New(Dependencies{})
	plan, _ := PlanFor(CannotSend)
	fs, err := d.Evaluate(context.Background(), core.Env{Now: func() time.Time { return testNow }}, state, nil, Transport, MailPlus)
	if err != nil {
		t.Fatal(err)
	}
	s := Summarize(plan.Checks[:2], Rank(CannotSend, fs))
	if !reflect.DeepEqual(problemKeys(s.Problems), []string{"deliver_auth"}) {
		t.Fatalf("problems %v", problemKeys(s.Problems))
	}
	p := s.Problems[0]
	if len(p.Findings) != 2 || p.Action != "mailplus" || p.Intent != "" {
		t.Fatalf("merged problem %+v", p)
	}
	// The provider's relay is kept: MailPlus Server, never the setup wizard.
	if q := otherByKey(s, "queue"); len(q) != 1 || q[0].Count != 2 {
		t.Fatalf("queue line %+v", q)
	}
}

// Per-domain findings of one kind group into one card that lists the domains.
func TestSummaryGroupsPerDomainFindings(t *testing.T) {
	dns := goodDNS()
	state := healthy()
	state.Domains = nil
	for _, name := range []string{"b.example.test", "a.example.test", "c.example.test"} {
		state.Domains = append(state.Domains, MailDomain{Name: name, Selectors: []string{"s1", "s2"}})
		dns.txt[name] = []string{"v=spf1 ip4:203.0.113.8 -all"}
		dns.txt["_dmarc."+name] = []string{"v=DMARC1; p=bogus"} // invalid policy: a problem
		dns.mx[name] = dns.mx["example.test"]
	}
	d := New(Dependencies{DNS: dns, Network: &fakeNetwork{}})
	s := summarize(t, BounceOrSpam, d, state)
	var dmarc, dkim *Problem
	for i := range append(s.Problems, s.More...) {
		p := &append(s.Problems, s.More...)[i]
		switch p.Key {
		case "dmarc":
			dmarc = p
		case "dkim":
			dkim = p
		}
	}
	all := []string{"a.example.test", "b.example.test", "c.example.test"}
	if dmarc == nil || !reflect.DeepEqual(dmarc.Targets, all) || len(dmarc.Findings) != 3 || len(dmarc.Details) != 3 {
		t.Fatalf("one DMARC card for three domains: %+v", dmarc)
	}
	// Two missing selectors per domain: one card, each domain once.
	if dkim == nil || !reflect.DeepEqual(dkim.Targets, all) || len(dkim.Findings) != 6 {
		t.Fatalf("one DKIM card: %+v", dkim)
	}
	if dmarc.Action != "setup" || dmarc.Intent != "send" {
		t.Fatalf("DMARC action %+v", dmarc)
	}
	keys := map[string]bool{}
	for _, p := range append(s.Problems, s.More...) {
		if keys[p.Key] {
			t.Fatalf("duplicate card %s", p.Key)
		}
		keys[p.Key] = true
	}
}

func finding2(check CheckID, cause string, severity core.Severity) core.Finding {
	return finding(check, cause, "", severity, "send", nil)
}

// Critical first, then the symptom's ranking; at most three, the rest in More.
func TestSummaryOrdersAndCapsAtThree(t *testing.T) {
	ranked := []core.Finding{
		finding2(MailPlus, "deferred_dns", core.SeverityWarning),
		finding2(MailPlus, "deferred_tls", core.SeverityWarning),
		finding2(MailPlus, "queue_stale", core.SeverityWarning),
		finding2(Relay, "relay_stale", core.SeverityWarning), // same card as queue_stale
		finding2(Network, "ptr", core.SeverityWarning),
		finding2(Relay, "relay_stopped", core.SeverityCritical),
		finding2(MailPlus, "queue", core.SeverityInfo),
	}
	s := Summarize([]CheckID{MailPlus, Relay, Network}, ranked)
	if got := problemKeys(s.Problems); !reflect.DeepEqual(got, []string{"relay_stopped", "deliver_dns", "deliver_tls"}) {
		t.Fatalf("problems %v", got)
	}
	if got := problemKeys(s.More); !reflect.DeepEqual(got, []string{"queue_stuck", "ptr"}) {
		t.Fatalf("more %v", got)
	}
	if len(s.Problems) > MaxProblems || s.Verdict != "problems" {
		t.Fatalf("%+v", s)
	}
	for _, p := range append(s.Problems, s.More...) {
		if p.Key == "queue_stuck" && len(p.Findings) != 2 {
			t.Fatalf("queue and relay staleness merge: %+v", p)
		}
		if p.Key == "deliver_dns" && p.Action != "" {
			t.Fatalf("DNS has no button: %+v", p)
		}
	}
	// Checks with a problem are not "ok".
	if len(otherByKey(s, "ok")) != 0 {
		t.Fatalf("%+v", s.Others)
	}
}

func TestSummaryOfTheMailPlusPrecondition(t *testing.T) {
	f, stop := Precondition(State{Installed: ptr(false)}, nil)
	if !stop {
		t.Fatal("precondition")
	}
	s := PreconditionSummary(f)
	if s.Verdict != "problems" || len(s.Problems) != 1 || s.Problems[0].Key != "mailplus_missing" || s.Problems[0].Action != "packages" {
		t.Fatalf("%+v", s)
	}
	f, _ = Precondition(State{}, Unreadable{Cause: "dsm_105"})
	if s := PreconditionSummary(f); s.Verdict != "unreadable" || len(s.Problems) != 0 || len(s.Others) != 0 {
		t.Fatalf("%+v", s)
	}
}

// With the relay in use, this NAS's own address does not send the mail: its
// reverse DNS and port 25 are not shown at all.
func TestSummaryHidesDirectSendFactsWhenARelaySends(t *testing.T) {
	dns := goodDNS()
	dns.reverse["203.0.113.8"] = []string{"dynamic.isp.test."}
	state := healthy()
	state.Relay = RelayState{Enabled: ptr(true), Running: ptr(true)}
	d := New(Dependencies{DNS: dns, Network: &fakeNetwork{failPorts: true}})
	fs, err := d.Evaluate(context.Background(), core.Env{Now: func() time.Time { return testNow }}, state, nil, Network)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("fixture should produce findings")
	}
	s := Summarize([]CheckID{Network}, fs)
	if len(s.Problems) != 0 || len(otherByKey(s, "outbound")) != 0 {
		t.Fatalf("%+v", s)
	}
	// Without the relay the same facts are a problem and a note.
	state.Relay = RelayState{Enabled: ptr(false)}
	fs, _ = d.Evaluate(context.Background(), core.Env{Now: func() time.Time { return testNow }}, state, nil, Network)
	s = Summarize([]CheckID{Network}, fs)
	if !reflect.DeepEqual(problemKeys(s.Problems), []string{"ptr"}) || len(otherByKey(s, "outbound")) != 1 {
		t.Fatalf("%+v", s)
	}
}

// Details never carry a DSM code, and every key the page renders exists in
// all nine locales.
func TestSummaryCopyExists(t *testing.T) {
	texts := locales(t)
	for locale, m := range texts {
		for _, rule := range problemRules {
			for _, part := range []string{"title", "body", "action"} {
				if m[prefix+"problem."+rule.key+"."+part] == "" {
					t.Fatal(locale, "missing", prefix+"problem."+rule.key+"."+part)
				}
			}
		}
		for _, key := range []string{"ok", "not_checked", "queue", "dmarc_missing", "mx_missing", "dkim_none", "outbound"} {
			if m[prefix+"other."+key] == "" {
				t.Fatal(locale, "missing", prefix+"other."+key)
			}
		}
		for _, area := range notChecked {
			if m[prefix+"area."+area] == "" {
				t.Fatal(locale, "missing area", area)
			}
		}
		for _, id := range checkOrder {
			name := strings.TrimPrefix(string(id), prefix)
			if m[prefix+"check."+name] == "" || m[prefix+"area."+name] == "" {
				t.Fatal(locale, "missing check name", id)
			}
		}
	}
}

func TestSummaryDetailsHaveNoDSMCode(t *testing.T) {
	f := finding(Network, "ptr", "203.0.113.8", core.SeverityWarning, "send", map[string]string{"cause": "dsm_105"})
	s := Summarize(nil, []core.Finding{f})
	raw, _ := json.Marshal(s)
	if strings.Contains(string(raw), "dsm_105") {
		t.Fatal(string(raw))
	}
}

func locales(t *testing.T) map[string]map[string]string {
	t.Helper()
	out := map[string]map[string]string{}
	for _, locale := range []string{"en", "zh-TW", "zh-CN", "ja", "ko", "de", "fr", "es", "it"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "i18n", "messages", locale+".json"))
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]string{}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		out[locale] = m
	}
	return out
}

// a kept setup whose Cloudflare token was refused is one critical
// problem with the "enter a new token" action, naming its domain.
func TestRefusedTokenIsAnActionableProblem(t *testing.T) {
	s := healthy()
	s.TokenInvalid = []string{"example.test"}
	fs := checkRelay(s, testNow)
	sum := Summarize([]CheckID{Relay}, Rank(CannotSend, fs))
	if sum.Verdict != "problems" || len(sum.Problems) != 1 {
		t.Fatalf("summary: %+v", sum)
	}
	p := sum.Problems[0]
	if p.Key != "token_invalid" || p.Action != "token" || p.Severity != core.SeverityCritical || strings.Join(p.Targets, ",") != "example.test" {
		t.Fatalf("problem: %+v", p)
	}
	if fs := checkRelay(healthy(), testNow); len(fs) != 0 {
		t.Fatalf("a healthy relay: %v", fs)
	}
}
