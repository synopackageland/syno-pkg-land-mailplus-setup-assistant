package diagnose

import (
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

// MailPlus Server not installed or not running is the first and only cause of
// every symptom: the run completes at once with that finding, runs no DNS or
// network probe, and offers no setup Fix (the fix is in Package Center).
func TestMailPlusPreconditionIsTheOnlyCause(t *testing.T) {
	no, yes := false, true
	for name, tc := range map[string]struct {
		state State
		cause string
	}{
		"not installed": {State{Installed: &no, Domains: []MailDomain{{Name: "example.test"}}}, "missing"},
		"stopped":       {State{Installed: &yes, Running: &no, Domains: []MailDomain{{Name: "example.test"}}}, "stopped"},
	} {
		for _, plan := range Plans() {
			dns, network := goodDNS(), &fakeNetwork{}
			r := &Runner{D: New(Dependencies{State: &fakeState{value: tc.state}, DNS: dns, Network: network})}
			run, err := r.Start("admin", plan.Symptom)
			if err != nil {
				t.Fatal(err)
			}
			done, _ := poll(t, r, core.Env{Now: func() time.Time { return testNow }}, run.ID, time.Second)
			if !done.Complete || done.Done != done.Total || len(done.Findings) != 1 {
				t.Fatalf("%s/%s: want one finding: %+v", name, plan.Symptom, done)
			}
			f := done.Findings[0]
			if f.ID != string(MailPlus)+"."+tc.cause || f.Severity != core.SeverityCritical || f.FixWizard != "" {
				t.Fatalf("%s/%s: %+v", name, plan.Symptom, f)
			}
			if len(dns.calls) != 0 || len(network.calls) != 0 {
				t.Fatalf("%s/%s: checks ran: dns=%v network=%v", name, plan.Symptom, dns.calls, network.calls)
			}
		}
	}
}

// Running: the precondition passes and the checks run as before.
func TestMailPlusPreconditionPassesWhenRunning(t *testing.T) {
	yes := true
	if _, stop := Precondition(State{Installed: &yes, Running: &yes}, nil); stop {
		t.Fatal("running MailPlus Server stopped the run")
	}
	if _, stop := Precondition(State{}, nil); stop {
		t.Fatal("an unread package (no snapshot error) is judged by the checks")
	}
	if f, stop := Precondition(State{}, Unreadable{Cause: "mailplus_api_missing"}); !stop || f.WhyKey != "mail.setup.unreadable.mailplusApiMissing" {
		t.Fatalf("unreadable: %+v", f)
	}
}
