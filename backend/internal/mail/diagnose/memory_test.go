package diagnose

import (
	"context"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

type mutableRelayStatus struct{ running bool }

func (m *mutableRelayStatus) Status() core.ServiceStatus {
	return core.ServiceStatus{Running: m.running}
}

// H2 (disk-hibernation.md §1.3): mail.diag.relay judges a stopped relay from
// memory, with no snapshot (no DSM call), only after a full run saw MailPlus
// routed through the relay.
func TestRelayMemoryJudgement(t *testing.T) {
	status := &mutableRelayStatus{running: true}
	source := &fakeState{value: healthy()}
	source.value.Relay = RelayState{Enabled: ptr(true), Running: ptr(true)}
	d := New(Dependencies{State: source, DNS: goodDNS(), Network: &fakeNetwork{}, RelayStatus: status})
	var relay core.MemoryCheck
	for _, c := range d.Checks() {
		m, ok := c.(core.MemoryCheck)
		if !ok {
			t.Fatalf("%s lost the memory extension", c.ID())
		}
		if c.ID() == string(Relay) {
			relay = m
		} else if m.MemoryInterval() != 0 {
			t.Fatalf("%s must not be judged from memory", c.ID())
		}
	}
	if relay == nil || relay.MemoryInterval() <= 0 {
		t.Fatal("relay has no memory interval")
	}
	status.running = false
	if _, final := relay.Judge(testNow); final {
		t.Fatal("judged before any full run read the MailPlus route")
	}
	if _, err := d.Run(context.Background(), core.Env{Now: func() time.Time { return testNow }}, Relay); err != nil {
		t.Fatal(err)
	}
	calls := source.calls
	got, final := relay.Judge(testNow)
	if !final || len(got) != 1 || got[0].Params["cause"] != "relay_stopped" || got[0].Severity != core.SeverityCritical {
		t.Fatalf("stopped relay judged %v, %+v", final, got)
	}
	status.running = true
	if _, final := relay.Judge(testNow); final {
		t.Fatal("a running relay needs the queue, which only a full run reads")
	}
	if source.calls != calls {
		t.Fatal("a memory judgement took a DSM snapshot")
	}
	source.value.Relay = RelayState{Enabled: ptr(false)}
	if _, err := d.Run(context.Background(), core.Env{}, Relay); err != nil {
		t.Fatal(err)
	}
	status.running = false
	if _, final := relay.Judge(testNow); final {
		t.Fatal("judged a relay that MailPlus does not use")
	}
	if New(Dependencies{State: source}).Checks()[1].(core.MemoryCheck).MemoryInterval() != 0 {
		t.Fatal("no relay status source must mean no memory judgement")
	}
}
