package diagnose

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

type fakeRelayStatus struct{ value core.ServiceStatus }

func (f fakeRelayStatus) Status() core.ServiceStatus { return f.value }

type readOnlyKV struct {
	at    time.Time
	found bool
	err   error
	reads int
}

func (f *readOnlyKV) Get(_ context.Context, module, key string, out any) (bool, error) {
	if module != "mail.relay" || key != "lastSuccess" {
		panic("unexpected KV read")
	}
	f.reads++
	*out.(*time.Time) = f.at
	return f.found, f.err
}
func (*readOnlyKV) Put(context.Context, string, string, any) error {
	panic("diagnostic KV write")
}

func TestRelayStateSource(t *testing.T) {
	for _, tt := range []struct {
		name    string
		memory  string
		found   bool
		kvError bool
		want    time.Time
		reads   int
	}{
		{"memory wins", testNow.Format(time.RFC3339Nano), true, false, testNow, 0},
		{"memory corrupt is unknown", "invalid", true, false, time.Time{}, 0},
		{"persisted fallback", "", true, false, testNow.Add(-time.Hour), 1},
		{"absent", "", false, false, time.Time{}, 1},
		{"read error", "", true, true, time.Time{}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			base := &fakeState{value: healthy()}
			base.value.Relay.Enabled = ptr(true)
			kv := &readOnlyKV{at: testNow.Add(-time.Hour), found: tt.found}
			if tt.kvError {
				kv.err = errors.New("fixture error")
			}
			source := WithRelay(base, fakeRelayStatus{core.ServiceStatus{
				Running: true, Info: map[string]string{"lastSuccess": tt.memory},
				LastErr: "UNRELATED_UNTRUSTED_TEXT",
			}})
			got, err := source.Snapshot(context.Background(), core.Env{KV: kv})
			if err != nil || !isTrue(got.Relay.Enabled) || !isTrue(got.Relay.Running) ||
				!got.Relay.LastSuccess.Equal(tt.want) || kv.reads != tt.reads {
				t.Fatal(got.Relay, err, kv.reads)
			}
			b, _ := json.Marshal(got)
			if strings.Contains(string(b), "UNRELATED_UNTRUSTED_TEXT") {
				t.Fatal("raw relay error leaked into state")
			}
		})
	}
	if _, err := WithRelay(nil, nil).Snapshot(context.Background(), core.Env{}); err == nil {
		t.Fatal("missing detector accepted")
	}
	base := &fakeState{err: errors.New("fixture error")}
	if _, err := WithRelay(base, nil).Snapshot(context.Background(), core.Env{}); err == nil {
		t.Fatal("detector error discarded")
	}
}

// The relay's in-memory time of the last Workers Free recipient refusal is
// passed on; a missing or corrupt value is none.
func TestRelayStatePlanRefusal(t *testing.T) {
	for _, tt := range []struct {
		name, value string
		want        time.Time
	}{
		{"recorded", testNow.Format(time.RFC3339Nano), testNow},
		{"absent", "", time.Time{}},
		{"corrupt", "invalid", time.Time{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			base := &fakeState{value: healthy()}
			base.value.Relay.Enabled = ptr(true)
			source := WithRelay(base, fakeRelayStatus{core.ServiceStatus{Running: true,
				Info: map[string]string{"lastSuccess": testNow.Format(time.RFC3339Nano), "lastPlanRefusal": tt.value}}})
			state, err := source.Snapshot(context.Background(), core.Env{})
			if err != nil || !state.Relay.PlanRefusal.Equal(tt.want) {
				t.Fatalf("%v %v", state.Relay.PlanRefusal, err)
			}
		})
	}
}
