package diagnose

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"SynoMailPlusSetupAssistant/internal/core"
)

func TestCSSAccountEvidence(t *testing.T) {
	for _, tt := range []struct {
		name   string
		state  AccessState
		causes []string
	}{
		{"unknown is not healthy", AccessState{}, []string{"access_unknown", "block_unknown", "license_unknown", "owner_unknown"}},
		{"group active still counts", AccessState{
			Accounts:      []AccountAccess{{Ref: 41, EffectiveActive: ptr(true), GroupControlled: ptr(true), HomeReadable: ptr(true)}},
			BlockedSource: ptr(false), Licensed: ptr(5), Activated: ptr(6), OwnerMatches: ptr(true),
		}, []string{"group_activation", "license_count"}},
		{"credentials do not establish access", AccessState{
			Accounts:      []AccountAccess{{Ref: 41, EffectiveActive: ptr(false), GroupControlled: ptr(true), HomeReadable: ptr(false)}},
			BlockedSource: ptr(true), Licensed: ptr(5), Activated: ptr(2), OwnerMatches: ptr(false),
		}, []string{"account_inactive", "group_activation", "home_access", "source_blocked", "license_owner"}},
		{"active but home unknown", AccessState{
			Accounts:      []AccountAccess{{Ref: 41, EffectiveActive: ptr(true)}},
			BlockedSource: ptr(false), Licensed: ptr(5), Activated: ptr(1), OwnerMatches: ptr(true),
		}, []string{"home_unknown"}},
		{"invalid counts remain unknown", AccessState{Licensed: ptr(-1), Activated: ptr(1)},
			[]string{"access_unknown", "block_unknown", "license_unknown", "owner_unknown"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fs := checkAccess(State{Access: tt.state})
			assertCauses(t, fs, tt.causes...)
			for _, f := range fs {
				if f.FixWizard != "" {
					t.Fatal("manual access or licence finding started setup", f)
				}
			}
		})
	}
}

func TestCSSSelectedHopAndProviderPreservation(t *testing.T) {
	for _, tt := range []struct {
		name  string
		state TransportState
		want  []string
	}{
		{"unknown", TransportState{}, []string{"path_unknown", "path_unknown", "path_unknown"}},
		{"existing provider with failed IMAP", TransportState{
			Send: PathProvider, Receive: PathForwarded, Client: PathIMAP,
			RelayFailure: DeferredAuth, WebReachable: ptr(true), ClientReachable: ptr(false),
		}, []string{"path_provider", "path_forwarded", "path_imap", "relay_failure", "protocol_split"}},
		{"web does not prove SMTP submission", TransportState{
			Send: PathHomeKeeper, Receive: PathDirect, Client: PathSubmission, WebReachable: ptr(true),
		}, []string{"path_homekeeper", "path_direct", "path_submission", "protocol_unknown"}},
		{"unknown enum never leaks", TransportState{Send: "password=SECRET", RelayFailure: "SECRET"},
			[]string{"path_unknown", "path_unknown", "path_unknown"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fs := checkTransport(State{Transport: tt.state})
			assertCauses(t, fs, tt.want...)
			b, _ := json.Marshal(fs)
			if strings.Contains(string(b), "SECRET") {
				t.Fatal("untrusted path leaked")
			}
		})
	}
	state := healthy()
	state.Transport.Send = PathProvider
	state.Queue = QueueState{Total: ptr(1), Oldest: ptr(testNow), Reasons: []DeferredReason{DeferredAuth}}
	fs := append(checkMailPlus(state, testNow), checkTransport(state)...)
	for _, f := range fs {
		if f.Params["cause"] == "deferred_auth" && (f.FixWizard != "" || f.FixKey != prefix+"provider_relay.fix") {
			t.Fatal("provider auth suggested replacing the relay", f)
		}
	}
	ranked := Rank(CannotSend, fs)
	if ranked[0].Check != string(Transport) {
		t.Fatal("mail path must precede recommendations")
	}
}

func TestCSSFindingKeysAndUnavailableSources(t *testing.T) {
	b, err := os.ReadFile("../../../../i18n/messages/en.json")
	if err != nil {
		t.Fatal(err)
	}
	var texts map[string]string
	if err := json.Unmarshal(b, &texts); err != nil {
		t.Fatal(err)
	}
	for _, s := range []State{{}, {
		Transport: TransportState{Send: PathProvider, Receive: PathForwarded, Client: PathIMAP, RelayFailure: DeferredAuth,
			WebReachable: ptr(true), ClientReachable: ptr(false)},
		Access: AccessState{Accounts: []AccountAccess{{Ref: 1, EffectiveActive: ptr(false), GroupControlled: ptr(true), HomeReadable: ptr(false)}},
			BlockedSource: ptr(true), Licensed: ptr(0), Activated: ptr(1), OwnerMatches: ptr(false)},
	}} {
		fs := append(checkTransport(s), checkAccess(s)...)
		for _, f := range fs {
			for _, k := range []string{f.TitleKey, f.WhyKey, f.FixKey} {
				if texts[k] == "" {
					t.Fatal("missing text", k)
				}
			}
		}
	}
	fs, err := New(Dependencies{}).Run(context.Background(), core.Env{}, Transport, Access)
	if err != nil || len(fs) != 2 {
		t.Fatal(fs, err)
	}
	for _, f := range fs {
		if texts[f.TitleKey] == "" {
			t.Fatal("missing unavailable title", f.TitleKey)
		}
	}
}
