package setup

import (
	"reflect"
	"testing"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

// MailPlus Server's own licence counts (License API v1, a test NAS fixture:
// limit 5, total 4) decide the setup only when they show a shortfall.
func TestLicenceShortfallStopsAtMailPlusServer(t *testing.T) {
	base := Decide(healthy(), Send, yes)
	if base.Blocked() || base.Send != DirectSend {
		t.Fatalf("healthy baseline: %+v", base)
	}
	for _, c := range []struct {
		name    string
		license detect.Observation[detect.License]
		short   bool
	}{
		{"licensed above active", detect.Fact(detect.License{Licensed: 5, Active: 4}), false},
		{"licensed equal to active", detect.Fact(detect.License{Licensed: 5, Active: 5}), false},
		{"licensed below active", detect.Fact(detect.License{Licensed: 5, Active: 6}), true},
		{"read failed", detect.Observation[detect.License]{Status: detect.Unknown, Detail: core.CauseUnavailable}, false},
		{"License API unsupported", detect.Observation[detect.License]{Status: detect.Unknown, Detail: detect.CauseUnsupported}, false},
		{"grant lacks the tuples", detect.Observation[detect.License]{Status: detect.Unknown, Detail: core.CauseAuthority}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := healthy()
			s.License = c.license
			d := Decide(s, Send, yes)
			if !c.short {
				// Enough or unknown licences change nothing in the decision.
				if !reflect.DeepEqual(d, base) {
					t.Fatalf("decision changed: %+v, want %+v", d, base)
				}
				return
			}
			if d.Gate != Stop || d.Reason != "licenseShort" || len(d.Needs) != 0 {
				t.Fatalf("shortfall decision %+v", d)
			}
			b := (&Wizard{}).decided(s, d)
			want := &BranchView{Kind: "configureMailPlus", Reason: "licenseShort", TitleKey: "mail.setup.licenseShort",
				BodyKey: "mail.setup.licenseShortBody", Params: map[string]string{"active": "6", "licensed": "5"}}
			if !reflect.DeepEqual(b, want) {
				t.Fatalf("branch %+v", b)
			}
		})
	}
}

// The shortfall comes before the other MailPlus prerequisites (adding members
// would only widen it) and before facts the decision would otherwise stop on.
func TestLicenceShortfallComesFirst(t *testing.T) {
	s := healthy()
	s.License = detect.Fact(detect.License{Licensed: 5, Active: 9})
	s.Domains = detect.Fact([]detect.Domain{})
	s.SMTP = detect.Unavailable[detect.SMTP]()
	for _, i := range []Intent{Send, Receive, Both} {
		if d := Decide(s, i, Answers{}); d.Reason != "licenseShort" {
			t.Fatalf("%s: %+v", i, d)
		}
	}
	// Diagnosis is never blocked by it.
	if d := Decide(s, Diagnose, Answers{}); d.Gate != Handoff {
		t.Fatalf("diagnose: %+v", d)
	}
}
