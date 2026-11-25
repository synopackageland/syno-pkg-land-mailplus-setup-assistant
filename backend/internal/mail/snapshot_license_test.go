package mail

import (
	"context"
	"testing"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

// licenceReader is a MailPlus read pass with a fixed result.
type licenceReader struct{ state detect.State }

func (r licenceReader) Detect(context.Context, core.Env, detect.Request) detect.State { return r.state }
func (r licenceReader) ReadMailPlus(context.Context, core.Env) detect.State           { return r.state }

type nopDSM struct{}

func (nopDSM) Call(context.Context, string, string, int, map[string]any, any) error { return nil }

// The diagnosis snapshot carries MailPlus Server's own licence counts to the
// access check; an unread licence stays nil (unknown), even when the domain
// list is unknown and the rest of the snapshot is cut short.
func TestSnapshotCarriesLicenceCounts(t *testing.T) {
	running := detect.Fact(detect.Package{Installed: true, Running: true})
	for _, c := range []struct {
		name                string
		license             detect.Observation[detect.License]
		licensed, activated int
		known               bool
	}{
		{"licensed above active", detect.Fact(detect.License{Licensed: 5, Active: 4}), 5, 4, true},
		{"licensed below active", detect.Fact(detect.License{Licensed: 5, Active: 7}), 5, 7, true},
		{"read failed", detect.Observation[detect.License]{Status: detect.Unknown, Detail: core.CauseUnavailable}, 0, 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := detect.State{Package: running, Domains: detect.Unavailable[[]detect.Domain](), License: c.license}
			out, err := detectorState{detector: licenceReader{s}}.Snapshot(context.Background(), core.Env{DSM: nopDSM{}})
			if err != nil {
				t.Fatal(err)
			}
			a := out.Access
			if !c.known {
				if a.Licensed != nil || a.Activated != nil {
					t.Fatalf("unknown licence became counts: %+v", a)
				}
				return
			}
			if a.Licensed == nil || a.Activated == nil || *a.Licensed != c.licensed || *a.Activated != c.activated {
				t.Fatalf("counts %+v", a)
			}
		})
	}
}
