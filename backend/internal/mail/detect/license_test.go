package detect

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

// Licence fixtures from the License API v1 replies read on a test NAS
// (MailPlus Server 4.1.1-31785): get_user_limit {"limit":5},
// get_active_user_num {"total":4}. Only those two counts decide; this
// assistant's own account list never stands in for either.
func TestLicenceCountsFromTheLicenseAPI(t *testing.T) {
	for _, c := range []struct {
		name    string
		license map[string]any
		errs    map[string]error
		known   bool
		want    License
		short   bool
		cause   string
		value   string
	}{
		{name: "licensed above active (a test NAS)", known: true, want: License{Licensed: 5, Active: 4}, value: "mail.setup.value.license"},
		{name: "licensed equal to active", license: map[string]any{"get_active_user_num": map[string]any{"total": 5}},
			known: true, want: License{Licensed: 5, Active: 5}, value: "mail.setup.value.license"},
		{name: "licensed below active", license: map[string]any{"get_active_user_num": map[string]any{"total": 7}},
			known: true, want: License{Licensed: 5, Active: 7}, short: true, value: "mail.setup.value.license.short"},
		{name: "limit field missing", license: map[string]any{"get_user_limit": map[string]any{"total": 5}},
			cause: core.CauseUnavailable, value: "mail.setup.cause.unavailable"},
		{name: "total field missing", license: map[string]any{"get_active_user_num": map[string]any{}},
			cause: core.CauseUnavailable, value: "mail.setup.cause.unavailable"},
		{name: "negative count", license: map[string]any{"get_user_limit": map[string]any{"limit": -1}},
			cause: core.CauseUnavailable, value: "mail.setup.cause.unavailable"},
		{name: "limit read refused by DSM", errs: map[string]error{"SYNO.MailPlusServer.License.get_user_limit": core.DSMError{Code: 117}},
			cause: "dsm_117", value: "mail.setup.cause.dsm"},
		{name: "active read failed", errs: map[string]error{"SYNO.MailPlusServer.License.get_active_user_num": errors.New("upstream text")},
			cause: core.CauseUnavailable, value: "mail.setup.cause.unavailable"},
		{name: "grant lacks the licence tuples", errs: map[string]error{"SYNO.MailPlusServer.License.get_user_limit": core.ErrAuthorityRequired},
			cause: core.CauseAuthority, value: "mail.setup.cause.authority"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dsm := &fakeDSM{license: c.license, errs: c.errs}
			s := (&Detector{Timeout: 20 * time.Millisecond}).Detect(context.Background(), core.Env{DSM: dsm}, Request{Domain: "example.test"})
			if s.License.IsKnown() != c.known || (c.known && s.License.Value != c.want) {
				t.Fatalf("licence %+v, want known=%v %+v", s.License, c.known, c.want)
			}
			if !c.known && s.License.Detail != c.cause {
				t.Fatalf("cause %q, want %q", s.License.Detail, c.cause)
			}
			if LicenseShort(s.License) != c.short {
				t.Fatalf("short = %v", !c.short)
			}
			// A licence problem never hides the other MailPlus facts.
			if !dsmFactsKnown(s) {
				t.Fatalf("licence read lost other facts: %+v", s)
			}
			for _, f := range Facts(s) {
				if f.LabelKey != "mail.setup.fact.license" {
					continue
				}
				if f.Value != c.value {
					t.Fatalf("fact %+v, want %s", f, c.value)
				}
				if (f.Status == core.SeverityWarning) != c.short {
					t.Fatalf("fact status %s", f.Status)
				}
				if c.known && (f.Params["licensed"] != strconv.Itoa(c.want.Licensed) || f.Params["active"] != strconv.Itoa(c.want.Active)) {
					t.Fatalf("params %v", f.Params)
				}
			}
		})
	}
}

// Older MailPlus Server without License v1 says unsupported, and the pass
// asks for no other version (v2/v3 of both methods answer 103).
func TestLicenceUnsupportedAndOnlyVersionOne(t *testing.T) {
	dsm := &fakeDSM{}
	s := (&Detector{Timeout: 20 * time.Millisecond}).ReadMailPlus(context.Background(), core.Env{DSM: dsm})
	if !s.License.IsKnown() || s.License.Value != (License{Licensed: 5, Active: 4}) {
		t.Fatalf("diagnosis snapshot did not read the licence: %+v", s.License)
	}
	n := 0
	for _, c := range dsm.called() {
		if c == "SYNO.MailPlusServer.License.get_user_limit" || c == "SYNO.MailPlusServer.License.get_active_user_num" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("%d licence reads, want 2: %v", n, dsm.called())
	}
	if !LicenseShort(Fact(License{Licensed: 0, Active: 1})) || LicenseShort(unknown[License](core.CauseUnavailable)) {
		t.Fatal("LicenseShort")
	}
	old := &fakeDSM{noLicenseAPI: true}
	s = (&Detector{Timeout: 20 * time.Millisecond}).ReadMailPlus(context.Background(), core.Env{DSM: old})
	if s.License.IsKnown() || s.License.Detail != CauseUnsupported || LicenseShort(s.License) {
		t.Fatalf("no License API: %+v", s.License)
	}
	for _, c := range old.called() {
		if c == "SYNO.MailPlusServer.License.get_user_limit" || c == "SYNO.MailPlusServer.License.get_active_user_num" {
			t.Fatalf("read an API DSM does not offer: %v", old.called())
		}
	}
}
