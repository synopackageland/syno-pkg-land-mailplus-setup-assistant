package detect

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

func catalog(t *testing.T, loc string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "i18n", "messages", loc+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

var placeholder = regexp.MustCompile(`\{(\w+)\}`)

// A test NAS showed raw Go values ("{true true false 4.1.1-31785}").
// Every fact is now a catalog key whose placeholders the params fill.
func TestFactsAreReadableInEveryLocale(t *testing.T) {
	dsm := &fakeDSM{}
	d := &Detector{Timeout: 20 * time.Millisecond, Resolver: fakeResolver{}, HTTP: fakeHTTP{}, Dial: fakeDial{}}
	s := d.Detect(context.Background(), core.Env{DSM: dsm}, Request{Domain: "example.test"})
	facts := Facts(s)
	if len(facts) < 20 {
		t.Fatalf("facts: %d", len(facts))
	}
	for _, loc := range []string{"en", "zh-TW", "zh-CN", "ja", "ko", "de", "fr", "es", "it"} {
		texts := catalog(t, loc)
		for _, f := range facts {
			if texts[f.LabelKey] == "" {
				t.Fatalf("%s: no label %s", loc, f.LabelKey)
			}
			text, ok := texts[f.Value]
			if !ok || !strings.HasPrefix(f.Value, "mail.setup.") {
				t.Fatalf("%s: %s shows %q, not a catalog key", loc, f.LabelKey, f.Value)
			}
			for _, m := range placeholder.FindAllStringSubmatch(text, -1) {
				if _, ok := f.Params[m[1]]; !ok {
					t.Fatalf("%s: %s = %s lacks {%s}", loc, f.LabelKey, f.Value, m[1])
				}
			}
		}
	}
	want := map[string]string{
		"mail.setup.fact.package": "mail.setup.value.package.running", "mail.setup.fact.smtp": "mail.setup.value.smtp.on",
		"mail.setup.fact.domains": "mail.setup.value.domains", "mail.setup.fact.delivery": "mail.setup.value.delivery.direct",
		"mail.setup.fact.license": "mail.setup.value.license", "mail.setup.fact.addressing": "mail.setup.cause.notChecked",
	}
	for _, f := range facts {
		if w, ok := want[f.LabelKey]; ok && f.Value != w {
			t.Errorf("%s = %s, want %s", f.LabelKey, f.Value, w)
		}
		if f.LabelKey == "mail.setup.fact.package" && f.Params["version"] != "4.1.1-31785" {
			t.Errorf("version lost: %v", f.Params)
		}
	}
}

func TestADomainDNSDoesNotKnowIsSaidSo(t *testing.T) {
	s := emptyState("sample-nas.test")
	s.DNS.Exists = Check{Status: "missing"}
	if DomainCause(s) != CauseNoDomain {
		t.Fatal(DomainCause(s))
	}
	for _, f := range Facts(s) {
		if f.LabelKey == "mail.setup.fact.domainDNS" && f.Value != "mail.setup.cause.noDomain" {
			t.Fatalf("domain DNS fact %+v", f)
		}
	}
}

func TestFactsAboutAnUnknownIPSayWhyTheyWereNotChecked(t *testing.T) {
	// No HTTP egress probe: the public IP stays unknown.
	s := (&Detector{Timeout: 20 * time.Millisecond, Resolver: fakeResolver{}}).Detect(context.Background(), core.Env{}, Request{Domain: "example.test"})
	if s.Network.EgressIPv4.IsKnown() {
		t.Fatal("ip known")
	}
	for _, f := range Facts(s) {
		switch f.LabelKey {
		case "mail.setup.fact.ptr", "mail.setup.fact.fcrdns", "mail.setup.fact.dnsbl":
			if f.Value != "mail.setup.cause.ipUnknown" {
				t.Errorf("%s = %s, want ipUnknown", f.LabelKey, f.Value)
			}
		}
	}
}

// a test NAS build 14: a name without an SPF record showed "set but invalid".
// No record is missing; only an existing record can fail.
func TestNoSPFRecordIsMissingNotInvalid(t *testing.T) {
	s := (&Detector{Timeout: 20 * time.Millisecond, Resolver: fakeResolver{}}).Detect(context.Background(), core.Env{}, Request{Domain: "example.test"})
	if s.DNS.SPF.Status != "missing" || fact(s, "spf") != "mail.setup.value.record.missing" {
		t.Fatalf("spf %+v fact %s", s.DNS.SPF, fact(s, "spf"))
	}
	two := fakeResolver{txt: map[string][]string{"example.test.": {"v=spf1 -all", "v=spf1 ~all"}}}
	s = (&Detector{Timeout: 20 * time.Millisecond, Resolver: two}).Detect(context.Background(), core.Env{}, Request{Domain: "example.test"})
	if s.DNS.SPF.Status != "fail" {
		t.Fatalf("two SPF records must fail: %+v", s.DNS.SPF)
	}
}

// sample-nas.test is not in DNS: its mail records say so, consistently with the
// domain fact, instead of record statuses.
func TestRecordsOfADomainDNSDoesNotKnowSaySo(t *testing.T) {
	s := detectDNS(t, zoneResolver{rcode: map[string][2]int{"sample-nas.test.": {3, 0}}}, "sample-nas.test")
	for _, label := range []string{"domainDNS", "dns", "mx", "spf", "dmarc"} {
		if got := fact(s, label); got != "mail.setup.cause.noDomain" {
			t.Errorf("%s = %s", label, got)
		}
	}
}

// a test NAS build 14: accounts and DKIM showed a bare "unknown" for a domain
// MailPlus Server does not have; they now name that cause.
func TestAccountsOfADomainNotInMailPlusSaySo(t *testing.T) {
	s := (&Detector{Timeout: 20 * time.Millisecond}).Detect(context.Background(), core.Env{DSM: &fakeDSM{}}, Request{Domain: "other.test"})
	if !s.Domains.IsKnown() {
		t.Fatal("domain list not read")
	}
	for _, label := range []string{"accounts", "dkim"} {
		if got := fact(s, label); got != "mail.setup.cause.notInMailPlus" {
			t.Errorf("%s = %s", label, got)
		}
	}
	// The domain list unread: its own cause, not "not in MailPlus".
	s = (&Detector{Timeout: 20 * time.Millisecond}).Detect(context.Background(), core.Env{DSM: &fakeDSM{errs: map[string]error{"SYNO.MailPlusServer.Domain.list": core.DSMError{Code: 117}}}}, Request{Domain: "other.test"})
	if got := fact(s, "accounts"); got != "mail.setup.cause.dsm" {
		t.Errorf("accounts = %s", got)
	}
}

// manyAccountsDSM reports more accounts than the detector reads.
type manyAccountsDSM struct{ fakeDSM }

func (f *manyAccountsDSM) Call(ctx context.Context, api, method string, version int, params map[string]any, out any) error {
	if api+"."+method != "SYNO.MailPlusServer.Domain.User.list" {
		return f.fakeDSM.Call(ctx, api, method, version, params, out)
	}
	users := []any{}
	for i := 0; i < 100; i++ {
		users = append(users, map[string]any{"id": i + 1, "name": "u", "is_activated": true})
	}
	b, _ := json.Marshal(map[string]any{"users": users, "total": 1001})
	return json.Unmarshal(b, out)
}

// More than 1000 accounts is its own cause, not "unavailable", and counts as
// unknown (the facts step asks for more evidence).
func TestMoreThan1000AccountsIsTooLarge(t *testing.T) {
	s := (&Detector{Timeout: 20 * time.Millisecond}).Detect(context.Background(), core.Env{DSM: &manyAccountsDSM{}}, Request{Domain: "example.test"})
	a := s.Accounts["example.test"]
	if a.IsKnown() || a.Detail != CauseTooManyAccounts {
		t.Fatalf("accounts = %+v", a)
	}
	if got := fact(s, "accounts"); got != "mail.setup.cause.accountsTooLarge" {
		t.Fatalf("accounts fact = %s", got)
	}
}

// txtFails fails the TXT lookup of one name (a DNS failure, not "not found").
type txtFails struct {
	fakeResolver
	name string
}

func (f txtFails) LookupTXT(ctx context.Context, n string) ([]string, error) {
	if n == f.name {
		return nil, &net.DNSError{Err: "server misbehaving", Name: n, IsTemporary: true}
	}
	return f.fakeResolver.LookupTXT(ctx, n)
}

// An SPF include whose lookup fails leaves the record's validity unknown,
// never "set"; a walk that succeeds keeps "set".
func TestSPFIncludeDNSFailureIsUnknown(t *testing.T) {
	txt := map[string][]string{
		"example.test.":       {"v=spf1 include:_spf.provider.test -all"},
		"_spf.provider.test.": {"v=spf1 ip4:192.0.2.0/24 -all"},
	}
	ok := fakeResolver{txt: txt}
	s := (&Detector{Timeout: 20 * time.Millisecond, Resolver: ok}).Detect(context.Background(), core.Env{}, Request{Domain: "example.test"})
	if s.DNS.SPF.Status != "present" || fact(s, "spf") != "mail.setup.value.record.present" {
		t.Fatalf("walk succeeded: spf %+v fact %s", s.DNS.SPF, fact(s, "spf"))
	}
	failing := txtFails{fakeResolver: ok, name: "_spf.provider.test."}
	s = (&Detector{Timeout: 20 * time.Millisecond, Resolver: failing}).Detect(context.Background(), core.Env{}, Request{Domain: "example.test"})
	if s.DNS.SPF.Status != "unknown" || fact(s, "spf") != "mail.setup.cause.dnsUnknown" {
		t.Fatalf("include DNS failed: spf %+v fact %s", s.DNS.SPF, fact(s, "spf"))
	}
}
