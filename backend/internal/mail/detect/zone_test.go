package detect

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

// zoneResolver answers per name and record type; a name absent from a map is
// a not-found answer (net.DNSError IsNotFound), as Go's resolver reports both
// NXDOMAIN and a name without that record type. fail makes every lookup of a
// name a resolver failure (SERVFAIL-like). cname makes a name an alias: like
// Go's resolver, every lookup follows it and returns the target's records
// without checking the owner name. rcode gives the reply code and answer
// count of the RCodeResolver probe (absent: the probe fails).
type zoneResolver struct {
	ns, txt, host, mx map[string][]string
	cname             map[string]string
	rcode             map[string][2]int
	fail              map[string]bool
	asked             map[string]bool
}

var errServFail = &net.DNSError{Err: "server misbehaving", Name: "x", IsTemporary: true}

func (z zoneResolver) answer(m map[string][]string, n string) ([]string, error) {
	if z.fail[n] {
		return nil, errServFail
	}
	if t, ok := z.cname[n]; ok {
		n = t
	}
	if v, ok := m[n]; ok {
		return v, nil
	}
	return nil, missing(n)
}
func (z zoneResolver) LookupTXT(_ context.Context, n string) ([]string, error) {
	return z.answer(z.txt, n)
}
func (z zoneResolver) LookupHost(_ context.Context, n string) ([]string, error) {
	return z.answer(z.host, n)
}
func (zoneResolver) LookupAddr(context.Context, string) ([]string, error) {
	return nil, errors.New("not used")
}
func (zoneResolver) LookupIP(_ context.Context, _, n string) ([]net.IP, error) {
	return nil, missing(n)
}
func (z zoneResolver) LookupMX(_ context.Context, n string) ([]*net.MX, error) {
	v, err := z.answer(z.mx, n)
	out := []*net.MX{}
	for _, h := range v {
		out = append(out, &net.MX{Host: h})
	}
	return out, err
}
func (z zoneResolver) LookupNS(_ context.Context, n string) ([]*net.NS, error) {
	if z.asked != nil {
		z.asked[n] = true
	}
	v, err := z.answer(z.ns, n)
	out := []*net.NS{}
	for _, h := range v {
		out = append(out, &net.NS{Host: h})
	}
	return out, err
}

// LookupCNAME as Go 1.26 answers it: the alias target (also when the target
// does not exist, from the CNAME query), the name itself when it has
// addresses, else not found.
func (z zoneResolver) LookupCNAME(_ context.Context, n string) (string, error) {
	if z.fail[n] || z.fail["cname:"+n] {
		return "", errServFail
	}
	if t, ok := z.cname[n]; ok {
		return t, nil
	}
	if _, ok := z.host[n]; ok {
		return n, nil
	}
	return "", missing(n)
}
func (z zoneResolver) LookupRCode(_ context.Context, n string) (int, int, error) {
	if v, ok := z.rcode[n]; ok {
		return v[0], v[1], nil
	}
	return 0, 0, errServFail
}

func detectDNS(t *testing.T, r Resolver, domain string) State {
	t.Helper()
	return (&Detector{Timeout: 50 * time.Millisecond, Resolver: r}).Detect(context.Background(), core.Env{}, Request{Domain: domain})
}

func fact(s State, label string) string {
	for _, f := range Facts(s) {
		if f.LabelKey == "mail.setup.fact."+label {
			return f.Value
		}
	}
	return ""
}

var cloudflareZone = []string{"ada.ns.cloudflare.com.", "bob.ns.cloudflare.com."}

// A subdomain can have records with no NS of its
// own, and was shown as "DNS does not know this domain".
func TestASubdomainWithRecordsButNoNSExists(t *testing.T) {
	asked := map[string]bool{}
	s := detectDNS(t, zoneResolver{
		ns:    map[string][]string{"example.org.": cloudflareZone},
		txt:   map[string][]string{"mail.example.org.": {"v=spf1 -all"}},
		asked: asked,
	}, "mail.example.org")
	if s.DNS.Exists.Status != "present" || DomainCause(s) != "" {
		t.Fatalf("subdomain with TXT must exist: %+v", s.DNS.Exists)
	}
	if s.DNS.Zone != "example.org" || s.DNS.NS.Status != "present" {
		t.Fatalf("zone must be found at the parent: %q %+v", s.DNS.Zone, s.DNS.NS)
	}
	if !s.DNS.Cloudflare.IsKnown() || !s.DNS.Cloudflare.Value || s.DNS.CloudflareSource != SourceDNS {
		t.Fatalf("parent NS on Cloudflare must make it Cloudflare-managed: %+v %q", s.DNS.Cloudflare, s.DNS.CloudflareSource)
	}
	if fact(s, "domainDNS") != "mail.setup.value.domainDNS.found" || fact(s, "dns") != "mail.setup.value.cloudflare.yes" {
		t.Fatalf("facts: domainDNS=%s dns=%s", fact(s, "domainDNS"), fact(s, "dns"))
	}
	if asked["me."] {
		t.Fatal("the zone walk asked the TLD for NS")
	}
}

func TestADeepSubdomainWalksToTheFirstZone(t *testing.T) {
	s := detectDNS(t, zoneResolver{
		ns:   map[string][]string{"example.test.": {"ns1.other-dns.test."}},
		host: map[string][]string{"a.b.example.test.": {"192.0.2.7"}},
	}, "a.b.example.test")
	if s.DNS.Exists.Status != "present" || s.DNS.Zone != "example.test" {
		t.Fatalf("exists %+v zone %q", s.DNS.Exists, s.DNS.Zone)
	}
	if !s.DNS.Cloudflare.IsKnown() || s.DNS.Cloudflare.Value {
		t.Fatalf("non-Cloudflare zone: %+v", s.DNS.Cloudflare)
	}
}

func TestADomainWithItsOwnNSIsItsOwnZone(t *testing.T) {
	s := detectDNS(t, zoneResolver{ns: map[string][]string{"example.test.": cloudflareZone}}, "example.test")
	if s.DNS.Exists.Status != "present" || s.DNS.Zone != "example.test" || !s.DNS.Cloudflare.IsKnown() || !s.DNS.Cloudflare.Value {
		t.Fatalf("%+v %q %+v", s.DNS.Exists, s.DNS.Zone, s.DNS.Cloudflare)
	}
}

// Every lookup not found: the name does not exist; nothing is guessed about
// a zone.
func TestATrueNXDOMAINIsMissing(t *testing.T) {
	s := detectDNS(t, zoneResolver{ns: map[string][]string{"example.org.": cloudflareZone}, rcode: map[string][2]int{"nothing.example.org.": {3, 0}}}, "nothing.example.org")
	if s.DNS.Exists.Status != "missing" || DomainCause(s) != CauseNoDomain {
		t.Fatalf("exists %+v cause %q", s.DNS.Exists, DomainCause(s))
	}
	if s.DNS.Cloudflare.IsKnown() || fact(s, "domainDNS") != "mail.setup.cause.noDomain" || fact(s, "dns") != "mail.setup.cause.noDomain" {
		t.Fatalf("cloudflare %+v domainDNS %s dns %s", s.DNS.Cloudflare, fact(s, "domainDNS"), fact(s, "dns"))
	}
}

// A resolver failure with no records anywhere is unknown, never missing.
func TestALookupErrorIsUnknown(t *testing.T) {
	s := detectDNS(t, zoneResolver{fail: map[string]bool{"mail.example.test.": true}}, "mail.example.test")
	if s.DNS.Exists.Status != "unknown" || DomainCause(s) != CauseDNSUnknown {
		t.Fatalf("exists %+v cause %q", s.DNS.Exists, DomainCause(s))
	}
	if s.DNS.Cloudflare.IsKnown() || fact(s, "dns") != "mail.setup.cause.dnsUnknown" {
		t.Fatalf("cloudflare %+v dns %s", s.DNS.Cloudflare, fact(s, "dns"))
	}
	// One failed type next to not-found answers is still unknown.
	z := zoneResolver{fail: map[string]bool{}}
	r := failingTXT{z}
	s = detectDNS(t, r, "mail.example.test")
	if s.DNS.Exists.Status != "unknown" {
		t.Fatalf("one failed lookup must leave existence unknown: %+v", s.DNS.Exists)
	}
}

// failingTXT fails only the TXT lookup; everything else is not found.
type failingTXT struct{ zoneResolver }

func (failingTXT) LookupTXT(context.Context, string) ([]string, error) { return nil, errServFail }

// The name exists, but the zone walk meets a failed NS lookup: the zone and
// Cloudflare stay unknown, never taken from a guess.
func TestAFailedNSLookupOnTheWayLeavesTheZoneUnknown(t *testing.T) {
	s := detectDNS(t, zoneResolver{
		txt:  map[string][]string{"mail.example.test.": {"v=spf1 -all"}},
		fail: map[string]bool{"example.test.": true},
	}, "mail.example.test")
	if s.DNS.Exists.Status != "present" || s.DNS.Zone != "" || s.DNS.NS.Status != "unknown" || s.DNS.Cloudflare.IsKnown() {
		t.Fatalf("exists %+v zone %q ns %+v cf %+v", s.DNS.Exists, s.DNS.Zone, s.DNS.NS, s.DNS.Cloudflare)
	}
}

// No public-suffix list: the walk never goes below two labels.
func TestTheZoneWalkStopsAtTwoLabels(t *testing.T) {
	asked := map[string]bool{}
	s := detectDNS(t, zoneResolver{
		ns:    map[string][]string{"test.": {"a.root-servers.test."}},
		txt:   map[string][]string{"a.b.test.": {"x"}},
		asked: asked,
	}, "a.b.test")
	if asked["test."] || s.DNS.Zone != "" || s.DNS.Cloudflare.IsKnown() {
		t.Fatalf("asked %v zone %q cf %+v", asked, s.DNS.Zone, s.DNS.Cloudflare)
	}
	if s.DNS.Exists.Status != "present" {
		t.Fatalf("exists %+v", s.DNS.Exists)
	}
}

// Go's LookupNS does not check the owner name. mail.example.test is a
// CNAME to the apex of a Cloudflare zone; LookupNS returns that apex's NS.
// The zone is the parent, which is not on Cloudflare.
func TestACNAMEToAZoneApexIsNotItsOwnZone(t *testing.T) {
	s := detectDNS(t, zoneResolver{
		cname: map[string]string{"mail.example.test.": "cfzone.test."},
		ns:    map[string][]string{"cfzone.test.": cloudflareZone, "example.test.": {"ns1.other-dns.test."}},
		host:  map[string][]string{"cfzone.test.": {"192.0.2.9"}},
	}, "mail.example.test")
	if s.DNS.Exists.Status != "present" || s.DNS.Zone != "example.test" {
		t.Fatalf("exists %+v zone %q", s.DNS.Exists, s.DNS.Zone)
	}
	if !s.DNS.Cloudflare.IsKnown() || s.DNS.Cloudflare.Value {
		t.Fatalf("the alias target's NS decided Cloudflare: %+v", s.DNS.Cloudflare)
	}
}

// A level of the walk that is an alias is skipped the same way.
func TestAnAliasOnTheWayIsNotAZone(t *testing.T) {
	s := detectDNS(t, zoneResolver{
		cname: map[string]string{"www.example.test.": "cfzone.test."},
		ns:    map[string][]string{"cfzone.test.": cloudflareZone, "example.test.": {"ns1.other-dns.test."}},
		txt:   map[string][]string{"a.www.example.test.": {"x"}},
	}, "a.www.example.test")
	if s.DNS.Zone != "example.test" || !s.DNS.Cloudflare.IsKnown() || s.DNS.Cloudflare.Value {
		t.Fatalf("zone %q cf %+v", s.DNS.Zone, s.DNS.Cloudflare)
	}
}

// NS answered but the alias check failed: whose NS it is stays unknown.
func TestNSWithAnUnknownAliasCheckLeavesTheZoneUnknown(t *testing.T) {
	s := detectDNS(t, zoneResolver{
		ns:   map[string][]string{"mail.example.test.": cloudflareZone},
		fail: map[string]bool{"cname:mail.example.test.": true},
	}, "mail.example.test")
	if s.DNS.Exists.Status != "present" || s.DNS.Zone != "" || s.DNS.Cloudflare.IsKnown() {
		t.Fatalf("exists %+v zone %q cf %+v", s.DNS.Exists, s.DNS.Zone, s.DNS.Cloudflare)
	}
}

// A dangling CNAME (its target does not exist; the reply is NXDOMAIN with the
// CNAME in the answer) exists: the alias is there.
func TestADanglingCNAMEExists(t *testing.T) {
	s := detectDNS(t, zoneResolver{
		cname: map[string]string{"alias.example.test.": "gone.example.test."},
		ns:    map[string][]string{"example.test.": {"ns1.other-dns.test."}},
		rcode: map[string][2]int{"alias.example.test.": {3, 1}},
	}, "alias.example.test")
	if s.DNS.Exists.Status != "present" || DomainCause(s) != "" {
		t.Fatalf("dangling alias: %+v", s.DNS.Exists)
	}
	if s.DNS.Zone != "example.test" {
		t.Fatalf("zone %q", s.DNS.Zone)
	}
	// Even if LookupCNAME misses it, NXDOMAIN with an answer is not missing.
	s = detectDNS(t, zoneResolver{rcode: map[string][2]int{"alias.example.test.": {3, 1}}}, "alias.example.test")
	if s.DNS.Exists.Status != "present" {
		t.Fatalf("NXDOMAIN with an answer: %+v", s.DNS.Exists)
	}
}

// An empty non-terminal: every lookup not found (Go cannot tell NODATA from
// NXDOMAIN). NOERROR without answers is unknown, not present: Cloudflare
// (RFC 9824 compact denial), NS1 and Route 53 answer a name that does not
// exist that way (nxdomain-t0089-zz9.example.com). Without the
// probe it is unknown too; never missing.
func TestAnEmptyNonTerminalIsNeverMissing(t *testing.T) {
	s := detectDNS(t, zoneResolver{rcode: map[string][2]int{"ent.example.test.": {0, 0}}}, "ent.example.test")
	if s.DNS.Exists.Status != "unknown" || DomainCause(s) != CauseDNSUnknown {
		t.Fatalf("NOERROR: %+v", s.DNS.Exists)
	}
	s = detectDNS(t, zoneResolver{}, "ent.example.test")
	if s.DNS.Exists.Status != "unknown" || DomainCause(s) != CauseDNSUnknown {
		t.Fatalf("no rcode proof: %+v", s.DNS.Exists)
	}
}

// x.co.uk has records but no NS: walking up reaches co.uk, which may be a
// public suffix; its NS say nothing about who hosts the domain.
func TestAZoneAtAPossiblePublicSuffixIsUnknown(t *testing.T) {
	s := detectDNS(t, zoneResolver{
		ns:  map[string][]string{"co.uk.": {"dns1.nic.uk."}},
		txt: map[string][]string{"x.co.uk.": {"x"}},
	}, "x.co.uk")
	if s.DNS.Exists.Status != "present" || s.DNS.Zone != "" || s.DNS.Cloudflare.IsKnown() {
		t.Fatalf("exists %+v zone %q cf %+v", s.DNS.Exists, s.DNS.Zone, s.DNS.Cloudflare)
	}
	// example.org is not such a name (see TestASubdomainWithRecordsButNoNSExists).
	if possiblePublicSuffix("example.org") || !possiblePublicSuffix("com.tw") {
		t.Fatal("possiblePublicSuffix")
	}
}

// The zone fact's evidence is named in the fact value; an unknown has no
// source.
func TestCloudflareFactNamesItsSource(t *testing.T) {
	s := emptyState("mail.example.test")
	if s.DNS.CloudflareSource != "" {
		t.Fatalf("unknown has a source: %q", s.DNS.CloudflareSource)
	}
	s.DNS.Exists = Check{Status: "present"}
	s.DNS.Cloudflare, s.DNS.CloudflareSource, s.DNS.CloudflareZone = Fact(true), SourceZone, "example.test"
	for _, f := range Facts(s) {
		if f.LabelKey == "mail.setup.fact.dns" {
			if f.Value != "mail.setup.value.cloudflare.yesZone" || f.Params["zone"] != "example.test" {
				t.Fatalf("fact: %+v", f)
			}
			return
		}
	}
	t.Fatal("no dns fact")
}
