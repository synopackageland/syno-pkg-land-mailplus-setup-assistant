package setup

import (
	"context"
	"strings"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

// nsDirectory adds the zone's NS record names (ZoneDelegations).
type nsDirectory struct {
	*fakeDirectory
	ns    []string
	nsErr error
	reads int
}

func (d *nsDirectory) NSNames(_ context.Context, env core.Env, ref, zone string) ([]string, error) {
	d.seen(env, ref, "ns:"+zone)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reads++
	return append([]string{}, d.ns...), d.nsErr
}

// dnsTimedOut is healthy() with every DNS lookup of the zone unanswered (a
// cold resolver): "DNS hosted by Cloudflare" is unknown from DNS.
func dnsTimedOut(domains ...string) detect.State {
	st := healthy()
	unknown := detect.Check{Status: "unknown", Detail: "DNS gave no usable answer"}
	st.DNS.Cloudflare, st.DNS.Exists, st.DNS.NS, st.DNS.Zone = detect.Unavailable[bool](), unknown, unknown, ""
	ds := []detect.Domain{}
	for i, n := range domains {
		ds = append(ds, detect.Domain{ID: i + 1, Name: n})
	}
	st.Domains = detect.Fact(ds)
	return st
}

// zoneFactRun signs in on the Cloudflare source, chooses the example.test
// zone, lets change alter the directory (after the choice, which accepts only
// an active zone), and returns the stored detection for domain.
func zoneFactRun(t *testing.T, dir CloudDirectory, fake *fakeDirectory, st detect.State, domain string, change func()) (detect.State, DetectView) {
	t.Helper()
	ctx := context.Background()
	w, _ := cloudRouteWizard(fake)
	w.options.Directory, w.options.Detector = dir, source{state: st}
	env := fakeEnv()
	flow, _ := w.Start(ctx, env, owner)
	if _, err := w.Connect(ctx, env, owner, flow.ID, fixtureToken); err != nil {
		t.Fatal(err)
	}
	if v, err := w.Zones(ctx, env, owner, flow.ID, testAccount, testZone); err != nil || v.MailDomainsState != "read" {
		t.Fatalf("zone: %+v %v", v, err)
	}
	if change != nil {
		change()
	}
	v := detectDone(t, w, env, flow.ID, Send, domain, cloudYes)
	f, _ := w.load(ctx, env, owner, flow.ID)
	return *f.State, v
}

func factValue(v DetectView, label string) core.Fact {
	for _, f := range v.Facts {
		if f.LabelKey == "mail.setup.fact."+label {
			return f
		}
	}
	return core.Fact{}
}

func fullZone(fake *fakeDirectory, status string) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.zones[testAccount] = []CloudZone{{ID: testZone, Name: "example.test", Status: status, Type: "full"}}
}

func TestZoneFactActiveZoneIsKnownDespiteADNSTimeout(t *testing.T) {
	fake := newDirectory()
	fullZone(fake, "active")
	dir := &nsDirectory{fakeDirectory: fake}
	s, v := zoneFactRun(t, dir, fake, dnsTimedOut("example.test"), "example.test", nil)
	if !s.DNS.Cloudflare.IsKnown() || !s.DNS.Cloudflare.Value || s.DNS.CloudflareSource != detect.SourceZone || s.DNS.CloudflareZone != "example.test" {
		t.Fatalf("dns: %+v", s.DNS)
	}
	if f := factValue(v, "dns"); f.Value != "mail.setup.value.cloudflare.yesZone" || f.Params["zone"] != "example.test" {
		t.Fatalf("fact: %+v", f)
	}
	if v.Branch.Kind != "configure" {
		t.Fatalf("branch: %+v", v.Branch)
	}
	if dir.reads != 1 {
		t.Fatalf("the apex's NS records are read too: %d", dir.reads)
	}
	for _, tok := range fake.tokens {
		if tok != fixtureToken {
			t.Fatalf("unexpected token value %q", tok)
		}
	}
}

func TestZoneFactFallsBackToDNS(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func(*fakeDirectory)
	}{
		{"pending", func(f *fakeDirectory) { fullZone(f, "pending") }},
		{"moved", func(f *fakeDirectory) { fullZone(f, "moved") }},
		{"deactivated", func(f *fakeDirectory) { fullZone(f, "deactivated") }},
		{"partial setup", func(f *fakeDirectory) {
			f.zones[testAccount] = []CloudZone{{ID: testZone, Name: "example.test", Status: "active", Type: "partial"}}
		}},
		{"no type", func(f *fakeDirectory) {
			f.zones[testAccount] = []CloudZone{{ID: testZone, Name: "example.test", Status: "active"}}
		}},
		{"read error", func(f *fakeDirectory) { fullZone(f, "active"); f.err = ErrCloudflareUnavailable }},
		{"zone read refused", func(f *fakeDirectory) { fullZone(f, "active"); f.zoneMiss = []string{PermZoneRead} }},
		{"zone gone", func(f *fakeDirectory) { f.zones[testAccount] = nil }},
	} {
		t.Run(c.name, func(t *testing.T) {
			fake := newDirectory()
			fullZone(fake, "active")
			dir := &nsDirectory{fakeDirectory: fake}
			s, v := zoneFactRun(t, dir, fake, dnsTimedOut("example.test"), "example.test", func() { c.change(fake) })
			if s.DNS.Cloudflare.IsKnown() || s.DNS.CloudflareSource != "" {
				t.Fatalf("taken from the zone: %+v", s.DNS)
			}
			if f := factValue(v, "dns"); f.Value != "mail.setup.cause.dnsUnknown" {
				t.Fatalf("fact: %+v", f)
			}
		})
	}
}

func TestZoneFactSubdomainDelegation(t *testing.T) {
	for _, c := range []struct {
		name   string
		domain string
		ns     []string
		nsErr  error
		known  bool
	}{
		{"no NS records", "mail.example.test", nil, nil, true},
		{"multi-provider DNS: an NS record at the apex", "mail.example.test", []string{"Example.TEST."}, nil, false},
		{"multi-provider DNS at the apex, mail name is the apex", "example.test", []string{"example.test"}, nil, false},
		{"NS read failed at the apex", "example.test", nil, ErrCloudflareUnavailable, false},
		{"delegated at the mail name", "mail.example.test", []string{"MAIL.example.test."}, nil, false},
		{"delegated between it and the apex", "a.b.example.test", []string{"b.example.test"}, nil, false},
		{"a sibling's delegation does not count", "mail.example.test", []string{"other.example.test", "xmail.example.test"}, nil, true},
		{"a delegation below the mail name does not count", "mail.example.test", []string{"deep.mail.example.test"}, nil, true},
		{"NS read failed", "mail.example.test", nil, ErrCloudflareUnavailable, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			fake := newDirectory()
			fullZone(fake, "active")
			dir := &nsDirectory{fakeDirectory: fake, ns: c.ns, nsErr: c.nsErr}
			s, _ := zoneFactRun(t, dir, fake, dnsTimedOut(c.domain), c.domain, nil)
			if got := s.DNS.Cloudflare.IsKnown() && s.DNS.CloudflareSource == detect.SourceZone; got != c.known {
				t.Fatalf("known %v, want %v: %+v", got, c.known, s.DNS)
			}
			if dir.reads != 1 {
				t.Fatalf("delegation reads: %d", dir.reads)
			}
		})
	}
	for _, domain := range []string{"mail.example.test", "example.test"} {
		t.Run("no NS reader: "+domain, func(t *testing.T) {
			fake := newDirectory()
			fullZone(fake, "active")
			s, _ := zoneFactRun(t, fake, fake, dnsTimedOut(domain), domain, nil)
			if s.DNS.Cloudflare.IsKnown() {
				t.Fatalf("taken without the NS records: %+v", s.DNS)
			}
		})
	}
}

// A definite DNS answer that differs stands; an agreeing one takes the zone
// as its source.
func TestApplyZoneFactKeepsADifferingDNSAnswer(t *testing.T) {
	present := func(ns ...string) detect.Check { return detect.Check{Status: "present", Values: ns} }
	for _, c := range []struct {
		name   string
		dns    detect.DNS
		source string
		value  bool
	}{
		{"NS elsewhere", detect.DNS{Cloudflare: detect.Fact(false), Zone: "example.test", NS: present("ns1.other.test")}, detect.SourceDNS, false},
		{"DNS sees a delegated child", detect.DNS{Cloudflare: detect.Fact(false), Zone: "mail.example.test", NS: present("ns1.other.test")}, detect.SourceDNS, false},
		{"child also on Cloudflare", detect.DNS{Cloudflare: detect.Fact(true), Zone: "mail.example.test", NS: present("a.ns.cloudflare.com")}, detect.SourceDNS, true},
		{"no zone in DNS at all", detect.DNS{Cloudflare: detect.Unavailable[bool](), NS: detect.Check{Status: "missing", Detail: detect.NoZoneFound}}, "", false},
		{"agrees", detect.DNS{Cloudflare: detect.Fact(true), Zone: "example.test", NS: present("a.ns.cloudflare.com")}, detect.SourceZone, true},
		{"the name is not in DNS yet", detect.DNS{Cloudflare: detect.Unavailable[bool](), NS: detect.Check{Status: "missing", Detail: "DNS name not found"}}, detect.SourceZone, true},
		{"timeout", detect.DNS{Cloudflare: detect.Unavailable[bool](), NS: detect.Check{Status: "unknown"}}, detect.SourceZone, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := detect.State{DNS: c.dns}
			if s.DNS.Cloudflare.IsKnown() {
				s.DNS.CloudflareSource = detect.SourceDNS
			}
			applyZoneFact(&s, "example.test")
			if s.DNS.CloudflareSource != c.source || s.DNS.Cloudflare.IsKnown() && s.DNS.Cloudflare.Value != c.value {
				t.Fatalf("got %+v", s.DNS)
			}
		})
	}
}

// The own-domain source reads no zone fact: DNS alone decides.
func TestZoneFactOnlyOnTheCloudflareSource(t *testing.T) {
	ctx := context.Background()
	fake := newDirectory()
	fullZone(fake, "active")
	dir := &nsDirectory{fakeDirectory: fake}
	w, _ := cloudRouteWizard(fake)
	w.options.Directory, w.options.Detector = dir, source{state: dnsTimedOut("example.test")}
	env := fakeEnv()
	flow, _ := w.Start(ctx, env, owner)
	if err := signIn(w, ctx, env, owner, flow.ID); err != nil {
		t.Fatal(err)
	}
	own := cloudYes
	own.Source = SourceOwn
	detectDone(t, w, env, flow.ID, Send, "example.test", own)
	f, _ := w.load(ctx, env, owner, flow.ID)
	if f.State.DNS.Cloudflare.IsKnown() {
		t.Fatalf("own source took the zone: %+v", f.State.DNS)
	}
}

// choosing only another account (no zoneId) cancels the old zone's
// MailPlus domain read the way a zone change does: its context ends at once
// (the executor slot it waits for or holds is given back), it is no longer
// the flow's read, and it never stores.
func TestAccountChangeCancelsTheStaleDomainRead(t *testing.T) {
	ctx := context.Background()
	dir := newDirectory()
	other := strings.Repeat("c", 32)
	dir.accounts = append(dir.accounts, CloudAccount{ID: other, Name: "Work"})
	dir.zones[other] = []CloudZone{{ID: strings.Repeat("d", 32), Name: "work.test", Status: "active"}}
	w, _ := cloudRouteWizard(dir)
	release := make(chan struct{})
	bg := &core.Background{}
	defer func() { close(release); bg.Wait() }()
	w.options.Detector, w.options.Background = blockingDomains{source: source{state: healthy()}, release: release}, bg
	w.domainWait = 20 * time.Millisecond
	env := fakeEnv()
	flow, _ := w.Start(ctx, env, owner)
	if _, err := w.Connect(ctx, env, owner, flow.ID, fixtureToken); err != nil {
		t.Fatal(err)
	}
	if v, err := w.Zones(ctx, env, owner, flow.ID, testAccount, testZone); err != nil || v.MailDomainsState != "reading" {
		t.Fatalf("zone: %+v %v", v, err)
	}
	w.mu.Lock()
	old := w.domainReads[flow.ID]
	w.mu.Unlock()
	for _, account := range []string{other, testAccount} {
		if v, err := w.Zones(ctx, env, owner, flow.ID, account, ""); err != nil || v.ZoneID != "" || v.MailDomainsState != "" {
			t.Fatalf("account %s: %+v %v", account, v, err)
		}
	}
	select {
	case <-old.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the stale read still runs (holds its slot)")
	}
	if !old.job.Interrupted() || old.job.Context().Err() == nil {
		t.Fatal("the stale read was not canceled")
	}
	w.mu.Lock()
	_, kept := w.domainReads[flow.ID]
	w.mu.Unlock()
	if kept {
		t.Fatal("the stale read is still the flow's read")
	}
	old.names, old.cause = []string{"example.test"}, ""
	if v, err := w.awaitDomainRead(ctx, env, owner, flow.ID, old); err != nil || v.MailDomainsState != "" || len(v.MailDomains) != 0 {
		t.Fatalf("the stale read stored: %+v %v", v, err)
	}
	if f, _ := w.load(ctx, env, owner, flow.ID); f.Cloud.ZoneID != "" || f.Cloud.MailDomainsReading || len(f.Cloud.MailDomains) != 0 || f.Cloud.MailDomainsCause != "" {
		t.Fatalf("flow: %+v", f.Cloud)
	}
	if v, err := w.PollZone(ctx, env, owner, flow.ID); err != nil || v.MailDomainsState != "" {
		t.Fatalf("poll: %+v %v", v, err)
	}
}
