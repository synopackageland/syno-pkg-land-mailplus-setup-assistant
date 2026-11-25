package diagnose

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

var testNow = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

func ptr[T any](v T) *T { return &v }

func healthy() State {
	return State{Installed: ptr(true), Running: ptr(true), SMTPEnabled: ptr(true),
		Domains: []MailDomain{{Name: "example.test", Selectors: []string{"mail"}}},
		Queue:   QueueState{Total: ptr(0)}, Relay: RelayState{Enabled: ptr(false)},
		CertificatesVisible: true, Certificates: []MailCertificate{{Host: "mail.example.test", Service: "postfix", NotAfter: testNow.Add(90 * 24 * time.Hour)}},
		Inbound25: ptr(true), IMAPEnabled: ptr(true), ClientReachable: ptr(true)}
}

type fakeState struct {
	value State
	err   error
	calls int
}

func (f *fakeState) Snapshot(ctx context.Context, _ core.Env) (State, error) {
	f.calls++
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	return f.value, f.err
}

type fakeDNS struct {
	txt     map[string][]string
	hosts   map[string][]string
	reverse map[string][]string
	mx      map[string][]*net.MX
	err     map[string]error
	calls   []string
}

func dnsName(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }
func (f *fakeDNS) failure(ctx context.Context, name string) error {
	f.calls = append(f.calls, name)
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.err[dnsName(name)]
}
func (f *fakeDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	err := f.failure(ctx, name)
	return append([]string(nil), f.txt[dnsName(name)]...), err
}
func (f *fakeDNS) LookupHost(ctx context.Context, name string) ([]string, error) {
	err := f.failure(ctx, name)
	return append([]string(nil), f.hosts[dnsName(name)]...), err
}
func (f *fakeDNS) LookupIP(ctx context.Context, _ string, name string) ([]net.IP, error) {
	err := f.failure(ctx, name)
	out := []net.IP{}
	for _, ip := range f.hosts[dnsName(name)] {
		out = append(out, net.ParseIP(ip))
	}
	return out, err
}
func (f *fakeDNS) LookupAddr(ctx context.Context, ip string) ([]string, error) {
	err := f.failure(ctx, ip)
	return append([]string(nil), f.reverse[ip]...), err
}
func (f *fakeDNS) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	err := f.failure(ctx, name)
	return append([]*net.MX(nil), f.mx[dnsName(name)]...), err
}
func goodDNS() *fakeDNS {
	return &fakeDNS{
		txt: map[string][]string{
			"example.test":                 {"v=spf1 ip4:203.0.113.8 -all"},
			"mail._domainkey.example.test": {"v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(make([]byte, 32))},
			"_dmarc.example.test":          {"v=DMARC1; p=reject"},
			"_mta-sts.example.test":        {"v=STSv1; id=123"},
			"_smtp._tls.example.test":      {"v=TLSRPTv1; rua=mailto:reports@example.test"},
		},
		hosts:   map[string][]string{"mail.example.test": {"203.0.113.8", "2001:db8::8"}},
		reverse: map[string][]string{"203.0.113.8": {"mail.example.test."}, "2001:db8::8": {"mail.example.test."}},
		mx:      map[string][]*net.MX{"example.test": {{Host: "mail.example.test.", Pref: 10}}},
		err:     map[string]error{},
	}
}
func checkerFor(f *fakeDNS) *checker {
	return &checker{ctx: context.Background(), r: f, timeout: time.Second, txtCache: map[string]ProbeResult{}, controls: map[string]ProbeResult{}}
}

type fakeNetwork struct {
	failEgress, failPorts bool
	calls                 []string
}

func (f *fakeNetwork) Egress(_ context.Context, family string) Egress {
	f.calls = append(f.calls, "egress:"+family)
	status, ips := "pass", []string{"203.0.113.8"}
	if family == "tcp6" {
		ips = []string{"2001:db8::8"}
	}
	if f.failEgress {
		status = "unknown"
	}
	return Egress{Family: family, ProbeResult: ProbeResult{Status: status, Values: ips}}
}
func (f *fakeNetwork) Outbound(_ context.Context, family string) []Port {
	f.calls = append(f.calls, "outbound:"+family)
	status := "reachable"
	if f.failPorts {
		status = "unknown"
	}
	return []Port{{Family: family, Endpoint: "fixture.test:25", Status: status}}
}
func causes(fs []core.Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.Params["cause"])
	}
	sort.Strings(out)
	return out
}
func assertCauses(t *testing.T, fs []core.Finding, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	sort.Strings(want)
	if got := causes(fs); !reflect.DeepEqual(got, want) {
		t.Fatalf("causes %v want %v", got, want)
	}
	for _, f := range fs {
		if f.Module != "mail" || f.TitleKey == "" || f.WhyKey == "" || f.FixKey == "" {
			t.Fatalf("incomplete finding %+v", f)
		}
	}
}

func TestMailPlusChecks(t *testing.T) {
	tests := []struct {
		name   string
		change func(*State)
		want   []string
	}{
		{"healthy", func(*State) {}, nil},
		{"visibility", func(s *State) { s.Installed = nil }, []string{"unavailable"}},
		{"absent", func(s *State) { s.Installed = ptr(false) }, []string{"missing"}},
		{"stopped", func(s *State) { s.Running = ptr(false) }, []string{"stopped"}},
		{"running unknown", func(s *State) { s.Running = nil }, []string{"unavailable"}},
		{"smtp", func(s *State) { s.SMTPEnabled = ptr(false) }, []string{"smtp"}},
		{"smtp unknown", func(s *State) { s.SMTPEnabled = nil }, []string{"unavailable"}},
		{"queue unknown", func(s *State) { s.Queue.Total = nil }, []string{"unavailable"}},
		{"queue invalid", func(s *State) { s.Queue.Total = ptr(-1) }, []string{"unavailable"}},
		{"fresh queue", func(s *State) { s.Queue.Total = ptr(2); s.Queue.Oldest = ptr(testNow.Add(-time.Minute)) }, []string{"queue"}},
		{"stale queue", func(s *State) { s.Queue.Total = ptr(2); s.Queue.Oldest = ptr(testNow.Add(-time.Hour)) }, []string{"queue_stale"}},
		{"age unknown", func(s *State) { s.Queue.Total = ptr(2) }, []string{"queue", "queue_age"}},
		{"clock skew", func(s *State) { s.Queue.Total = ptr(2); s.Queue.Oldest = ptr(testNow.Add(time.Minute)) }, []string{"queue", "queue_age"}},
		{"reasons allowlist", func(s *State) {
			s.Queue.Total = ptr(2)
			s.Queue.Oldest = ptr(testNow)
			s.Queue.Reasons = []DeferredReason{DeferredAuth, DeferredDNS, DeferredTLS, DeferredPolicy, DeferredRemote, DeferredAuth, "SECRET"}
		}, []string{"queue", "deferred_auth", "deferred_dns", "deferred_tls", "deferred_policy", "deferred_remote"}},
		{"no stale reasons with empty queue", func(s *State) { s.Queue.Reasons = []DeferredReason{DeferredAuth} }, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := healthy()
			tt.change(&s)
			fs := checkMailPlus(s, testNow)
			assertCauses(t, fs, tt.want...)
			if strings.Contains(fmt.Sprint(fs), "SECRET") {
				t.Fatal("untrusted reason exposed")
			}
		})
	}
	a := healthy()
	a.Queue = QueueState{Total: ptr(2), Oldest: ptr(testNow.Add(-2 * time.Hour))}
	b := a
	b.Queue.Total = ptr(3)
	if checkMailPlus(a, testNow)[0].ID != checkMailPlus(b, testNow)[0].ID {
		t.Fatal("count changed stable finding ID")
	}
}

func TestRelayChecks(t *testing.T) {
	tests := []struct {
		name   string
		change func(*State)
		want   []string
	}{
		{"healthy", func(*State) {}, nil},
		{"unknown enabled", func(s *State) { s.Relay.Enabled = nil }, []string{"unavailable"}},
		{"stopped", func(s *State) { s.Relay = RelayState{Enabled: ptr(true), Running: ptr(false)} }, []string{"relay_stopped"}},
		{"running unknown", func(s *State) { s.Relay.Enabled = ptr(true) }, []string{"unavailable"}},
		{"idle not stale", func(s *State) {
			s.Relay = RelayState{Enabled: ptr(true), Running: ptr(true), LastSuccess: testNow.Add(-48 * time.Hour)}
		}, nil},
		{"pending stale", func(s *State) {
			s.Queue.Total = ptr(1)
			s.Relay = RelayState{Enabled: ptr(true), Running: ptr(true), LastSuccess: testNow.Add(-time.Hour)}
		}, []string{"relay_stale"}},
		{"pending recent", func(s *State) {
			s.Queue.Total = ptr(1)
			s.Relay = RelayState{Enabled: ptr(true), Running: ptr(true), LastSuccess: testNow.Add(-time.Minute)}
		}, nil},
		{"pending no history", func(s *State) { s.Queue.Total = ptr(1); s.Relay = RelayState{Enabled: ptr(true), Running: ptr(true)} }, []string{"relay_history"}},
		{"pending future history", func(s *State) {
			s.Queue.Total = ptr(1)
			s.Relay = RelayState{Enabled: ptr(true), Running: ptr(true), LastSuccess: testNow.Add(time.Hour)}
		}, []string{"relay_history"}},
		{"queue unknown", func(s *State) { s.Queue.Total = nil; s.Relay = RelayState{Enabled: ptr(true), Running: ptr(true)} }, []string{"unavailable"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { s := healthy(); tt.change(&s); assertCauses(t, checkRelay(s, testNow), tt.want...) })
	}
}

func TestCertificateAndPathChecks(t *testing.T) {
	for _, tt := range []struct {
		name    string
		visible bool
		certs   []MailCertificate
		want    []string
	}{
		{"not visible", false, nil, []string{"unavailable"}},
		{"empty", true, nil, []string{"unavailable"}},
		{"unrelated", true, []MailCertificate{{Service: "nginx"}}, []string{"unavailable"}},
		{"expiry unknown", true, []MailCertificate{{Service: "postfix"}}, []string{"unavailable"}},
		{"expired", true, []MailCertificate{{Service: "postfix", NotAfter: testNow}}, []string{"cert_expired"}},
		{"thirty days", true, []MailCertificate{{Service: "dovecot", NotAfter: testNow.Add(30 * 24 * time.Hour)}}, []string{"cert_soon"}},
		{"valid", true, healthy().Certificates, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := healthy()
			s.CertificatesVisible = tt.visible
			s.Certificates = tt.certs
			assertCauses(t, checkCertificates(s, testNow), tt.want...)
		})
	}
	for _, tt := range []struct {
		name            string
		change          func(*State)
		client, inbound []string
	}{
		{"working tunnel", func(*State) {}, nil, nil},
		{"unknown", func(s *State) { s.ClientReachable = nil; s.Inbound25 = nil }, []string{"client_unknown"}, []string{"inbound_unknown"}},
		{"failed", func(s *State) { s.ClientReachable = ptr(false); s.Inbound25 = ptr(false) }, []string{"client"}, []string{"inbound"}},
		{"imap disabled", func(s *State) { s.IMAPEnabled = ptr(false) }, []string{"imap"}, nil},
		{"imap unknown", func(s *State) { s.IMAPEnabled = nil }, []string{"unavailable"}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := healthy()
			tt.change(&s)
			assertCauses(t, checkClient(s), tt.client...)
			assertCauses(t, observedPath(Inbound, "inbound", s.Inbound25, "receive"), tt.inbound...)
		})
	}
}

func TestDomainChecks(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*State, *fakeDNS)
		want   []string
	}{
		{"all records", func(*State, *fakeDNS) {}, nil},
		{"missing all", func(_ *State, f *fakeDNS) { f.txt = nil; f.mx = nil }, []string{"mx", "spf", "dkim", "dmarc", "mtasts", "tlsrpt"}},
		{"null mx", func(_ *State, f *fakeDNS) { f.mx["example.test"] = []*net.MX{{Host: "."}} }, []string{"mx"}},
		{"unavailable dns", func(_ *State, f *fakeDNS) {
			for k := range f.txt {
				f.err[k] = errors.New("SECRET")
			}
			f.err["example.test"] = errors.New("SECRET")
		}, []string{"mx", "spf", "dkim", "dmarc", "mtasts", "tlsrpt"}},
		{"no selector guessed", func(s *State, _ *fakeDNS) { s.Domains[0].Selectors = nil }, []string{"dkim"}},
		{"invalid selector", func(s *State, _ *fakeDNS) { s.Domains[0].Selectors = []string{"bad/selector"} }, []string{"dkim"}},
		{"invalid domain", func(s *State, _ *fakeDNS) { s.Domains[0].Name = "SECRET/password" }, []string{"unavailable"}},
		{"no domains", func(s *State, _ *fakeDNS) { s.Domains = nil }, []string{"unavailable"}},
		{"duplicate domain", func(s *State, _ *fakeDNS) { s.Domains = append(s.Domains, s.Domains[0]) }, nil},
		{"invalid dmarc", func(_ *State, f *fakeDNS) { f.txt["_dmarc.example.test"] = []string{"v=DMARC1; p=invalid"} }, []string{"dmarc"}},
		{"invalid mtasts", func(_ *State, f *fakeDNS) { f.txt["_mta-sts.example.test"] = []string{"v=STSv1"} }, []string{"mtasts"}},
		{"invalid tlsrpt", func(_ *State, f *fakeDNS) { f.txt["_smtp._tls.example.test"] = []string{"v=TLSRPTv1"} }, []string{"tlsrpt"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, f := healthy(), goodDNS()
			tt.change(&s, f)
			got := checkDomains(checkerFor(f), s)
			assertCauses(t, got, tt.want...)
			b, _ := json.Marshal(got)
			if strings.Contains(string(b), "SECRET") {
				t.Fatal("raw error or malformed input exposed")
			}
		})
	}
	s := healthy()
	for i := 0; i < 11; i++ {
		s.Domains = append(s.Domains, s.Domains[0])
	}
	assertCauses(t, checkDomains(checkerFor(goodDNS()), s), "bounded")
}

func TestNetworkChecks(t *testing.T) {
	for _, tt := range []struct {
		name      string
		change    func(*State, *fakeDNS, *fakeNetwork)
		wantCause string
		severity  core.Severity
	}{
		{"ptr missing", func(_ *State, f *fakeDNS, _ *fakeNetwork) { f.reverse = nil }, "ptr", core.SeverityWarning},
		{"ptr unknown", func(_ *State, f *fakeDNS, _ *fakeNetwork) { f.err["203.0.113.8"] = errors.New("SECRET") }, "ptr", core.SeverityInfo},
		{"relay ptr informational", func(s *State, f *fakeDNS, _ *fakeNetwork) { s.Relay.Enabled = ptr(true); f.reverse = nil }, "ptr", core.SeverityInfo},
		{"egress uncertain", func(_ *State, _ *fakeDNS, n *fakeNetwork) { n.failEgress = true }, "egress", core.SeverityInfo},
		{"port failure not proven filtering", func(_ *State, _ *fakeDNS, n *fakeNetwork) { n.failPorts = true }, "outbound", core.SeverityInfo},
		{"no provider opted in", func(*State, *fakeDNS, *fakeNetwork) {}, "dnsbl_unknown", core.SeverityInfo},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, f, n := healthy(), goodDNS(), &fakeNetwork{}
			tt.change(&s, f, n)
			got := New(Dependencies{Network: n}).checkNetwork(context.Background(), checkerFor(f), s)
			found := false
			for _, finding := range got {
				if finding.Params["cause"] == tt.wantCause {
					found = true
					if finding.Severity != tt.severity {
						t.Fatal(finding)
					}
				}
			}
			if !found {
				t.Fatalf("missing %s: %+v", tt.wantCause, got)
			}
			if len(n.calls) != 4 {
				t.Fatal("network probes not both families", n.calls)
			}
		})
	}
	for _, listed := range []bool{false, true} {
		f := goodDNS()
		f.hosts["2.0.0.127.psbl.surriel.com"] = []string{"127.0.0.2"}
		if listed {
			f.hosts["8.113.0.203.psbl.surriel.com"] = []string{"127.0.0.2"}
		}
		c := checkerFor(f)
		c.enabledProviders = []string{"PSBL"}
		got := New(Dependencies{Network: &fakeNetwork{}}).checkNetwork(context.Background(), c, healthy())
		count := 0
		for _, finding := range got {
			if finding.Params["cause"] == "dnsbl" {
				count++
			}
		}
		if (count == 1) != listed {
			t.Fatal("DNSBL listing mapping", got)
		}
	}
}

func TestDNSBLControlsAndSecretSafety(t *testing.T) {
	for _, tt := range []struct{ name, positive, negative, target, want string }{
		{"not listed", "127.0.0.2", "", "", "not_listed"},
		{"listed", "127.0.0.2", "", "127.0.0.10", "listed"},
		{"all nxdomain", "", "", "", "unknown"},
		{"wildcard", "127.0.0.2", "127.0.0.2", "127.0.0.2", "unknown"},
		{"provider refusal", "127.255.255.254", "", "", "unknown"},
		{"unexpected target", "127.0.0.2", "", "192.0.2.1", "unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := goodDNS()
			zone := "SECRET.zen.dq.spamhaus.net"
			for name, value := range map[string]string{"2.0.0.127": tt.positive, "1.0.0.127": tt.negative, "8.113.0.203": tt.target} {
				if value != "" {
					f.hosts[dnsName(name+"."+zone)] = []string{value}
				}
			}
			c := checkerFor(f)
			c.key = "SECRET"
			c.enabledProviders = []string{"Spamhaus ZEN"}
			got := c.bl(netip.MustParseAddr("203.0.113.8"), c.providers()[0])
			if got.Status != tt.want {
				t.Fatalf("%+v", got)
			}
			b, _ := json.Marshal(got)
			if strings.Contains(string(b), "SECRET") {
				t.Fatal("DQS key exposed")
			}
		})
	}
	err := fmt.Errorf("wrapped: %w", &net.DNSError{Name: "SECRET.zone", Err: "SECRET", IsNotFound: true})
	if got := dnsResult(nil, err); got.Status != "missing" || strings.Contains(got.Detail, "SECRET") {
		t.Fatal(got)
	}
}

func TestSPFAndDKIMPreflight(t *testing.T) {
	for _, tt := range []struct{ name, record, want string }{
		{"valid", "v=spf1 ip4:203.0.113.8 -all", "pass"},
		{"invalid ip", "v=spf1 ip4:garbage -all", "fail"},
		{"cycle", "v=spf1 include:example.test -all", "unknown"},
		{"macro", "v=spf1 exists:%{i}.example.test -all", "unknown"},
		{"mx needs evaluator", "v=spf1 mx -all", "unknown"},
		{"unknown mechanism", "v=spf1 nope -all", "fail"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := goodDNS()
			f.txt["example.test"] = []string{tt.record}
			got := checkerFor(f).spf("example.test")
			if got.Status != tt.want {
				t.Fatalf("%+v", got)
			}
			if !strings.HasPrefix(got.Authorization, "unknown:") {
				t.Fatal("sender authorization inferred")
			}
		})
	}
	for _, n := range []int{10, 11} {
		f := goodDNS()
		terms := []string{"v=spf1"}
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("i%d.example.test", i)
			terms = append(terms, "include:"+name)
			f.txt[name] = []string{"v=spf1 -all"}
		}
		terms = append(terms, "-all")
		f.txt["example.test"] = []string{strings.Join(terms, " ")}
		got := checkerFor(f).spf("example.test")
		want := "pass"
		if n == 11 {
			want = "unknown"
		}
		if got.Status != want || got.LookupTerms != n {
			t.Fatal(got)
		}
	}
	for _, tt := range []struct{ record, want string }{
		{"v=DKIM1; p=", "fail"},
		{"v=DKIM1; p=bad-base64", "fail"},
		{"v=DKIM1; k=unknown; p=YWJj", "unknown"},
		{"v=DKIM1; k=ed25519; p=YWJj", "fail"},
		{"v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(make([]byte, 32)), "present"},
	} {
		got := dkimCheck("mail", ProbeResult{Status: "present", Values: []string{tt.record}})
		if got.Status != tt.want {
			t.Fatal(got)
		}
	}
}

func TestSymptomPlansAndRanking(t *testing.T) {
	expected := map[Symptom][]CheckID{
		CannotSend: {Transport, MailPlus, Access, Relay, Network, DomainDNS}, BounceOrSpam: {Transport, DomainDNS, Network, MailPlus, Relay},
		CannotReceive: {Transport, MailPlus, Access, DomainDNS, Inbound, Certificate}, PhoneConnect: {Transport, MailPlus, Access, Certificate, Client},
		NotSure: {Transport, MailPlus, Access, Relay, Network, DomainDNS, Inbound, Certificate, Client},
	}
	for symptom, want := range expected {
		t.Run(string(symptom), func(t *testing.T) {
			plan, ok := PlanFor(symptom)
			if !ok || !reflect.DeepEqual(plan.Checks, want) {
				t.Fatal(plan)
			}
			fs := []core.Finding{finding(MailPlus, "unavailable", "", core.SeverityInfo, "", nil)}
			for i := len(plan.Causes) - 1; i >= 0; i-- {
				fs = append(fs, finding(want[0], plan.Causes[i], "", core.SeverityWarning, "send", nil))
			}
			got := Rank(symptom, fs)
			for i, cause := range plan.Causes {
				if got[i].Params["cause"] != cause {
					t.Fatal("ranking", causes(got))
				}
			}
			if got[len(got)-1].Params["cause"] != "unavailable" {
				t.Fatal("unknown ranked as cause")
			}
			if got[0].FixWizard != "mail.setup" || got[0].Params["intent"] != "send" {
				t.Fatal("missing handoff intent")
			}
			plan.Checks[0] = "mutation"
			copy, _ := PlanFor(symptom)
			if copy.Checks[0] == "mutation" {
				t.Fatal("mutable global plan")
			}
		})
	}
	if _, ok := PlanFor("invented"); ok {
		t.Fatal("unknown symptom accepted")
	}
	plans := Plans()
	if len(plans) != 5 {
		t.Fatal(plans)
	}
}

func TestRunnerAndWizardAreReadOnlyAndIdempotent(t *testing.T) {
	source := &fakeState{value: healthy()}
	d := New(Dependencies{State: source, DNS: goodDNS(), Network: &fakeNetwork{}})
	env := core.Env{Now: func() time.Time { return testNow }}
	if len(d.Checks()) != 9 {
		t.Fatal("missing scheduled checks")
	}
	for _, check := range d.Checks() {
		if check.ID() == "" || check.Interval() < 0 {
			t.Fatal(check)
		}
	}
	// Secrets/KV/DSM intentionally remain nil: any unauthorized access panics.
	for _, check := range d.Checks() {
		if _, err := check.Run(context.Background(), env); err != nil {
			t.Fatal(err)
		}
	}
	for _, plan := range Plans() {
		t.Run(string(plan.Symptom), func(t *testing.T) {
			runner := &Runner{D: d}
			before := source.calls
			run, err := runner.Start("admin", plan.Symptom)
			if err != nil || run.Done != 0 || run.Total != len(plan.Checks) || run.Complete || source.calls != before {
				t.Fatal("start must not run a check", run, err)
			}
			if _, err := runner.Next(context.Background(), env, "other-admin", run.ID, time.Minute); !errors.Is(err, ErrUnknownRun) {
				t.Fatal("another administrator advanced the run", err)
			}
			for range plan.Checks {
				run, err = runner.Next(context.Background(), env, "admin", run.ID, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
			}
			if !run.Complete || run.Done != run.Total || source.calls != before+1 {
				t.Fatal("bad completion: a run reads its snapshot exactly once", run)
			}
			for _, f := range run.Findings {
				found := false
				for _, id := range plan.Checks {
					found = found || f.Check == string(id)
				}
				if !found {
					t.Fatal("irrelevant check", f.Check)
				}
			}
			saved, _ := json.Marshal(run)
			again, err := runner.Next(context.Background(), env, "admin", run.ID, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(again)
			if string(b) != string(saved) || source.calls != before+1 {
				t.Fatal("completed run reran checks")
			}
		})
	}
	if _, err := (&Runner{D: d}).Start("admin", Symptom("invented")); !errors.Is(err, ErrUnknownSymptom) {
		t.Fatal("invalid symptom accepted")
	}
	source.err = errors.New("SECRET password cookie")
	fs, err := d.Run(context.Background(), env, MailPlus, Network)
	if err != nil {
		t.Fatal(err)
	}
	assertCauses(t, fs, "unavailable", "unavailable")
	b, _ := json.Marshal(fs)
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("source error leaked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := source.calls
	if _, err := d.Run(ctx, env, MailPlus); !errors.Is(err, context.Canceled) || source.calls != before {
		t.Fatal("cancellation ignored", err)
	}
	if _, err := d.Run(context.Background(), env, "unknown"); err == nil {
		t.Fatal("unknown check accepted")
	}
}

func TestDiagnosticLocales(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..", "i18n", "messages")
	var english map[string]string
	for _, locale := range []string{"en", "zh-TW", "zh-CN", "ja", "ko", "de", "fr", "es", "it"} {
		b, err := os.ReadFile(filepath.Join(root, locale+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var texts map[string]string
		if err := json.Unmarshal(b, &texts); err != nil {
			t.Fatal(err)
		}
		if locale == "en" {
			english = texts
		}
		for key, text := range english {
			if !strings.HasPrefix(key, prefix) {
				continue
			}
			got, ok := texts[key]
			if !ok || strings.TrimSpace(got) == "" {
				t.Fatal(locale, key, "missing translation")
			}
			if strings.HasSuffix(got, ".") || strings.HasSuffix(got, "。") || strings.Contains(got, "…") {
				t.Fatal(locale, key, "copy rule", got)
			}
			if strings.Contains(text, "{subject}") != strings.Contains(got, "{subject}") {
				t.Fatal(locale, key, "placeholder mismatch")
			}
		}
		for key := range texts {
			if strings.HasPrefix(key, prefix) && english[key] == "" {
				t.Fatal(locale, key, "extra key")
			}
		}
	}
	allCauses := []string{"unavailable", "bounded", "missing", "stopped", "smtp", "queue", "queue_stale", "queue_age", "deferred_dns", "deferred_auth", "deferred_tls", "deferred_policy", "deferred_remote", "relay_stopped", "relay_stale", "relay_history", "mx", "spf", "dkim", "dmarc", "mtasts", "tlsrpt", "egress", "ptr", "dnsbl", "dnsbl_unknown", "outbound", "inbound", "inbound_unknown", "client", "client_unknown", "imap", "cert_soon", "cert_expired"}
	for _, cause := range allCauses {
		f := finding(MailPlus, cause, "fixture", core.SeverityInfo, "", nil)
		for _, key := range []string{f.TitleKey, f.WhyKey, f.FixKey} {
			if english[key] == "" {
				t.Fatal("untranslated finding", key)
			}
		}
	}
}
