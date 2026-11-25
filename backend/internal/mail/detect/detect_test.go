package detect

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

type fakeResolver struct {
	ptrErr  error
	hostErr error
	nsErr   error
	txt     map[string][]string
	ips     map[string][]net.IP
}

func missing(name string) error { return &net.DNSError{IsNotFound: true, Name: name, Err: "missing"} }
func (f fakeResolver) LookupTXT(_ context.Context, n string) ([]string, error) {
	v, ok := f.txt[n]
	if !ok {
		return nil, missing(n)
	}
	return v, nil
}
func (f fakeResolver) LookupHost(context.Context, string) ([]string, error) {
	if f.hostErr != nil {
		return nil, f.hostErr
	}
	return []string{"192.0.2.1"}, nil
}
func (f fakeResolver) LookupAddr(context.Context, string) ([]string, error) {
	if f.ptrErr != nil {
		return nil, f.ptrErr
	}
	return []string{"mail.example.test."}, nil
}
func (f fakeResolver) LookupIP(_ context.Context, _, n string) ([]net.IP, error) {
	v, ok := f.ips[n]
	if !ok {
		return nil, missing(n)
	}
	return v, nil
}
func (f fakeResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, missing("example.test")
}

// LookupCNAME: no alias (the name resolves to addresses itself).
func (f fakeResolver) LookupCNAME(_ context.Context, n string) (string, error) { return n, nil }
func (f fakeResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	if f.nsErr != nil {
		return nil, f.nsErr
	}
	return []*net.NS{{Host: "a.ns.cloudflare.com."}, {Host: "b.ns.cloudflare.com."}}, nil
}

type fakeHTTP struct{}

func (fakeHTTP) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("192.0.2.1"))}, nil
}

type fakeDial struct{}

func (fakeDial) DialContext(context.Context, string, string) (net.Conn, error) {
	a, b := net.Pipe()
	b.Close()
	return a, nil
}

type extensions struct {
	mu      sync.Mutex
	inbound int
}

func (*extensions) Addressing(context.Context, string) (Addressing, error) { return Fixed, nil }
func (e *extensions) Inbound25(context.Context, string) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.inbound++
	return true, nil
}
func (*extensions) Tunnel(context.Context) (Tunnel, error) {
	return Tunnel{ID: "fake-tunnel", Ready: true, SMTPHost: "10.0.0.2"}, nil
}
func (*extensions) Readiness(context.Context, string) (bool, bool, error) {
	return false, false, errors.New("no delivery receipt")
}
func (*extensions) DNSReadiness(context.Context, string) (bool, bool, error) {
	return false, false, errors.New("not evaluated")
}

// fakeDSM records every call; the detector reads concurrently, so calls are
// guarded. slow delays a call (honoring cancellation); errs injects a failure.
type fakeDSM struct {
	// license replaces the License v1 replies by method (nil: the test NAS
	// fixture, limit 5 and total 4).
	license map[string]any
	// noLicenseAPI leaves SYNO.MailPlusServer.License out of SYNO.API.Info.
	noLicenseAPI bool
	fail         string
	malformed    bool
	slow         map[string]time.Duration
	errs         map[string]error
	mu           sync.Mutex
	calls        []string
}

func (f *fakeDSM) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeDSM) Call(ctx context.Context, api, method string, version int, params map[string]any, out any) error {
	key := api + "." + method
	if api == "SYNO.MailPlusServer.License" && version != 1 {
		return core.DSMError{Code: 103} // versions 2 and 3 have neither method
	}
	f.mu.Lock()
	f.calls = append(f.calls, key)
	f.mu.Unlock()
	if delay := f.slow[key]; delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return core.ErrDSMTimeout
		}
	}
	if err := f.errs[key]; err != nil {
		return err
	}
	if key == f.fail {
		return errors.New("must not expose credentials from upstream errors")
	}
	var v any
	switch key {
	case "SYNO.Core.Package.list":
		if f.malformed {
			v = map[string]any{}
		} else {
			v = map[string]any{"packages": []any{map[string]any{"id": "MailPlus-Server", "version": "4.1.1-31785", "additional": map[string]any{"status": "running", "installed_info": map[string]any{"is_broken": false, "is_brick": false}}}}}
		}
	case "SYNO.API.Info.query":
		m := map[string]any{}
		for _, api := range []string{"SYNO.MailPlusServer.Domain", "SYNO.MailPlusServer.Domain.User", "SYNO.MailPlusServer.Service.SMTP", "SYNO.MailPlusServer.SMTP.Delivery", "SYNO.MailPlusServer.Queue", "SYNO.MailPlusServer.License"} {
			m[api] = map[string]any{"minVersion": 1, "maxVersion": 3}
		}
		if f.noLicenseAPI {
			delete(m, "SYNO.MailPlusServer.License")
		}
		v = m
	case "SYNO.MailPlusServer.Service.SMTP.get":
		v = map[string]any{"enable_smtp": true, "smtp_port": 25}
	case "SYNO.MailPlusServer.Domain.list":
		if params["offset"] != 0 || params["limit"] != -1 {
			return errors.New("wrong domain list params")
		}
		v = map[string]any{"domains": []any{map[string]any{"domain_id": 1, "name": "example.test", "is_primary": true, "user_num": 2}}}
	case "SYNO.MailPlusServer.Domain.User.list":
		if params["domain_id"] != 1 || params["limit"] != 100 {
			return errors.New("wrong user page params")
		}
		// Two short pages ensure pagination follows total rather than the page size
		offset := params["offset"].(int)
		name := "alice"
		if offset == 1 {
			name = "bob"
		}
		v = map[string]any{"users": []any{map[string]any{"id": offset + 1, "name": name, "is_activated": true, "aliases": []any{map[string]any{"alias": name}}}}, "total": 2}
	case "SYNO.MailPlusServer.Domain.get_security":
		v = map[string]any{"enable_dkim_sign": true, "dkim_selector": "mail", "dkim_public_key": "public-key"}
	case "SYNO.MailPlusServer.SMTP.Delivery.get_type":
		v = map[string]any{"host_type": "none", "enable_fallback_relay": false}
	case "SYNO.MailPlusServer.SMTP.Delivery.get_multiple":
		v = map[string]any{"host_list": []any{map[string]any{"id": 1, "server": "other.test", "port": 587, "security_connection": true, "enable_auth": true, "auth_name": "must-not-expose-name", "auth_password": "must-not-expose-password"}}}
	case "SYNO.MailPlusServer.License.get_user_limit", "SYNO.MailPlusServer.License.get_active_user_num":
		// Replies read on a test NAS (MailPlus Server 4.1.1-31785, five free licences).
		v = map[string]any{"get_user_limit": map[string]any{"limit": 5}, "get_active_user_num": map[string]any{"total": 4}}[method]
		if r, ok := f.license[method]; ok {
			v = r
		}
	case "SYNO.MailPlusServer.Queue.list":
		if params["limit"] != 1 {
			return errors.New("queue must not enumerate mail")
		}
		v = map[string]any{"items": []any{}, "total": 3}
	default:
		return errors.New("unexpected method")
	}
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, out)
}
func TestReadOnlyDetectionIsPartialRedactedAndPaginated(t *testing.T) {
	dsm := &fakeDSM{fail: "SYNO.MailPlusServer.Service.SMTP.get"}
	d := &Detector{Timeout: 20 * time.Millisecond, Resolver: fakeResolver{}, HTTP: fakeHTTP{}, Dial: fakeDial{}, Extensions: &extensions{}}
	s := d.Detect(context.Background(), core.Env{DSM: dsm}, Request{Domain: "example.test"})
	if !s.Package.IsKnown() || !s.Package.Value.Running || s.SMTP.IsKnown() {
		t.Fatal("failed SMTP probe lost package facts or became false")
	}
	if !s.QueueSize.IsKnown() || s.QueueSize.Value != 3 || len(s.Accounts[s.Domain].Value) != 2 {
		t.Fatal("partial probe failure lost queue or paginated accounts")
	}
	if s.SendReady.IsKnown() {
		t.Fatal("unknown readiness became known")
	}
	if !s.Network.EgressIPv4.IsKnown() || !s.Network.FCrDNS.IsKnown() || !s.Network.FCrDNS.Value {
		t.Fatal("E4 egress/PTR/forward evidence missing")
	}
	if s.Network.Inbound25.IsKnown() {
		t.Fatal("send-only detection probed inbound")
	}
	b, _ := json.Marshal(s)
	for _, secret := range []string{"must-not-expose-name", "must-not-expose-password", "must not expose credentials"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("sensitive upstream data in State")
		}
	}
	for _, method := range dsm.called() {
		if !(strings.HasSuffix(method, ".get") || strings.HasSuffix(method, ".list") || strings.HasSuffix(method, ".query") || strings.HasSuffix(method, ".get_type") || strings.HasSuffix(method, ".get_multiple") || strings.HasSuffix(method, ".get_security") ||
			method == "SYNO.MailPlusServer.License.get_user_limit" || method == "SYNO.MailPlusServer.License.get_active_user_num") {
			t.Fatalf("detection called a write: %s", method)
		}
	}
}
func TestInboundOnlyWithExplicitReceiveRequest(t *testing.T) {
	e := &extensions{}
	d := &Detector{Extensions: e, HTTP: fakeHTTP{}, Timeout: 20 * time.Millisecond}
	s := d.Detect(context.Background(), core.Env{}, Request{Domain: "example.test", Receive: false})
	if s.Network.Inbound25.IsKnown() || e.inbound != 0 {
		t.Fatal("inbound probe without receive intent")
	}
	s = d.Detect(context.Background(), core.Env{}, Request{Domain: "example.test", Receive: true})
	if !s.Network.Inbound25.IsKnown() || !s.Network.Inbound25.Value || e.inbound != 1 {
		t.Fatal("receive probe not performed")
	}
}
func TestMalformedPackageIsUnknownNotAbsent(t *testing.T) {
	dsm := &fakeDSM{malformed: true}
	s := (&Detector{Timeout: time.Millisecond}).Detect(context.Background(), core.Env{DSM: dsm}, Request{Domain: "example.test"})
	if s.Package.IsKnown() {
		t.Fatal("malformed package response treated as not installed")
	}
	// With a 1 ms deadline the package probe may be abandoned before or after
	// it calls DSM; either way nothing beyond the package list is probed.
	for _, method := range dsm.called() {
		if method != "SYNO.Core.Package.list" {
			t.Fatalf("probed private MailPlus API %s without known running package", method)
		}
	}
}
func TestTimeoutIsolationAndSanitizedUnknown(t *testing.T) {
	start := time.Now()
	o := bounded(context.Background(), 5*time.Millisecond, func(ctx context.Context) (bool, error) { <-ctx.Done(); return false, ctx.Err() })
	if o.IsKnown() || time.Since(start) > time.Second {
		t.Fatal("probe timeout was not bounded")
	}
	s := (&Detector{Timeout: 10 * time.Millisecond, Resolver: fakeResolver{ptrErr: errors.New("private query payload"), nsErr: errors.New("secret resolver details")}, HTTP: fakeHTTP{}}).Detect(context.Background(), core.Env{}, Request{Domain: "example.test"})
	if !s.Network.EgressIPv4.IsKnown() || s.Network.FCrDNS.IsKnown() || s.DNS.Cloudflare.IsKnown() {
		t.Fatal("one failed probe changed unrelated facts or became known")
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "secret resolver") || strings.Contains(string(b), "private query") {
		t.Fatal("upstream error leaked")
	}
}
func TestDNSBLControlsAndDocumentedCodes(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		positive, negative, target []net.IP
		want                       string
	}{
		{"valid-listing", []net.IP{net.ParseIP("127.0.0.2")}, nil, []net.IP{net.ParseIP("127.0.0.2")}, "listed"},
		{"clean-with-valid-controls", []net.IP{net.ParseIP("127.0.0.2")}, nil, nil, "not_listed"},
		{"missing-positive-control", nil, nil, nil, "unknown"},
		{"wildcard-resolver", []net.IP{net.ParseIP("127.0.0.2")}, []net.IP{net.ParseIP("127.0.0.2")}, nil, "unknown"},
		{"provider-error-not-listed", []net.IP{net.ParseIP("127.0.0.2")}, nil, []net.IP{net.ParseIP("127.255.255.254")}, "unknown"},
		{"undocumented-code", []net.IP{net.ParseIP("127.0.0.2")}, nil, []net.IP{net.ParseIP("127.0.0.99")}, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ips := map[string][]net.IP{}
			if tc.positive != nil {
				ips["2.0.0.127.test.invalid."] = tc.positive
			}
			if tc.negative != nil {
				ips["1.0.0.127.test.invalid."] = tc.negative
			}
			if tc.target != nil {
				ips["1.2.0.192.test.invalid."] = tc.target
			}
			c := (&Detector{Resolver: fakeResolver{ips: ips}, Timeout: time.Millisecond}).checker(context.Background())
			p := provider{name: "fake", zone: "test.invalid", codes: map[string]string{"127.0.0.2": "listed"}}
			got := c.bl(mustAddr(t, "192.0.2.1"), p)
			if got.Status != tc.want {
				t.Fatalf("got %s want %s", got.Status, tc.want)
			}
		})
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	v, e := netip.ParseAddr(s)
	if e != nil {
		t.Fatal(e)
	}
	return v
}

// a name without its own DMARC follows its parent's policy, up to the
// zone; a lookup that fails is unknown, never "no policy".
func TestParentDMARC(t *testing.T) {
	policy := []string{"v=DMARC1; p=quarantine; rua=mailto:d@example.test"}
	check := func(txt map[string][]string, name, zone string) Check {
		return (&Detector{Resolver: fakeResolver{txt: txt}, Timeout: time.Second}).checker(context.Background()).parentDMARC(name, zone)
	}
	if c := check(map[string][]string{"_dmarc.example.test.": policy}, "mail.example.test", "example.test"); c.Status != "present" || c.Detail != "example.test" {
		t.Fatalf("zone policy: %+v", c)
	}
	if c := check(map[string][]string{"_dmarc.b.example.test.": policy}, "a.b.example.test", "example.test"); c.Status != "present" || c.Detail != "b.example.test" {
		t.Fatalf("nearest parent: %+v", c)
	}
	// Not above the zone, and never the zone itself for the apex.
	if c := check(map[string][]string{"_dmarc.test.": policy}, "example.test", "example.test"); c.Status != "missing" {
		t.Fatalf("apex: %+v", c)
	}
	if c := check(map[string][]string{"_dmarc.example.test.": {"v=DMARC1; p=bogus"}}, "mail.example.test", "example.test"); c.Status != "missing" {
		t.Fatalf("invalid parent: %+v", c)
	}
	// Unknown zone: down to two labels.
	if c := check(map[string][]string{"_dmarc.example.test.": policy}, "mail.example.test", ""); c.Status != "present" {
		t.Fatalf("no zone: %+v", c)
	}
	if c := (&Detector{Resolver: timeoutTXT{}, Timeout: time.Second}).checker(context.Background()).parentDMARC("mail.example.test", "example.test"); c.Status != "unknown" {
		t.Fatalf("failed lookup: %+v", c)
	}
}

type timeoutTXT struct{ fakeResolver }

func (timeoutTXT) LookupTXT(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{IsTimeout: true, Err: "timeout"}
}
