package detect

import (
	"context"

	"SynoMailPlusSetupAssistant/internal/core"
	"net"
	"net/http"
	"strings"
	"time"
)

// Resolver/HTTPDoer/Dialer permit deterministic fakes; no network runs on import.
type Resolver interface {
	LookupTXT(context.Context, string) ([]string, error)
	LookupHost(context.Context, string) ([]string, error)
	LookupAddr(context.Context, string) ([]string, error)
	LookupIP(context.Context, string, string) ([]net.IP, error)
	LookupMX(context.Context, string) ([]*net.MX, error)
	LookupNS(context.Context, string) ([]*net.NS, error)
	LookupCNAME(context.Context, string) (string, error)
}
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}
type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type Detector struct {
	Resolver   Resolver
	HTTP       HTTPDoer
	Dial       Dialer
	Extensions Extensions
	// Timeout bounds one network or DNS probe (default 5 s). DSM reads are
	// bounded by core per call and by DSMBudget for the whole MailPlus pass.
	Timeout   time.Duration
	DSMBudget time.Duration
}

func New() *Detector {
	r := &net.Resolver{PreferGo: true}
	d := &net.Dialer{Resolver: r, Timeout: 5 * time.Second}
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) { return d.DialContext(ctx, "tcp4", addr) }}
	return &Detector{Resolver: systemResolver{Resolver: r, resolvConf: "/etc/resolv.conf"}, Dial: d, HTTP: &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, Timeout: 5 * time.Second}
}

// bounded isolates failures, enforces a deadline even for a faulty adapter, and
// never exposes adapter error strings (which can contain credential payloads):
// a failure keeps only its fixed cause (core.Cause). timeout <= 0 adds no
// deadline of its own beyond parent's.
// Adapter implementations must still honor cancellation to avoid abandoned work.
func bounded[T any](parent context.Context, timeout time.Duration, fn func(context.Context) (T, error)) Observation[T] {
	return boundedCause(parent, timeout, fn, core.Cause)
}

// boundedCause is bounded with its own fixed-cause mapping (DSM reads use
// dsmCause).
func boundedCause[T any](parent context.Context, timeout time.Duration, fn func(context.Context) (T, error), cause func(error) string) Observation[T] {
	ctx, cancel := parent, context.CancelFunc(func() {})
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, timeout)
	}
	defer cancel()
	type reply struct {
		v   T
		err error
	}
	ch := make(chan reply, 1)
	go func() { v, e := fn(ctx); ch <- reply{v, e} }()
	select {
	case r := <-ch:
		if r.err == nil {
			return Fact(r.v)
		}
		return unknown[T](cause(r.err))
	case <-ctx.Done():
		return unknown[T](core.CauseTimeout)
	}
}
func observedCheck[T any](o Observation[T], convert func(T) Check) Check {
	if !o.IsKnown() {
		return Check{Status: "unknown", Detail: o.Detail}
	}
	return convert(o.Value)
}
func (d *Detector) checker(ctx context.Context) *checker {
	t := d.Timeout
	if t <= 0 || t > 30*time.Second {
		t = 5 * time.Second
	}
	return &checker{ctx: ctx, r: d.Resolver, http: d.HTTP, dial: d.Dial, timeout: t, txtCache: map[string]Check{}, controls: map[string]Check{}}
}

// Evidence sources of DNS.Cloudflare.
const (
	SourceDNS  = "dns"
	SourceZone = "zone"
)

// cloudflareNS decides from the zone's NS records whether Cloudflare hosts
// it; without them it is unknown.
func cloudflareNS(v Check) Observation[bool] {
	if v.Status != "present" {
		return unknown[bool](CauseDNSUnknown)
	}
	for _, n := range v.Values {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if !strings.HasSuffix(n, ".ns.cloudflare.com") {
			return Fact(false)
		}
	}
	return Fact(true)
}
