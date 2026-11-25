package diagnose

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// SystemNetwork implements only public egress reads and TCP handshakes, never
// SMTP commands or message submission; it ignores environment HTTP proxies.
type SystemNetwork struct {
	Resolver *net.Resolver
	Timeout  time.Duration
	// GlobalIPv6 reports whether this host has a global IPv6 address
	// (default: the interface addresses). Tests replace it.
	GlobalIPv6 func() (bool, error)
}

// noIPv6 decides deterministically whether IPv6 probes cannot work: the host
// has no global unicast IPv6 address (link-local and ULA fc00::/7 are not
// global). It returns the reason, or "" when IPv6 should be probed. An
// unreadable address list is a reason too: the family stays unknown.
func (n SystemNetwork) noIPv6() string {
	has := n.GlobalIPv6
	if has == nil {
		has = hostGlobalIPv6
	}
	ok, err := has()
	switch {
	case err != nil:
		return "host addresses unavailable; IPv6 not probed"
	case !ok:
		return "no global IPv6 address on this host; IPv6 not probed"
	}
	return ""
}

func hostGlobalIPv6() (bool, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, err
	}
	for _, a := range addrs {
		prefix, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		ip := prefix.Addr()
		if ip.Is6() && !ip.Is4In6() && ip.IsGlobalUnicast() && !ip.IsPrivate() {
			return true, nil
		}
	}
	return false, nil
}

func (n SystemNetwork) timeout() time.Duration {
	if n.Timeout <= 0 || n.Timeout > 30*time.Second {
		return 5 * time.Second
	}
	return n.Timeout
}

func (n SystemNetwork) Egress(ctx context.Context, family string) Egress {
	endpoints := []string{"https://api.ipify.org", "https://ipv4.icanhazip.com"}
	if family == "tcp6" {
		endpoints = []string{"https://api6.ipify.org", "https://ipv6.icanhazip.com"}
	}
	out := Egress{Family: family, ProbeResult: ProbeResult{Status: "unknown"}}
	if family == "tcp6" {
		if reason := n.noIPv6(); reason != "" {
			out.ProbeResult.Detail = reason
			return out
		}
	}
	// Both sources are asked at once, so a dead family costs one timeout.
	checks := make([]ProbeResult, len(endpoints))
	var wg sync.WaitGroup
	for i, url := range endpoints {
		wg.Add(1)
		go func() {
			defer wg.Done()
			checks[i] = n.egressFrom(ctx, family, url)
		}()
	}
	wg.Wait()
	seen := map[string]int{}
	for _, check := range checks {
		if check.Status == "pass" {
			seen[check.Values[0]]++
		}
		out.Sources = append(out.Sources, check)
	}
	for ip, count := range seen {
		out.ProbeResult.Values = append(out.ProbeResult.Values, ip)
		if count == 2 {
			out.ProbeResult.Status = "pass"
			out.ProbeResult.Detail = "two independent sources agree"
		}
	}
	sort.Strings(out.ProbeResult.Values)
	if out.ProbeResult.Status != "pass" {
		out.ProbeResult.Detail = "two-source agreement unavailable; no inference that this address family is disabled"
	}
	return out
}

func (n SystemNetwork) egressFrom(ctx context.Context, family, url string) ProbeResult {
	d := &net.Dialer{Timeout: n.timeout(), Resolver: n.Resolver}
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		return d.DialContext(ctx, family, addr)
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: n.timeout(), Transport: tr, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	res, err := client.Do(req)
	check := ProbeResult{Status: "unknown", Detail: url + ": network unavailable"}
	if err == nil {
		data, readErr := io.ReadAll(io.LimitReader(res.Body, 256))
		res.Body.Close()
		ip, parseErr := netip.ParseAddr(strings.TrimSpace(string(data)))
		if res.StatusCode == 200 && readErr == nil && parseErr == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && ((family == "tcp4") == ip.Is4()) {
			check = ProbeResult{Status: "pass", Values: []string{ip.String()}, Detail: url}
		} else {
			check.Detail = url + ": invalid HTTP status or address"
		}
	}
	return check
}

func (n SystemNetwork) Outbound(ctx context.Context, family string) []Port {
	endpoints := []string{"portquiz.net:25", "gmail-smtp-in.l.google.com:25"}
	out := make([]Port, len(endpoints))
	if family == "tcp6" {
		if reason := n.noIPv6(); reason != "" {
			for i, endpoint := range endpoints {
				out[i] = Port{Family: family, Endpoint: endpoint, Status: "unknown", Detail: reason}
			}
			return out
		}
	}
	var wg sync.WaitGroup
	for i, endpoint := range endpoints {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(ctx, n.timeout())
			defer cancel()
			d := net.Dialer{Resolver: n.Resolver, Timeout: n.timeout()}
			conn, err := d.DialContext(ctx, family, endpoint)
			p := Port{Family: family, Endpoint: endpoint, Status: "unknown", Detail: "failed to connect; cannot distinguish filtering, routing or destination failure"}
			if err == nil {
				p.Status = "reachable"
				p.Detail = "TCP handshake only; does not prove SMTP delivery"
				conn.Close()
			} else {
				p.Detail += " (" + safeError(err) + ")"
			}
			out[i] = p
		}()
	}
	wg.Wait()
	return out
}
