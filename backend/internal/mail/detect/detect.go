package detect

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

func ValidDomain(s string) bool { return validDomain(s) }
func NormalizeDomain(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}
func validDomain(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func emptyState(domain string) State {
	return State{At: time.Now().UTC(), Domain: domain, Package: Unavailable[Package](), SMTP: Unavailable[SMTP](), Domains: Unavailable[[]Domain](), Accounts: map[string]Observation[[]Account]{}, License: Unavailable[License](), Delivery: Unavailable[Delivery](), Signing: map[string]Observation[Signing]{}, QueueSize: Unavailable[int](), SendReady: Unavailable[bool](), ReceiveReady: Unavailable[bool](),
		Network: Network{EgressIPv4: Unavailable[string](), Addressing: Unavailable[Addressing](), PTR: Unavailable[[]string](), FCrDNS: Unavailable[bool](), Outbound25: Unavailable[bool](), Inbound25: Unavailable[bool](), DNSBL: []DNSBL{{Provider: "unconfigured", Status: "unknown"}}, Tunnel: Unavailable[Tunnel]()},
		DNS:     DNS{Cloudflare: Unavailable[bool](), Exists: Check{Status: "unknown"}, NS: Check{Status: "unknown"}, MX: Check{Status: "unknown"}, SPF: Check{Status: "unknown"}, DMARC: Check{Status: "unknown"}, SendRecords: Unavailable[bool](), ReceiveRecords: Unavailable[bool]()}}
}

// Detect reads MailPlus Server through DSM while the network probes run; the
// two touch disjoint parts of State. DNS record checks follow, since they use
// the domain's DKIM selector.
func (d *Detector) Detect(ctx context.Context, env core.Env, req Request) State {
	domain := NormalizeDomain(req.Domain)
	s := emptyState(domain)
	if !ValidDomain(domain) {
		return s
	}
	t := d.Timeout
	if t <= 0 || t > 30*time.Second {
		t = 5 * time.Second
	}
	if env.Now != nil {
		s.At = env.Now().UTC()
	}
	var dsmDone sync.WaitGroup
	if env.DSM != nil {
		dsmDone.Add(1)
		go func() { defer dsmDone.Done(); d.mailplus(ctx, env.DSM, &s, []string{domain}, true) }()
	}
	// Waits on every return path: no goroutine outlives Detect.
	defer dsmDone.Wait()
	if d.Extensions == nil {
		// No source for these in this version: unknown by design, and said so.
		s.Network.Tunnel = unknown[Tunnel](CauseNotChecked)
		s.Network.Addressing, s.Network.Inbound25 = unknown[Addressing](CauseNotChecked), unknown[bool](CauseNotChecked)
		s.SendReady, s.ReceiveReady = unknown[bool](CauseNotChecked), unknown[bool](CauseNotChecked)
		s.DNS.SendRecords, s.DNS.ReceiveRecords = unknown[bool](CauseNotChecked), unknown[bool](CauseNotChecked)
	} else if !req.Receive {
		s.Network.Inbound25 = unknown[bool](CauseNotChecked) // only probed for receiving
	}
	if d.Extensions != nil {
		s.Network.Tunnel = bounded(ctx, t, d.Extensions.Tunnel)
		ready := bounded(ctx, t, func(c context.Context) ([2]bool, error) {
			a, b, e := d.Extensions.Readiness(c, domain)
			return [2]bool{a, b}, e
		})
		if ready.IsKnown() {
			s.SendReady = Fact(ready.Value[0])
			s.ReceiveReady = Fact(ready.Value[1])
		}
		ready = bounded(ctx, t, func(c context.Context) ([2]bool, error) {
			a, b, e := d.Extensions.DNSReadiness(c, domain)
			return [2]bool{a, b}, e
		})
		if ready.IsKnown() {
			s.DNS.SendRecords = Fact(ready.Value[0])
			s.DNS.ReceiveRecords = Fact(ready.Value[1])
		}
	}
	if d.Resolver != nil {
		s.DNS.Exists, s.DNS.Zone, s.DNS.NS = d.domainDNS(ctx, domain, t)
		s.DNS.Cloudflare = cloudflareNS(s.DNS.NS)
		if s.DNS.Cloudflare.IsKnown() {
			s.DNS.CloudflareSource = SourceDNS
		}
	}
	if d.HTTP != nil {
		e := bounded(ctx, 2*t, func(c context.Context) (Egress, error) { return egress(d.checker(c), "tcp4"), nil })
		if e.IsKnown() && e.Value.Check.Status == "pass" && len(e.Value.Check.Values) == 1 {
			s.Network.EgressIPv4 = Fact(e.Value.Check.Values[0])
		}
	}
	if d.Dial != nil {
		ports := bounded(ctx, 2*t, func(c context.Context) ([]Port, error) { return ports(d.checker(c), "tcp4"), nil })
		if ports.IsKnown() {
			for _, p := range ports.Value {
				if p.Status == "reachable" {
					s.Network.Outbound25 = Fact(true)
				}
			}
		}
	}
	if !s.Network.EgressIPv4.IsKnown() {
		// Without the public IP its reverse DNS and forward match were not
		// checked: say so instead of a generic unknown.
		s.Network.PTR, s.Network.FCrDNS = unknown[[]string](CauseIPUnknown), unknown[bool](CauseIPUnknown)
	}
	if s.Network.EgressIPv4.IsKnown() {
		ip := s.Network.EgressIPv4.Value
		if d.Extensions != nil {
			s.Network.Addressing = bounded(ctx, t, func(c context.Context) (Addressing, error) { return d.Extensions.Addressing(c, ip) })
			if req.Receive {
				s.Network.Inbound25 = bounded(ctx, t, func(c context.Context) (bool, error) { return d.Extensions.Inbound25(c, ip) })
			}
		}
		if d.Resolver != nil {
			p := bounded(ctx, 16*t, func(c context.Context) (IPReport, error) {
				a, e := netip.ParseAddr(ip)
				if e != nil {
					return IPReport{}, errors.New("invalid_ip")
				}
				return d.checker(c).ipReport(a, "observed execution-host egress"), nil
			})
			if p.IsKnown() {
				if p.Value.PTR.Status == "present" || p.Value.PTR.Status == "missing" {
					s.Network.PTR = Fact(p.Value.PTR.Values)
				}
				switch p.Value.FCrDNS {
				case "pass":
					s.Network.FCrDNS = Fact(true)
				case "fail":
					s.Network.FCrDNS = Fact(false)
				}
				s.Network.DNSBL = nil
				for _, bl := range p.Value.DNSBL {
					s.Network.DNSBL = append(s.Network.DNSBL, DNSBL{Provider: bl.Provider, Status: bl.Status, Codes: bl.Codes})
				}
			}
		}
	}
	// DNS records use the DKIM selector MailPlus reports, so they follow the
	// DSM pass.
	dsmDone.Wait()
	if d.Resolver != nil {
		selectors := append([]string{}, req.Selectors...)
		if sign, ok := s.Signing[domain]; ok && sign.IsKnown() && sign.Value.Selector != "" {
			selectors = append(selectors, sign.Value.Selector)
		}
		if len(selectors) > 16 {
			selectors = selectors[:16]
		}
		safe := []string{}
		seen := map[string]bool{}
		for _, v := range selectors {
			if len(v) <= 120 && validDomain(v+".invalid") && !seen[v] {
				safe = append(safe, v)
				seen[v] = true
			}
		}
		// Each E4 DNS query has its own deadline; this envelope also bounds expansion.
		dns := bounded(ctx, 12*t, func(c context.Context) (HealthDomain, error) { return d.checker(c).domain(domain, safe), nil })
		if dns.IsKnown() {
			s.DNS.MX = dns.Value.MX
			s.DNS.SPF = dns.Value.SPF.Records
			// "fail" is for a record that exists but is invalid; no record
			// stays "missing" (the walk also fails a name without one).
			if dns.Value.SPF.Status == "fail" && s.DNS.SPF.Status == "present" {
				s.DNS.SPF.Status = "fail"
			} else if dns.Value.SPF.DNSUnknown && s.DNS.SPF.Status == "present" {
				// A record whose include/redirect walk hit a DNS failure is
				// not known to be valid: unknown, never "present".
				s.DNS.SPF.Status = "unknown"
			}
			s.DNS.DKIM = dns.Value.DKIM
			s.DNS.DMARC = dns.Value.DMARC
			if s.DNS.DMARC.Status == "missing" {
				s.DNS.ParentDMARC = bounded(ctx, 4*t, func(c context.Context) (Check, error) {
					return d.checker(c).parentDMARC(domain, s.DNS.Zone), nil
				}).Value
				if s.DNS.ParentDMARC.Status == "" {
					s.DNS.ParentDMARC = Check{Status: "unknown"}
				}
			}
		}
	}
	return s
}
