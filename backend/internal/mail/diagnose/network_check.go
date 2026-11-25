package diagnose

import (
	"context"
	"net/netip"
	"strings"

	"SynoMailPlusSetupAssistant/internal/core"
)

func (d *Diagnostics) checkNetwork(ctx context.Context, c *checker, s State) []core.Finding {
	if d.deps.Network == nil {
		return []core.Finding{finding(Network, "unavailable", "", core.SeverityInfo, "", nil)}
	}
	out := []core.Finding{}
	// A relay's public IP, PTR and DNSBL status are not the NAS's IP status.
	// Keep direct-send observations informational when Home Keeper is in use.
	directSeverity := core.SeverityWarning
	viaRelay := isTrue(s.Relay.Enabled) || s.Transport.Send == PathProvider || s.Transport.Send == PathHomeKeeper
	if viaRelay {
		directSeverity = core.SeverityInfo
	}
	// relay=1 tells the summary that a relay sends the mail, so this NAS's
	// own address (PTR, block lists, port 25) does not decide delivery.
	mark := func(f core.Finding) core.Finding {
		if viaRelay {
			f.Params["relay"] = "1"
		}
		return f
	}
	for _, family := range []string{"tcp4", "tcp6"} {
		if ctx.Err() != nil {
			break
		}
		egress := d.deps.Network.Egress(ctx, family)
		if egress.ProbeResult.Status != "pass" || len(egress.ProbeResult.Values) != 1 {
			out = append(out, finding(Network, "egress", family, core.SeverityInfo, "", egress))
			// Do not PTR/DNSBL-check disputed IPs, or infer an absent address
			// family. IPv4 TCP25 can still be probed independently below.
		} else if ip, err := netip.ParseAddr(egress.ProbeResult.Values[0]); err == nil &&
			ip.IsGlobalUnicast() && !ip.IsPrivate() && ip.Is4() == (family == "tcp4") {
			if c.r == nil {
				out = append(out, finding(Network, "unavailable", family+".dns", core.SeverityInfo, "", nil))
			} else {
				report := c.ipReport(ip, "two-source HTTP egress (not an SMTP route guarantee)")
				if report.FCrDNS != "pass" {
					severity := directSeverity
					if report.FCrDNS == "unknown" {
						severity = core.SeverityInfo
					}
					f := finding(Network, "ptr", ip.String(), severity, "send",
						struct {
							PTR     ProbeResult `json:"ptr"`
							Reverse []Reverse   `json:"reverse"`
							FCrDNS  string      `json:"fcrdns"`
						}{report.PTR, report.Reverse, report.FCrDNS})
					f.Params["target"] = ip.String()
					out = append(out, mark(f))
				}
				if len(report.DNSBL) == 0 {
					out = append(out, finding(Network, "dnsbl_unknown", ip.String(), core.SeverityInfo, "", nil))
				}
				for _, bl := range report.DNSBL {
					if bl.Status == "not_listed" {
						continue
					}
					cause, severity, intent := "dnsbl_unknown", core.SeverityInfo, ""
					if bl.Status == "listed" {
						cause, severity, intent = "dnsbl", directSeverity, "send"
					}
					f := finding(Network, cause, ip.String()+"."+strings.ReplaceAll(bl.Provider, " ", "_"),
						severity, intent, bl)
					f.Params["target"] = ip.String()
					out = append(out, mark(f))
				}
			}
		} else {
			out = append(out, finding(Network, "egress", family, core.SeverityInfo, "", nil))
		}
		// Try both families even when HTTP egress is unavailable: mail routing
		// can differ from HTTP. Failed handshakes cannot prove ISP filtering.
		ports := d.deps.Network.Outbound(ctx, family)
		reachable := false
		for _, port := range ports {
			reachable = reachable || port.Status == "reachable"
		}
		if !reachable {
			out = append(out, mark(finding(Network, "outbound", family, core.SeverityInfo, "send", ports)))
		}
	}
	return out
}
