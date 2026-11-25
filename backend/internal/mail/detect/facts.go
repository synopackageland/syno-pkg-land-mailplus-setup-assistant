package detect

import (
	"strconv"
	"strings"

	"SynoMailPlusSetupAssistant/internal/core"
)

// Facts are what the setup wizard shows. Every value is a catalog key
// (mail.setup.value.* or mail.setup.cause.*) with parameters, never a Go
// value: the browser renders it in the administrator's language.
func Facts(s State) []core.Fact {
	out := []core.Fact{}
	add := func(label, value string, params map[string]string) {
		out = append(out, core.Fact{LabelKey: "mail.setup.fact." + label, Value: value, Params: params, Status: core.SeverityInfo})
	}
	unknown := func(label, detail string) {
		key, params := CauseKey(detail)
		add(label, key, params)
	}
	v := func(key string) string { return "mail.setup.value." + key }

	switch p := s.Package; {
	case !p.IsKnown():
		unknown("package", p.Detail)
	case !p.Value.Installed:
		add("package", v("package.missing"), nil)
	case p.Value.Broken:
		add("package", v("package.broken"), map[string]string{"version": p.Value.Version})
	case !p.Value.Running:
		add("package", v("package.stopped"), map[string]string{"version": p.Value.Version})
	default:
		add("package", v("package.running"), map[string]string{"version": p.Value.Version})
	}
	if smtp := s.SMTP; !smtp.IsKnown() {
		unknown("smtp", smtp.Detail)
	} else if smtp.Value.Enabled {
		add("smtp", v("smtp.on"), map[string]string{"port": strconv.Itoa(smtp.Value.Port)})
	} else {
		add("smtp", v("smtp.off"), nil)
	}
	if d := s.Domains; !d.IsKnown() {
		unknown("domains", d.Detail)
	} else if len(d.Value) == 0 {
		add("domains", v("none"), nil)
	} else {
		names := []string{}
		for _, dm := range d.Value {
			names = append(names, dm.Name)
		}
		add("domains", v("domains"), map[string]string{"count": strconv.Itoa(len(names)), "names": strings.Join(names, ", ")})
	}
	if a, ok := s.Accounts[s.Domain]; !ok || !a.IsKnown() {
		detail := notRead(s)
		if ok {
			detail = a.Detail
		}
		unknown("accounts", detail)
	} else {
		active := 0
		for _, acc := range a.Value {
			if acc.Active {
				active++
			}
		}
		add("accounts", v("accounts"), map[string]string{"active": strconv.Itoa(active), "total": strconv.Itoa(len(a.Value))})
	}
	if l := s.License; !l.IsKnown() {
		unknown("license", l.Detail)
	} else {
		add("license", v("license"), map[string]string{"active": strconv.Itoa(l.Value.Active), "licensed": strconv.Itoa(l.Value.Licensed)})
		if LicenseShort(l) {
			out[len(out)-1].Value = v("license.short")
			out[len(out)-1].Status = core.SeverityWarning
		}
	}
	if d := s.Delivery; !d.IsKnown() {
		unknown("delivery", d.Detail)
	} else {
		hosts := []string{}
		for _, h := range d.Value.Default {
			hosts = append(hosts, h.Server+":"+strconv.Itoa(h.Port))
		}
		params := map[string]string{"hosts": strings.Join(hosts, ", ")}
		switch {
		case d.Value.Type == "list" && len(hosts) > 0:
			add("delivery", v("delivery.relay"), params)
		case d.Value.Fallback && len(hosts) > 0:
			add("delivery", v("delivery.directFallback"), params)
		default:
			add("delivery", v("delivery.direct"), nil)
		}
	}
	if sign, ok := s.Signing[s.Domain]; !ok || !sign.IsKnown() {
		detail := notRead(s)
		if ok {
			detail = sign.Detail
		}
		unknown("dkim", detail)
	} else if sign.Value.Enabled {
		add("dkim", v("on"), nil)
	} else {
		add("dkim", v("off"), nil)
	}
	if q := s.QueueSize; !q.IsKnown() {
		unknown("queue", q.Detail)
	} else {
		add("queue", v("queue"), map[string]string{"count": strconv.Itoa(q.Value)})
	}
	n := s.Network
	if !n.EgressIPv4.IsKnown() {
		unknown("ip", n.EgressIPv4.Detail)
	} else {
		add("ip", v("text"), map[string]string{"text": n.EgressIPv4.Value})
	}
	if !n.Addressing.IsKnown() {
		unknown("addressing", n.Addressing.Detail)
	} else {
		add("addressing", v("addressing."+string(n.Addressing.Value)), nil)
	}
	if !n.PTR.IsKnown() {
		unknown("ptr", n.PTR.Detail)
	} else if len(n.PTR.Value) == 0 {
		add("ptr", v("ptr.none"), nil)
	} else {
		add("ptr", v("text"), map[string]string{"text": strings.Join(n.PTR.Value, ", ")})
	}
	switch {
	case !n.FCrDNS.IsKnown():
		unknown("fcrdns", n.FCrDNS.Detail)
	case n.FCrDNS.Value:
		add("fcrdns", v("fcrdns.pass"), nil)
	default:
		add("fcrdns", v("fcrdns.fail"), nil)
	}
	reach := func(label string, o Observation[bool]) {
		switch {
		case !o.IsKnown():
			unknown(label, o.Detail)
		case o.Value:
			add(label, v("reachable"), nil)
		default:
			add(label, v("notReachable"), nil)
		}
	}
	reach("outbound", n.Outbound25)
	reach("inbound", n.Inbound25)
	listed, checked, unsure := []string{}, 0, 0
	for _, bl := range n.DNSBL {
		switch bl.Status {
		case "listed":
			listed = append(listed, bl.Provider)
			checked++
		case "not_listed":
			checked++
		default:
			unsure++
		}
	}
	switch {
	case len(listed) > 0:
		add("dnsbl", v("dnsbl.listed"), map[string]string{"names": strings.Join(listed, ", ")})
	case checked > 0 && unsure == 0:
		add("dnsbl", v("dnsbl.clean"), map[string]string{"count": strconv.Itoa(checked)})
	case !n.EgressIPv4.IsKnown():
		unknown("dnsbl", CauseIPUnknown)
	default:
		unknown("dnsbl", core.CauseUnavailable)
	}
	if t := n.Tunnel; !t.IsKnown() {
		unknown("tunnel", t.Detail)
	} else if t.Value.Ready {
		add("tunnel", v("tunnel.ready"), nil)
	} else {
		add("tunnel", v("tunnel.notReady"), nil)
	}
	// DNS: does the domain exist, who hosts it, and the mail records.
	if c := DomainCause(s); c != "" {
		unknown("domainDNS", c)
	} else {
		add("domainDNS", v("domainDNS.found"), nil)
	}
	switch c := s.DNS.Cloudflare; {
	case c.IsKnown() && c.Value && s.DNS.CloudflareSource == SourceZone:
		add("dns", v("cloudflare.yesZone"), map[string]string{"zone": s.DNS.CloudflareZone})
	case c.IsKnown() && c.Value:
		add("dns", v("cloudflare.yes"), nil)
	case c.IsKnown():
		add("dns", v("cloudflare.no"), nil)
	default:
		unknown("dns", firstCause(DomainCause(s), c.Detail))
	}
	for _, r := range []struct {
		label string
		check Check
	}{{"mx", s.DNS.MX}, {"spf", s.DNS.SPF}, {"dmarc", s.DNS.DMARC}} {
		switch {
		case DomainCause(s) == CauseNoDomain:
			// A name DNS does not know has no records: say why, as the
			// domain fact does, instead of a record status.
			unknown(r.label, CauseNoDomain)
		case r.check.Status == "present" || r.check.Status == "missing" || r.check.Status == "fail":
			add(r.label, v("record."+r.check.Status), nil)
		default:
			unknown(r.label, firstCause(DomainCause(s), CauseDNSUnknown))
		}
	}
	return out
}

// DomainCause is CauseNoDomain when DNS says the domain does not exist (every
// lookup of it not found), CauseDNSUnknown when DNS gave no usable answer,
// else "" (some lookup returned records). See zone.go.
func DomainCause(s State) string {
	switch s.DNS.Exists.Status {
	case "present":
		return ""
	case "missing":
		return CauseNoDomain
	}
	return CauseDNSUnknown
}

// notRead is why the domain's accounts or DKIM were not read at all: the
// domain is not in MailPlus Server's (known) domain list, else unavailable.
func notRead(s State) string {
	if !s.Domains.IsKnown() {
		return firstCause(s.Domains.Detail)
	}
	for _, dm := range s.Domains.Value {
		if dm.Name == s.Domain {
			return core.CauseUnavailable
		}
	}
	return CauseNotInMailPlus
}

func firstCause(causes ...string) string {
	for _, c := range causes {
		if c != "" {
			return c
		}
	}
	return core.CauseUnavailable
}
