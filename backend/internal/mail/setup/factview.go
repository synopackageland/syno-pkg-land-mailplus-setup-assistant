package setup

import (
	"strings"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

// Fact groups, in the order the detection results show them.
const (
	GroupMailPlus   = "mailplus"
	GroupNetwork    = "network"
	GroupDNS        = "dns"
	GroupCloudflare = "cloudflare"
)

// Fact states: what a reader must look at first. Only problem and unknown
// need attention; ok and notChecked fold away (still shown on request).
const (
	FactOK         = "ok"
	FactProblem    = "problem"
	FactUnknown    = "unknown"
	FactNotChecked = "notChecked"
	// FactPlanned: missing now, but the decided plan creates it (the same
	// needs the preview is built from); no action is needed.
	FactPlanned = "planned"
	// FactOptional: missing, not needed by the chosen route, and not created
	// by the plan: a recommendation, never a problem.
	FactOptional = "optional"
)

// Notes (catalog keys) for planned and optional facts.
const (
	noteRouting = "mail.setup.planned.routing"
	noteSending = "mail.setup.planned.sending"
	noteDNS     = "mail.setup.planned.dns"
	noteDMARC   = "mail.setup.optional.dmarc"
	noteSPF     = "mail.setup.optional.spfRelay"
	// noteMailPlusDomain: the plan creates the MailPlus Server mail domain
	// (need mailplus.domain).
	noteMailPlusDomain = "mail.setup.planned.mailplusDomain"
)

// plannedFacts names the facts the decision's plan creates, with the note
// that says who creates them. It reads only Decision.Needs: the list the
// preview's changes are built from (the Cloudflare adapter's Plan and
// ManualRecords), so the facts step and the preview agree. A stop or a
// MailPlus hand-off has no DNS needs and so plans nothing. Records the
// administrator must add by hand (manualDNS) are not planned: the decision
// stops there.
//
//   - cloudflare.inbound: Email Routing creates the name's MX and SPF.
//   - cloudflare.sending: Email Sending creates its own records under the
//     name (cf-bounce MX/SPF and DKIM), which the relayed mail is checked
//     against; the name's own SPF is not used by that path.
//   - dns.spf, dns.dmarc, dns.mx, dns.a: this App writes the record.
func plannedFacts(d Decision) map[string]string {
	out := map[string]string{}
	if d.Gate == Stop || d.Gate == Handoff || d.Gate == Minimal {
		return out
	}
	set := func(note string, labels ...string) {
		for _, l := range labels {
			if _, taken := out[l]; !taken {
				out[l] = note
			}
		}
	}
	// Routing first: its SPF is the name's own record.
	for _, n := range d.Needs {
		if n == "cloudflare.inbound" {
			set(noteRouting, "mx", "spf", "domainDNS")
		}
	}
	for _, n := range d.Needs {
		switch n {
		case "cloudflare.sending":
			set(noteSending, "domainDNS")
		case "dns.spf":
			set(noteDNS, "spf", "domainDNS")
		case "dns.dmarc":
			set(noteDNS, "dmarc", "domainDNS")
		case "dns.mx", "dns.a":
			set(noteDNS, "mx", "domainDNS")
		}
	}
	return out
}

// absent reports a fact that says the record (or the whole name) is not in
// DNS yet: what a plan can create. An existing record (present, or invalid)
// never is.
func absent(f core.Fact) bool {
	noDomain, _ := detect.CauseKey(detect.CauseNoDomain)
	return f.Value == noDomain || f.Value == "mail.setup.value.record.missing"
}

// factGroups places each detection fact (mail.setup.fact.<label>) in a group.
var factGroups = map[string]string{
	"package": GroupMailPlus, "smtp": GroupMailPlus, "domains": GroupMailPlus, "accounts": GroupMailPlus,
	"license": GroupMailPlus, "delivery": GroupMailPlus, "dkim": GroupMailPlus, "queue": GroupMailPlus,
	"ip": GroupNetwork, "addressing": GroupNetwork, "ptr": GroupNetwork, "fcrdns": GroupNetwork,
	"outbound": GroupNetwork, "inbound": GroupNetwork, "dnsbl": GroupNetwork,
	"domainDNS": GroupDNS, "mx": GroupDNS, "spf": GroupDNS, "dmarc": GroupDNS,
	"dns": GroupCloudflare, "tunnel": GroupCloudflare,
}

// problemValues are the values (mail.setup.value.<key>) that are a definite
// problem wherever they show. Other values are fine; record.missing is fine
// too (the plan adds the record).
var problemValues = map[string]bool{
	"package.missing": true, "package.broken": true, "package.stopped": true, "smtp.off": true,
	"license.short": true, "addressing.changing": true, "ptr.none": true, "fcrdns.fail": true,
	"notReachable": true, "dnsbl.listed": true, "tunnel.notReady": true, "record.fail": true,
}

// notUnknownCauses are cause values that are certain negatives, not missing
// evidence: a problem, never "unknown".
var notUnknownCauses = map[string]bool{"noDomain": true, "notInMailPlus": true}

// annotateFacts adds the group, the state and whether the chosen route and
// intent need each fact. It never drops a fact: an unrelated fact is still
// returned (the page folds it away). Deterministic: it reads only the values
// detect.Facts wrote and the state they came from.
//
// Facts the decided plan creates (plannedFacts) show as planned with a note,
// never as a problem; on the Cloudflare sending path a missing DMARC is
// optional (Email Sending does not add one, and a name without its own DMARC
// follows its parent domain's policy, which a weaker default would override).
//
// A plan that creates the MailPlus Server mail domain shows the
// domain list as planned; the new domain's accounts and DKIM signing, which
// MailPlus Server cannot report before the domain exists, are unrelated to
// this run (sending needs no mailbox and the Cloudflare relay signs itself;
// receiving waits for a member). While receiving waits (ReceivePending), the
// receiving facts are unrelated too: this run does not set receiving up.
func annotateFacts(facts []core.Fact, s detect.State, i Intent, a Answers) []core.Fact {
	d := Decide(s, i, a)
	planned := plannedFacts(d)
	newDomain := !d.Blocked() && d.Gate != Minimal && hasNeed(d, "mailplus.domain")
	if newDomain {
		planned["domains"] = noteMailPlusDomain
	}
	direct, cloudflare := a.Route == RouteDirect, a.Route == RouteCloudflare
	chosen := direct || cloudflare
	needed := func(label string) bool {
		if d.ReceivePending {
			switch label {
			case "inbound", "tunnel", "mx":
				return false
			}
		}
		if !chosen {
			return true
		}
		switch label {
		case "ip", "addressing":
			return direct
		case "ptr", "fcrdns", "dnsbl", "outbound":
			return direct && i.Sends()
		case "inbound":
			return direct && i.Receives()
		case "tunnel":
			return cloudflare && i.Receives()
		case "delivery", "dkim", "spf", "dmarc":
			return i.Sends()
		case "mx":
			return i.Receives()
		}
		return true
	}
	out := make([]core.Fact, 0, len(facts))
	for _, f := range facts {
		label := strings.TrimPrefix(f.LabelKey, "mail.setup.fact.")
		f.Group = factGroups[label]
		f.State = factState(label, f, s, i, a)
		f.Unrelated = !needed(label)
		switch {
		case newDomain && label == "domains":
			f.State, f.NoteKey = FactPlanned, planned[label]
		case newDomain && (label == "accounts" || label == "dkim"):
			f.State, f.NoteKey, f.Unrelated = FactPlanned, noteMailPlusDomain, true
		}
		if (f.State == FactProblem || f.State == FactOK) && absent(f) {
			if note, ok := planned[label]; ok {
				f.State, f.NoteKey = FactPlanned, note
			} else if label == "dmarc" && (d.Send == RelaySend || (d.Send == DirectSend && s.DNS.ParentDMARC.Status == "present")) {
				f.State, f.NoteKey = FactOptional, noteDMARC
			} else if label == "spf" && d.Send == RelaySend {
				f.State, f.NoteKey = FactOptional, noteSPF
			}
		}
		switch f.State {
		case FactOK:
			f.Status = core.SeverityOK
		case FactProblem:
			f.Status = core.SeverityWarning
		case FactPlanned, FactOptional:
			f.Status = core.SeverityInfo
		}
		out = append(out, f)
	}
	return out
}

func factState(label string, f core.Fact, s detect.State, i Intent, a Answers) string {
	if cause, ok := strings.CutPrefix(f.Value, "mail.setup.cause."); ok {
		switch {
		case cause == "notChecked":
			return FactNotChecked
		case notUnknownCauses[cause]:
			return FactProblem
		}
		return FactUnknown
	}
	value := strings.TrimPrefix(f.Value, "mail.setup.value.")
	switch {
	case problemValues[value] || f.Status == core.SeverityWarning:
		return FactProblem
	case label == "domains" && value == "none":
		return FactProblem
	case label == "accounts" && i.Receives():
		// Receiving needs an enabled mailbox on the domain.
		if ac := s.Accounts[s.Domain]; ac.IsKnown() && !HasMailbox(ac.Value) {
			return FactProblem
		}
	case label == "dns" && value == "cloudflare.no" && a.Route != RouteDirect:
		// The Cloudflare route needs the domain's DNS on Cloudflare.
		return FactProblem
	}
	return FactOK
}
