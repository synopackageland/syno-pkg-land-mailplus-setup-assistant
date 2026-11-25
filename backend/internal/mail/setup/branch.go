// Package setup implements the mail.setup decision tree and reversible plans.
package setup

import (
	"strings"

	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

type Intent string

const (
	Send     Intent = "send"
	Receive  Intent = "receive"
	Both     Intent = "both"
	Diagnose Intent = "diagnose"
	Check    Intent = "check"
)

func (i Intent) Sends() bool    { return i == Send || i == Both }
func (i Intent) Receives() bool { return i == Receive || i == Both }
func (i Intent) Valid() bool {
	return i == Send || i == Receive || i == Both || i == Diagnose || i == Check
}

type Branch string

const (
	DirectSend     Branch = "direct-send"
	RelaySend      Branch = "cloudflare-relay"
	DirectReceive  Branch = "direct-receive"
	RoutingReceive Branch = "cloudflare-routing"
	Already        Branch = "already-correct"
	Minimal        Branch = "minimal-mailplus"
	Stop           Branch = "stop"
	Handoff        Branch = "diagnose"
)

type Decision struct {
	Send    Branch `json:"send,omitempty"`
	Receive Branch `json:"receive,omitempty"`
	Gate    Branch `json:"gate,omitempty"`
	Reason  string `json:"reason,omitempty"` // mail.setup.<reason> is localized
	// Cause is the fixed cause (core.Cause) of the DSM observation that made
	// the reason "unknown"; empty when the missing evidence is not a DSM read.
	Cause string `json:"cause,omitempty"`
	// Missing names the facts (and their causes) that made the reason
	// "unknown" when they are not DSM reads: network, DNS, Cloudflare.
	Missing []Missing `json:"missing,omitempty"`
	Needs   []string  `json:"needs"` // semantic requirements, never executable writes
	// SendWhy and ReceiveWhy say why each direction took its path: reason
	// codes, each localized as mail.setup.why.<code>. Empty when the
	// direction was not decided (already correct, not asked, stopped before).
	SendWhy    []string `json:"sendWhy,omitempty"`
	ReceiveWhy []string `json:"receiveWhy,omitempty"`
	// ReceivePending is set when the intent includes receiving but the
	// domain has no enabled mailbox in MailPlus Server: receiving (and its
	// verification) waits for one, while sending, which needs no mailbox, is
	// decided and set up on its own. Only for intent both; receive alone
	// stops at configureMailPlus.
	ReceivePending bool `json:"receivePending,omitempty"`
}

func (d Decision) Cloud() bool   { return d.Send == RelaySend || d.Receive == RoutingReceive }
func (d Decision) Blocked() bool { return d.Gate == Stop || d.Gate == Handoff }

// Decide is pure. Where the domain came from (Answers.Source) decides
// nothing here. The direct paths need the administrator's own-IP route
// (Answers.Route, confirmed on the route step) and no check that says
// otherwise (sendPath, receivePath); anything else takes the Cloudflare path,
// and the decision names why (SendWhy, ReceiveWhy).
//
// MailPlus Server's side comes first and does not depend on the route: a
// missing domain stops every intent (configureMailPlus); a domain without an
// enabled mailbox stops receiving only, because receive verification needs a
// mailbox and sending does not. For intent both, sending goes on alone and
// ReceivePending says receiving waits.
func Decide(s detect.State, i Intent, a Answers) Decision {
	d := Decision{Needs: []string{}}
	stop := func(reason string) Decision { d.Gate = Stop; d.Reason = reason; d.Needs = nil; return d }
	unread := func(cause string) Decision { d = stop("unknown"); d.Cause = cause; return d }
	// lacking stops at "unknown" naming the facts it lacked. An empty list
	// keeps the neutral generic text (mail.setup.unknownBody).
	lacking := func(m ...Missing) Decision {
		d = stop("unknown")
		d.Missing = append(m, domainMissing(s)...)
		return d
	}
	if !i.Valid() {
		return stop("invalidIntent")
	}
	if i == Diagnose || i == Check {
		d.Gate = Handoff
		return d
	}
	if !s.Package.IsKnown() {
		return unread(s.Package.Detail)
	}
	if !s.Package.Value.Installed {
		return stop("notInstalled")
	}
	if s.Package.Value.Broken {
		return stop("broken")
	}
	if !s.Package.Value.Running {
		return stop("stopped")
	}
	// MailPlus Server's own counts say more users are active than licensed:
	// fixed in MailPlus Server (add licences or deactivate users) before
	// setup changes anything. An unknown licence decides nothing.
	if detect.LicenseShort(s.License) {
		return stop("licenseShort")
	}
	if !s.SMTP.IsKnown() {
		return unread(s.SMTP.Detail)
	}
	if !s.Domains.IsKnown() {
		return unread(s.Domains.Detail)
	}
	exists := false
	for _, dm := range s.Domains.Value {
		if dm.Name == s.Domain {
			exists = true
		}
	}
	// A MailPlus Server that finished its first-run setup has a domain; then
	// a missing one is a plan step (the App creates it). Its first
	// run, and receiving alone (a new domain has no member), stay with
	// MailPlus Server's own wizard.
	creatable := !exists && len(s.Domains.Value) > 0 && i != Receive
	if !exists && !creatable {
		d.Gate = Minimal
		d.Reason = "configureMailPlus"
		d.Needs = append(d.Needs, "mailplus.domain")
	}
	if !s.SMTP.Value.Enabled {
		d.Gate = Minimal
		d.Reason = "configureMailPlus"
		d.Needs = append(d.Needs, "mailplus.smtp")
	}
	if exists {
		ac := s.Accounts[s.Domain]
		if !ac.IsKnown() {
			return unread(ac.Detail)
		}
		if !HasMailbox(ac.Value) {
			switch i {
			case Receive:
				d.Gate = Minimal
				d.Reason = "configureMailPlus"
				d.Needs = append(d.Needs, "mailplus.members")
			case Both:
				// Sending needs no mailbox: decide it alone, receiving waits.
				d.ReceivePending = true
				i = Send
			}
		}
	} else if !creatable {
		d.Needs = append(d.Needs, "mailplus.members")
	}
	// Minimal provisioning is explicit and re-detects before any DNS/relay plan.
	if d.Gate == Minimal {
		return d
	}
	if creatable {
		d.Needs = append(d.Needs, "mailplus.domain")
		if i == Both {
			// A new domain has no member: sending goes on, receiving waits.
			d.ReceivePending = true
			i = Send
		}
	}
	if i.Sends() {
		if s.SendReady.IsKnown() && s.SendReady.Value {
			d.Send = Already
		} else {
			why, direct := sendPath(s.Network, a)
			d.SendWhy = why
			if !direct {
				d.Send = RelaySend
				d.Needs = append(d.Needs, "cloudflare.sending", "relay.configure", "mailplus.delivery")
				sign := s.Signing[s.Domain]
				if creatable {
					// A new domain signs nothing (verified on 4.1.1-31785).
					sign = detect.Fact(detect.Signing{})
				}
				if !sign.IsKnown() {
					return unread(sign.Detail)
				}
				if sign.Value.Enabled {
					d.Needs = append(d.Needs, "mailplus.dkim.disable")
				}
				// Default Delivery is global. Do not take over another smarthost.
				if !s.Delivery.IsKnown() {
					return unread(s.Delivery.Detail)
				}
				if s.Delivery.Value.Type != "none" || s.Delivery.Value.Fallback {
					return stop("existingRelay")
				}
			} else {
				d.Send = DirectSend
				for _, r := range []struct {
					name string
					v    detect.Check
				}{{"dns.spf", s.DNS.SPF}, {"dns.dmarc", s.DNS.DMARC}} {
					if r.v.Status == "unknown" || r.v.Status == "" {
						return lacking(Missing{Fact: strings.TrimPrefix(r.name, "dns."), Cause: detect.CauseDNSUnknown})
					}
					if r.v.Status == "missing" && r.name == "dns.dmarc" {
						// A parent domain's policy applies to a name without
						// its own: a p=none record would weaken it.
						switch s.DNS.ParentDMARC.Status {
						case "present":
							continue
						case "missing":
						default:
							return lacking(Missing{Fact: "dmarc", Cause: detect.CauseDNSUnknown})
						}
					}
					if r.v.Status == "missing" {
						d.Needs = append(d.Needs, r.name)
					} else if r.v.Status != "present" {
						return stop("dnsConflict")
					}
				}
				sign := s.Signing[s.Domain]
				if !sign.IsKnown() || !sign.Value.Enabled || sign.Value.PublicKey == "" || sign.Value.Selector == "" {
					return stop("dkimRequired")
				}
				key := false
				for _, k := range s.DNS.DKIM {
					if k.Selector == sign.Value.Selector {
						if k.Status == "unknown" {
							return lacking(Missing{Fact: "dkimRecord", Cause: detect.CauseDNSUnknown})
						}
						if k.Status == "present" {
							key = true
						} else if k.Status != "missing" {
							return stop("dnsConflict")
						}
					}
				}
				if !key {
					d.Needs = append(d.Needs, "dns.dkim")
				}
				dmarc := s.DNS.DMARC.Status == "present" || s.DNS.ParentDMARC.Status == "present"
				if s.DNS.SendRecords.IsKnown() && !s.DNS.SendRecords.Value && s.DNS.SPF.Status == "present" && dmarc && key {
					return stop("dnsConflict")
				}
			}
		}
	}
	if i.Receives() {
		if s.ReceiveReady.IsKnown() && s.ReceiveReady.Value {
			d.Receive = Already
		} else {
			why, direct := receivePath(s.Network, a)
			d.ReceiveWhy = why
			if !direct {
				// The tunnel is a Cloudflare fact: the plan reads it with the
				// administrator's token and stops (tunnelRequired) or asks
				// (tunnelChoice) there. Detection cannot know it.
				d.Receive = RoutingReceive
				d.Needs = append(d.Needs, "cloudflare.inbound")
			} else {
				d.Receive = DirectReceive
				if s.DNS.MX.Status == "missing" {
					d.Needs = append(d.Needs, "dns.a", "dns.mx")
				} else if s.DNS.MX.Status != "present" {
					return lacking(Missing{Fact: "mx", Cause: detect.CauseDNSUnknown})
				} else if !s.DNS.ReceiveRecords.IsKnown() || !s.DNS.ReceiveRecords.Value {
					return stop("dnsConflict")
				}
			}
		}
	}
	if len(d.Needs) > 0 {
		if !s.DNS.Cloudflare.IsKnown() {
			return lacking(Missing{Fact: "dns", Cause: detect.CauseDNSUnknown})
		}
		if !s.DNS.Cloudflare.Value {
			if d.Cloud() {
				return stop("moveDNS")
			}
			d.Gate = Stop
			d.Reason = "manualDNS"
			return d
		}
	}
	if len(d.Needs) == 0 {
		d.Reason = "alreadyCorrect"
		if i.Sends() && (!s.SendReady.IsKnown() || !s.SendReady.Value) || i.Receives() && (!s.ReceiveReady.IsKnown() || !s.ReceiveReady.Value) {
			d.Reason = "dnsReady"
		}
	}
	return d
}

// HasMailbox reports an enabled account with an address: what receiving and
// its verification need on the domain.
func HasMailbox(accounts []detect.Account) bool {
	for _, a := range accounts {
		if a.Active && len(a.Addresses) > 0 {
			return true
		}
	}
	return false
}

func hasNeed(d Decision, n string) bool {
	for _, v := range d.Needs {
		if v == n {
			return true
		}
	}
	return false
}
func hasPrefixNeed(d Decision, p string) bool {
	for _, v := range d.Needs {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	return false
}

// Missing is one fact the decision needed but could not know, with its fixed
// cause (detect.CauseKey turns it into text).
type Missing struct {
	Fact  string `json:"fact"`
	Cause string `json:"cause"`
}

// domainMissing adds the domain's own DNS state when it explains the gap
// (for example a .test domain that DNS does not know).
func domainMissing(s detect.State) []Missing {
	if c := detect.DomainCause(s); c != "" {
		return []Missing{{Fact: "domainDNS", Cause: c}}
	}
	return nil
}
