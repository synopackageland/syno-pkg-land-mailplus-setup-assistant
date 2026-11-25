package diagnose

import (
	"strconv"

	"SynoMailPlusSetupAssistant/internal/core"
)

// MailPath identifies the selected hop, not a package-wide health claim.
// No hostname, IP, username, header or provider error belongs in these fields.
type MailPath string

const (
	PathDirect     MailPath = "direct"
	PathProvider   MailPath = "provider"
	PathHomeKeeper MailPath = "homekeeper"
	PathForwarded  MailPath = "forwarded"
	PathWeb        MailPath = "web"
	PathIMAP       MailPath = "imap"
	PathSubmission MailPath = "submission"
)

type TransportState struct {
	Send    MailPath `json:"send,omitempty"`
	Receive MailPath `json:"receive,omitempty"`
	Client  MailPath `json:"client,omitempty"`
	// Failure applies to the selected relay hop only; no active login probe.
	RelayFailure DeferredReason `json:"relayFailure,omitempty"`
	// These observations must concern the selected client protocol/endpoint,
	// including its actual address family, rather than a working web endpoint.
	ClientReachable *bool `json:"clientReachable,omitempty"`
	WebReachable    *bool `json:"webReachable,omitempty"`
}

// AccountAccess describes one selected mailbox using a stable opaque reference,
// never an account name or address. EffectiveActive is the authoritative result
// AFTER user/group policy, not an OR of individual flags.
type AccountAccess struct {
	Ref             uint64 `json:"ref"`
	EffectiveActive *bool  `json:"effectiveActive,omitempty"`
	GroupControlled *bool  `json:"groupControlled,omitempty"`
	HomeReadable    *bool  `json:"homeReadable,omitempty"`
}

type AccessState struct {
	Accounts []AccountAccess `json:"accounts,omitempty"`
	// BlockedSource must refer to the affected client's independently selected
	// source IP, not the administrator's CGI address or a forwarded header.
	BlockedSource *bool `json:"blockedSource,omitempty"`
	// Licensed and Activated are MailPlus Server's own counts
	// (License get_user_limit / get_active_user_num v1), nil when unread.
	Licensed  *int `json:"licensed,omitempty"`
	Activated *int `json:"activated,omitempty"`
	// OwnerMatches is a verified ownership comparison, never an owner identity.
	OwnerMatches *bool `json:"ownerMatches,omitempty"`
}

func cssFinding(check CheckID, cause, family, subject string, severity core.Severity, facts any) core.Finding {
	f := finding(check, cause, subject, severity, "", facts)
	f.WhyKey = prefix + family + ".why"
	f.FixKey = prefix + family + ".fix"
	return f
}

func checkTransport(s State) []core.Finding {
	t := s.Transport
	out := []core.Finding{}
	for _, hop := range []struct {
		name  string
		path  MailPath
		valid []MailPath
	}{
		{"send", t.Send, []MailPath{PathDirect, PathProvider, PathHomeKeeper}},
		{"receive", t.Receive, []MailPath{PathDirect, PathForwarded}},
		{"client", t.Client, []MailPath{PathWeb, PathIMAP, PathSubmission}},
	} {
		cause := "path_unknown"
		for _, allowed := range hop.valid {
			if hop.path == allowed {
				cause = "path_" + string(allowed)
			}
		}
		path := "unknown"
		if cause != "path_unknown" {
			path = string(hop.path)
		}
		f := cssFinding(Transport, cause, "transport_path", hop.name, core.SeverityInfo,
			map[string]string{"hop": hop.name, "path": path})
		if hop.name == "send" || hop.name == "receive" {
			f.TitleKey = prefix + "path_" + hop.name + "_" + path + ".title"
		}
		out = append(out, f)
	}
	if t.Send == PathProvider || t.Send == PathHomeKeeper {
		switch t.RelayFailure {
		case DeferredAuth, DeferredTLS, DeferredDNS, DeferredRemote, DeferredPolicy:
			out = append(out, cssFinding(Transport, "relay_failure", "provider_relay", string(t.RelayFailure),
				core.SeverityWarning, nil))
		}
	}
	if t.Client == PathIMAP || t.Client == PathSubmission {
		if isFalse(t.ClientReachable) {
			cause := "client"
			if isTrue(t.WebReachable) {
				cause = "protocol_split"
			}
			out = append(out, cssFinding(Transport, cause, "protocol_path", "", core.SeverityWarning, nil))
		} else if t.ClientReachable == nil {
			out = append(out, cssFinding(Transport, "protocol_unknown", "protocol_path", "", core.SeverityInfo, nil))
		}
	}
	return out
}

func checkAccess(s State) []core.Finding {
	a := s.Access
	out := []core.Finding{}
	if len(a.Accounts) == 0 {
		out = append(out, cssFinding(Access, "access_unknown", "account_access", "", core.SeverityInfo, nil))
	}
	seen := map[uint64]bool{}
	for i, account := range a.Accounts {
		if i >= 1000 {
			out = append(out, cssFinding(Access, "access_unknown", "account_access", "limit", core.SeverityInfo,
				map[string]int{"examined": 1000}))
			break
		}
		if account.Ref == 0 || seen[account.Ref] {
			out = append(out, cssFinding(Access, "access_unknown", "account_access", "identity", core.SeverityInfo, nil))
			break
		}
		seen[account.Ref] = true
		subject := strconv.FormatUint(account.Ref, 10)
		switch {
		case isFalse(account.EffectiveActive):
			out = append(out, cssFinding(Access, "account_inactive", "account_access", subject, core.SeverityWarning, account))
		case account.EffectiveActive == nil:
			out = append(out, cssFinding(Access, "access_unknown", "account_access", subject, core.SeverityInfo, account))
		}
		if isTrue(account.GroupControlled) {
			out = append(out, cssFinding(Access, "group_activation", "account_access", subject, core.SeverityInfo, account))
		}
		if isFalse(account.HomeReadable) {
			out = append(out, cssFinding(Access, "home_access", "account_access", subject, core.SeverityWarning, nil))
		} else if account.HomeReadable == nil {
			out = append(out, cssFinding(Access, "home_unknown", "account_access", subject, core.SeverityInfo, nil))
		}
	}
	cause, severity := "block_unknown", core.SeverityInfo
	if isTrue(a.BlockedSource) {
		cause, severity = "source_blocked", core.SeverityWarning
	}
	if !isFalse(a.BlockedSource) {
		out = append(out, cssFinding(Access, cause, "auto_block", "", severity, nil))
	}
	cause, severity = "license_unknown", core.SeverityInfo
	validCounts := a.Licensed != nil && a.Activated != nil && *a.Licensed >= 0 && *a.Activated >= 0
	if validCounts && *a.Activated > *a.Licensed {
		cause, severity = "license_count", core.SeverityWarning
	}
	if !validCounts || cause == "license_count" {
		var counts any
		if validCounts {
			counts = map[string]int{"licensed": *a.Licensed, "activated": *a.Activated}
		}
		f := cssFinding(Access, cause, "mail_license", "", severity, counts)
		if !validCounts {
			f.WhyKey = prefix + "license_unread.why" // not read: failed, refused, unsupported or MailPlus stopped
		}
		out = append(out, f)
	}
	if a.OwnerMatches == nil {
		f := cssFinding(Access, "owner_unknown", "mail_license", "", core.SeverityInfo, nil)
		f.WhyKey = prefix + "license_unchecked.why"
		out = append(out, f)
	} else if !*a.OwnerMatches {
		out = append(out, cssFinding(Access, "license_owner", "mail_license", "", core.SeverityWarning, nil))
	}
	return out
}
