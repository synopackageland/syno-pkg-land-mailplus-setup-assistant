package diagnose

import (
	"encoding/json"
	"sort"
	"strings"

	"SynoMailPlusSetupAssistant/internal/core"
)

// Summary is what the result step shows: a verdict, at most MaxProblems
// problems (each says plainly what is wrong and gives one action), the rest
// folded, and one line per other check. The ranked findings stay in the Run
// for the details; the page never lists them one by one.
//
// Every finding lands in exactly one place: a Problem (warning or critical
// with a known action), an Other line (information the user can read in one
// line), or nowhere (an observation this version cannot make, or one that
// only explains how the checks work). Findings with the same cause from
// several paths (a queue reason and the relay's failure category) merge into
// one Problem; per-domain or per-address findings of one kind group into one
// Problem or line that lists the targets.
type Summary struct {
	// Verdict: problems (at least one Problem), unclear (none, but some
	// checks could not read what they need), clear (none, every check ran),
	// unreadable (MailPlus Server could not be read, so no check ran: the
	// run's only finding says why).
	Verdict  string    `json:"verdict"`
	Problems []Problem `json:"problems"`
	// More holds the problems past MaxProblems, in the same order.
	More   []Problem `json:"more,omitempty"`
	Others []Other   `json:"others"`
}

// MaxProblems is how many problems the result shows before "Show more".
const MaxProblems = 3

// Problem is one thing to fix. Its copy is mail.diag.problem.<Key>.title,
// .body (the effect, one sentence) and .action (the one thing to do).
type Problem struct {
	Key      string        `json:"key"`
	Severity core.Severity `json:"severity"`
	// Targets are the affected domains, addresses or hosts, sorted.
	Targets []string `json:"targets,omitempty"`
	// Action is the button: setup (the setup wizard, with Intent), token
	// (enter a new Cloudflare token for the kept setup), mailplus
	// (open MailPlus Server), packages (open Package Center), or "" (the
	// action text names the place; there is no button).
	Action string `json:"action,omitempty"`
	Intent string `json:"intent,omitempty"`
	// Findings are the merged finding IDs; Details their evidence (no DSM
	// code: see plainEvidence), folded under "Show details".
	Findings []string `json:"findings"`
	Details  []Detail `json:"details,omitempty"`
}

type Detail struct {
	Target   string          `json:"target,omitempty"`
	Evidence json.RawMessage `json:"evidence"`
}

// Other is one line under "Other checks": mail.diag.other.<Key> with
// {targets, count, check}. State ok (checked, nothing found), note (a fact
// worth knowing that needs no action now) or unknown (could not be checked:
// the one not_checked line, whose Targets are areas).
type Other struct {
	Key     string   `json:"key"`
	State   string   `json:"state"`
	Check   string   `json:"check,omitempty"`
	Targets []string `json:"targets,omitempty"`
	Count   int      `json:"count,omitempty"`
}

type problemRule struct {
	key    string
	action string // setup | token | mailplus | packages | ""
}

// problemRules maps a warning or critical cause to its Problem. A cause
// missing here is never shown as a problem (it would have no action).
var problemRules = map[string]problemRule{
	"missing":          {"mailplus_missing", "packages"},
	"stopped":          {"mailplus_stopped", "packages"},
	"smtp":             {"smtp_off", "mailplus"},
	"relay_stopped":    {"relay_stopped", "setup"},
	"token_invalid":    {"token_invalid", "token"},
	"recipient_plan":   {"recipient_plan", "setup"},
	"relay_stale":      {"queue_stuck", "mailplus"},
	"queue_stale":      {"queue_stuck", "mailplus"},
	"deferred_auth":    {"deliver_auth", "setup"},
	"deferred_dns":     {"deliver_dns", ""},
	"deferred_tls":     {"deliver_tls", "setup"},
	"deferred_policy":  {"deliver_policy", "mailplus"},
	"deferred_remote":  {"deliver_remote", "mailplus"},
	"spf":              {"spf", "setup"},
	"dkim":             {"dkim", "setup"},
	"dmarc":            {"dmarc", "setup"},
	"mx":               {"mx", "setup"},
	"ptr":              {"ptr", "setup"},
	"dnsbl":            {"dnsbl", "setup"},
	"inbound":          {"inbound", "setup"},
	"imap":             {"imap_off", "mailplus"},
	"client":           {"phone", "mailplus"},
	"protocol_split":   {"phone", "mailplus"},
	"cert_expired":     {"cert_expired", ""},
	"cert_soon":        {"cert_soon", ""},
	"account_inactive": {"account_inactive", "mailplus"},
	"home_access":      {"home_access", ""},
	"source_blocked":   {"source_blocked", ""},
	"license_count":    {"license_count", "mailplus"},
	"license_owner":    {"license_owner", "mailplus"},
}

// hidden causes are never shown: how a path is chosen (not a check), optional
// records most domains do not need, and facts the next line already covers.
var hidden = map[string]bool{
	"path_unknown": true, "path_direct": true, "path_provider": true, "path_homekeeper": true,
	"path_forwarded": true, "path_web": true, "path_imap": true, "path_submission": true,
	"mtasts": true, "tlsrpt": true, "queue_age": true, "group_activation": true,
	"dnsbl_unknown": true,
}

// notChecked causes are observations this version cannot make yet (no
// verified source). They and every check that could not read what it needs
// share one line that names the areas (mail.diag.area.<area>; a check's
// area is its own name).
var notChecked = map[string]string{
	"inbound_unknown": "inbound", "client_unknown": "client", "protocol_unknown": "client",
	"access_unknown": "access", "home_unknown": "access", "block_unknown": "autoblock",
	"license_unknown": "license", "owner_unknown": "license",
}

// PreconditionSummary is the summary of a run stopped at the MailPlus Server
// gate: not installed or stopped is the one problem; not readable is the
// unreadable verdict (its finding carries the cause in words).
func PreconditionSummary(f core.Finding) Summary {
	if f.Params["cause"] == "unavailable" {
		return Summary{Verdict: "unreadable", Problems: []Problem{}, Others: []Other{}}
	}
	return Summarize(nil, []core.Finding{f})
}

// Summarize builds the result step's summary from a run's ranked findings
// (Rank's order is the symptom's likely-impact order) and the checks it ran.
func Summarize(checks []CheckID, ranked []core.Finding) Summary {
	type group struct {
		p     Problem
		first int
		setup bool // a member finding hands off to the setup wizard
	}
	groups := map[string]*group{}
	var order []*group
	others := map[string]*Other{}
	var otherOrder []string
	addOther := func(key, state, check, target string, count int) {
		id := key + "|" + check
		o := others[id]
		if o == nil {
			o = &Other{Key: key, State: state, Check: check}
			others[id] = o
			otherOrder = append(otherOrder, id)
		}
		if target != "" && !contains(o.Targets, target) {
			o.Targets = append(o.Targets, target)
		}
		o.Count += count
	}
	// shown: the check has a problem or a line; unclear: it has a finding
	// that hides what it could not observe. Either way it is not "ok".
	shown, unclear := map[string]bool{}, map[string]bool{}
	for i, f := range ranked {
		cause := f.Params["cause"]
		if cause == "relay_failure" {
			cause = "deferred_" + f.Params["subject"] // the same cause, seen on the relay hop
		}
		target := f.Params["target"]
		check := strings.TrimPrefix(f.Check, prefix)
		if rule, ok := problemRules[cause]; ok && (f.Severity == core.SeverityWarning || f.Severity == core.SeverityCritical) {
			shown[f.Check] = true
			g := groups[rule.key]
			if g == nil {
				g = &group{p: Problem{Key: rule.key, Severity: f.Severity, Action: rule.action, Findings: []string{}}, first: i}
				groups[rule.key] = g
				order = append(order, g)
			}
			if f.Severity == core.SeverityCritical {
				g.p.Severity = core.SeverityCritical
			}
			if intent := f.Params["intent"]; f.FixWizard == "mail.setup" && intent != "" {
				g.setup = true
				g.p.Intent = mergeIntent(g.p.Intent, intent)
			}
			if target != "" && !contains(g.p.Targets, target) {
				g.p.Targets = append(g.p.Targets, target)
			}
			g.p.Findings = append(g.p.Findings, f.ID)
			if len(f.Evidence) > 0 && string(f.Evidence) != "null" {
				g.p.Details = append(g.p.Details, Detail{Target: target, Evidence: f.Evidence})
			}
			continue
		}
		if hidden[cause] {
			// An unknown path leaves its check unclear. Block lists are
			// opt-in (none by default): not checking them is no doubt about
			// what the network check did read.
			if strings.HasSuffix(cause, "_unknown") && cause != "dnsbl_unknown" {
				unclear[f.Check] = true
			}
			continue
		}
		shown[f.Check] = true
		switch {
		case notChecked[cause] != "":
			addOther("not_checked", "unknown", "", notChecked[cause], 0)
		case f.Params["relay"] == "1" && f.Severity == core.SeverityInfo:
			// Mail leaves through the relay: this NAS's own address does not
			// send it, so its reverse DNS, block lists and port 25 do not matter.
		case cause == "queue":
			addOther("queue", "note", check, "", queueCount(f.Evidence))
		case cause == "dmarc" && f.Params["status"] == "missing":
			addOther("dmarc_missing", "note", check, target, 0)
		case cause == "mx" && f.Params["status"] == "missing":
			addOther("mx_missing", "note", check, target, 0)
		case cause == "dkim" && f.Params["status"] == "unknown" && len(f.Evidence) == 0:
			addOther("dkim_none", "note", check, target, 0)
		case cause == "outbound":
			addOther("outbound", "note", check, "", 0)
		default:
			// Could not read or decide (unavailable, egress, relay history,
			// bounded, an unknown DNS answer): the check is named on the
			// not-checked line.
			addOther("not_checked", "unknown", "", check, 0)
		}
	}
	for _, id := range checks {
		if !shown[string(id)] && !unclear[string(id)] {
			addOther("ok", "ok", strings.TrimPrefix(string(id), prefix), "", 0)
		}
	}
	for _, g := range order {
		if g.p.Action == "setup" && !g.setup {
			// A provider's own relay, or a cause the setup cannot change:
			// MailPlus Server is where it is fixed.
			g.p.Action = "mailplus"
		}
		if g.p.Action != "setup" {
			g.p.Intent = ""
		}
	}

	sort.SliceStable(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if (a.p.Severity == core.SeverityCritical) != (b.p.Severity == core.SeverityCritical) {
			return a.p.Severity == core.SeverityCritical
		}
		return a.first < b.first
	})
	s := Summary{Problems: []Problem{}, Others: []Other{}}
	for i, g := range order {
		sort.Strings(g.p.Targets)
		if i < MaxProblems {
			s.Problems = append(s.Problems, g.p)
		} else {
			s.More = append(s.More, g.p)
		}
	}
	stateOrder := map[string]int{"note": 0, "unknown": 1, "ok": 2}
	for _, id := range otherOrder {
		o := others[id]
		sort.Strings(o.Targets)
		s.Others = append(s.Others, *o)
	}
	sort.SliceStable(s.Others, func(i, j int) bool { return stateOrder[s.Others[i].State] < stateOrder[s.Others[j].State] })
	switch {
	case len(s.Problems) > 0:
		s.Verdict = "problems"
	case anyState(s.Others, "unknown"):
		s.Verdict = "unclear"
	default:
		s.Verdict = "clear"
	}
	return s
}

func anyState(others []Other, state string) bool {
	for _, o := range others {
		if o.State == state {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func mergeIntent(a, b string) string {
	if a == "" || a == b {
		return b
	}
	return "both"
}

func queueCount(evidence json.RawMessage) int {
	var v struct {
		Count int `json:"count"`
	}
	if json.Unmarshal(evidence, &v) != nil {
		return 0
	}
	return v.Count
}
