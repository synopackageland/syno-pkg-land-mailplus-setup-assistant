package setup

import "SynoMailPlusSetupAssistant/internal/mail/detect"

// Route is the administrator's choice of mail route, asked right after the
// domain. It replaces the earlier Yes/No/Not sure questions about the
// Internet connection: nothing probes the connection from outside, so the
// route is what the administrator states.
type Route string

const (
	// RouteCloudflare is "Cloudflare receives and sends for me" (recommended):
	// both directions take the Cloudflare path whatever the checks say.
	RouteCloudflare Route = "cloudflare"
	// RouteDirect is "use my own IP": the administrator confirmed a fixed
	// public IP and TCP 25 reachable from outside (the router forwards it).
	// A check that says otherwise still wins.
	RouteDirect Route = "direct"
)

// Answers are what the administrator chose for this setup. No external probe
// checks the route, so only an explicit RouteDirect allows a direct path:
// RouteCloudflare and no choice both mean "not usable".
type Answers struct {
	// Source is where the domain comes from, chosen on the start step: "own"
	// (typed; its DNS managed by the administrator) or "cloudflare" (picked
	// from the Cloudflare sign-in's zones, so its DNS is on Cloudflare). It
	// never decides a mail path: the route and the checks do, on both.
	Source Source `json:"source,omitempty"`
	// Route is the route step's choice; "" until the administrator chose one
	// (the first detection runs before the route is asked).
	Route Route `json:"route,omitempty"`
}

// Source is the start step's choice: where the domain comes from.
type Source string

const (
	SourceOwn        Source = "own"
	SourceCloudflare Source = "cloudflare"
)

// Cloudflare reports a domain picked from the Cloudflare sign-in.
func (a Answers) Cloudflare() bool { return a.Source == SourceCloudflare }

// Direct reports the administrator's confirmed own-IP route.
func (a Answers) Direct() bool { return a.Route == RouteDirect }

// Valid accepts a known source and a known route (or none).
func (a Answers) Valid() bool {
	if a.Source != "" && a.Source != SourceOwn && a.Source != SourceCloudflare {
		return false
	}
	return a.Route == "" || a.Route == RouteDirect || a.Route == RouteCloudflare
}

// For normalizes the answers: "own" and no source are the same choice (the
// default before the start step). The route holds for every intent.
func (a Answers) For(Intent) Answers {
	out := Answers{Route: a.Route}
	if a.Cloudflare() {
		out.Source = SourceCloudflare
	}
	return out
}

// routeWhy is why a route that is not RouteDirect leaves the direct path out:
// the administrator chose Cloudflare, or has not chosen yet.
func routeWhy(a Answers) string {
	if a.Route == RouteCloudflare {
		return "routeCloudflare"
	}
	return "routeUnset"
}

// sendPath decides whether MailPlus may deliver directly. The Cloudflare
// route (or no route yet) decides alone, with one reason: routeCloudflare or
// routeUnset. On the own-IP route the reasons come in a fixed order: checks
// that came out bad (they win over the choice), then checks that could not be
// done. Each reason is a code localized as mail.setup.why.<code>.
//
// Every check this version runs must have come out good: egress IP, PTR,
// forward-confirmed reverse DNS, outbound TCP 25 and every DNSBL. Static
// addressing is not checked by this version, so the administrator's
// confirmation stands for it; a known changing address still wins.
func sendPath(n detect.Network, a Answers) (why []string, direct bool) {
	if !a.Direct() {
		return []string{routeWhy(a)}, false
	}
	bad, unknown := []string{}, []string{}
	if n.Addressing.IsKnown() && n.Addressing.Value == detect.Changing {
		bad = append(bad, "ipChanging")
	}
	ip := n.EgressIPv4.IsKnown()
	if !ip {
		// PTR, FCrDNS and the blocklists are read for the IP: one reason.
		unknown = append(unknown, "ipUnknown")
	}
	if n.PTR.IsKnown() && len(n.PTR.Value) == 0 {
		bad = append(bad, "ptrNone")
	} else if ip && !n.PTR.IsKnown() {
		unknown = append(unknown, "ptrUnknown")
	}
	if n.FCrDNS.IsKnown() && !n.FCrDNS.Value {
		bad = append(bad, "fcrdnsFail")
	} else if ip && !n.FCrDNS.IsKnown() {
		unknown = append(unknown, "fcrdnsUnknown")
	}
	if n.Outbound25.IsKnown() && !n.Outbound25.Value {
		bad = append(bad, "outboundBlocked")
	} else if !n.Outbound25.IsKnown() {
		unknown = append(unknown, "outboundUnknown")
	}
	listed, clean := false, len(n.DNSBL) > 0
	for _, bl := range n.DNSBL {
		listed = listed || bl.Status == "listed"
		clean = clean && bl.Status == "not_listed"
	}
	if listed {
		bad = append(bad, "dnsblListed")
	} else if ip && !clean {
		unknown = append(unknown, "dnsblUnknown")
	}
	why = append(bad, unknown...)
	if len(why) == 0 {
		return []string{"routeDirect", "sendChecksPass"}, true
	}
	return why, false
}

// receivePath decides whether the Internet may deliver to MailPlus directly.
// The Cloudflare route (or no route yet) decides alone, as for sending.
// Neither static addressing nor inbound TCP 25 is checked by this version (no
// external probe; the route step links to an outside test whose result is
// never read), so the administrator's confirmation stands for them; a known
// changing address or a known blocked port still wins. The direct path needs
// the public IP for its A record.
func receivePath(n detect.Network, a Answers) (why []string, direct bool) {
	if !a.Direct() {
		return []string{routeWhy(a)}, false
	}
	why = []string{}
	if n.Addressing.IsKnown() && n.Addressing.Value == detect.Changing {
		why = append(why, "ipChanging")
	}
	// Every unknown Inbound25 is treated as "not checked" because this version
	// runs no inbound probe at all (detect sets it to CauseNotChecked). When an
	// external probe is ever added, a probe that ran and failed must count as
	// unclear (not usable, like outboundUnknown), not as "not checked": tell
	// the two apart by Inbound25.Detail here.
	if n.Inbound25.IsKnown() && !n.Inbound25.Value {
		why = append(why, "inboundBlocked")
	}
	if !n.EgressIPv4.IsKnown() {
		why = append(why, "ipUnknown")
	}
	if len(why) == 0 {
		return []string{"routeDirect"}, true
	}
	return why, false
}

// WhyCodes lists every reason code sendPath and receivePath can return (for
// catalog checks).
var WhyCodes = []string{
	"ipChanging", "ptrNone", "fcrdnsFail", "outboundBlocked", "dnsblListed", "inboundBlocked",
	"routeCloudflare", "routeUnset",
	"ipUnknown", "ptrUnknown", "fcrdnsUnknown", "outboundUnknown", "dnsblUnknown",
	"routeDirect", "sendChecksPass",
}

// RouteKeys are the route step's texts (mail.setup.route.<key>), for catalog
// checks: the two choices, the own-IP requirements, the outside test link,
// the confirmation and the switch back to Cloudflare.
var RouteKeys = []string{
	"cloudflare", "cloudflareHint", "direct", "directHint", "requirements",
	"fixedIp", "fixedIpHint", "inbound", "inboundHint", "test", "testNoIp", "testNote",
	"detected", "confirm", "notEligible", "useCloudflare", "checksDisagree",
}
