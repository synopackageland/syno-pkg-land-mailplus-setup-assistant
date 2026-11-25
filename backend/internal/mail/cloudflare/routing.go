package cloudflare

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"reflect"
	"sort"
	"strings"
)

type RoutingDomain struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Enabled    bool            `json:"enabled"`
	Status     string          `json:"status"`
	Subdomains []RoutingDomain `json:"subdomains,omitempty"`
}

type RoutingMatcher struct {
	Type  string `json:"type"`
	Field string `json:"field,omitempty"`
	Value string `json:"value,omitempty"`
}

type RoutingAction struct {
	Type  string   `json:"type"`
	Value []string `json:"value,omitempty"`
}

type RoutingRule struct {
	ID       string           `json:"id,omitempty"`
	Name     string           `json:"name"`
	Enabled  bool             `json:"enabled"`
	Priority int              `json:"priority"`
	Matchers []RoutingMatcher `json:"matchers"`
	Actions  []RoutingAction  `json:"actions"`
}

func routingPath(zoneID string, suffix ...string) (string, error) {
	return path(append([]string{"zones", zoneID, "email", "routing"}, suffix...)...)
}

func (c *Client) RoutingStatus(ctx context.Context, zoneID string) (RoutingDomain, error) {
	p, err := routingPath(zoneID)
	if err != nil {
		return RoutingDomain{}, err
	}
	var result RoutingDomain
	_, err = c.request(ctx, http.MethodGet, p, nil, nil, &result, PermissionSettingsRead, PermissionSettingsWrite)
	return result, err
}

func (c *Client) RoutingDNS(ctx context.Context, zoneID, subdomain string) (DNSCheck, error) {
	p, err := routingPath(zoneID, "dns")
	if err != nil {
		return DNSCheck{}, err
	}
	query := url.Values{}
	if subdomain != "" {
		subdomain, err = domainName(subdomain)
		if err != nil {
			return DNSCheck{}, err
		}
		query.Set("subdomain", subdomain)
	}
	var result DNSCheck
	_, err = c.request(ctx, http.MethodGet, p, query, nil, &result, PermissionSettingsRead, PermissionSettingsWrite)
	return result, err
}

// DisableRouting turns Email Routing off for the zone apex (DELETE
// /zones/{zone}/email/routing/dns, which also removes the MX and SPF records
// Email Routing added). Only the removal of a setup that itself enabled
// routing on the zone calls it, after the administrator ticked the option:
// disabling zone routing affects every address of the zone.
func (c *Client) DisableRouting(ctx context.Context, zoneID string) error {
	status, err := c.RoutingStatus(ctx, zoneID)
	if err != nil || !status.Enabled {
		return err
	}
	p, err := routingPath(zoneID, "dns")
	if err != nil {
		return err
	}
	_, err = c.request(ctx, http.MethodDelete, p, nil, nil, nil, PermissionSettingsWrite)
	return err
}

// EnableRouting never replaces existing mail DNS or changes the catch-all.
// subdomain == "" enables the zone; otherwise it enables only that subdomain.
// Disabling (DisableRouting) is only for removing a setup that enabled it.
func (c *Client) EnableRouting(ctx context.Context, zoneID, subdomain string) (RoutingDomain, error) {
	zone, err := c.GetZone(ctx, zoneID)
	if err != nil {
		return RoutingDomain{}, err
	}
	target := zone.Name
	if subdomain != "" {
		target, err = domainName(subdomain)
		if err != nil || !inZone(target, zone.Name) || target == zone.Name {
			return RoutingDomain{}, invalid("routing subdomain")
		}
	}
	status, err := c.RoutingStatus(ctx, zoneID)
	if err != nil {
		return RoutingDomain{}, err
	}
	if target == zone.Name && status.Enabled {
		return status, nil
	}
	check, err := c.RoutingDNS(ctx, zoneID, subdomain)
	if err != nil {
		return RoutingDomain{}, err
	}
	for _, item := range status.Subdomains {
		// A subdomain stays enabled after a removal deleted its receiving
		// records (no per-subdomain disable exists); it is enabled again,
		// which adds them back, only when Cloudflare's check misses some.
		if strings.EqualFold(item.Name, target) && item.Enabled && len(check.Errors) == 0 {
			return item, nil
		}
	}
	records, err := c.ListDNSRecords(ctx, zoneID)
	if err != nil {
		return RoutingDomain{}, err
	}
	for _, record := range records {
		if !strings.EqualFold(strings.TrimSuffix(record.Name, "."), target) {
			continue
		}
		// Email Routing's own MX/SPF (left enabled by a rollback) are not a
		// conflict; any other MX/SPF belongs to its existing owner.
		if (record.Type == "MX" || record.Type == "TXT" && isSPF(record.Content)) && !RoutingRecord(record) {
			return RoutingDomain{}, conflict("existing routing DNS")
		}
	}
	for _, issue := range check.Errors {
		if !strings.HasSuffix(issue.Code, ".missing") {
			return RoutingDomain{}, conflict("routing DNS preview")
		}
	}
	p, _ := routingPath(zoneID, "dns")
	// The API's field is "name" (the zone or one of its subdomains). An
	// unknown field would be ignored and enable the zone apex instead.
	body := map[string]string{"name": target}
	var result RoutingDomain
	_, err = c.request(ctx, http.MethodPost, p, nil, body, &result, PermissionSettingsWrite)
	return result, err
}

// RoutingSPF is the SPF value Email Routing requires on a routed name.
const RoutingSPF = "v=spf1 include:_spf.mx.cloudflare.net ~all"

// RoutingRecord reports Email Routing's own MX/SPF: flagged by Cloudflare
// (meta.email_routing), or an SPF TXT that is exactly Email Routing's value
// (a refused enable can leave the flag unset).
func RoutingRecord(r DNSRecord) bool {
	if r.Meta.EmailRouting {
		return true
	}
	return r.Type == "TXT" && strings.Trim(strings.TrimSpace(r.Content), `"`) == RoutingSPF
}

func (c *Client) ListRoutingRules(ctx context.Context, zoneID string) ([]RoutingRule, error) {
	p, err := routingPath(zoneID, "rules")
	if err != nil {
		return nil, err
	}
	return list[RoutingRule](ctx, c, p, nil, PermissionRoutingRead, PermissionRoutingWrite)
}

// CatchAll reads the catch-all (SetCatchAll and RestoreCatchAll below change
// it, guarded). Wildcard literal matchers are not a
// substitute for Cloudflare's catch-all (the wildcard did not deliver in testing).
func (c *Client) CatchAll(ctx context.Context, zoneID string) (RoutingRule, error) {
	p, err := routingPath(zoneID, "rules", "catch_all")
	if err != nil {
		return RoutingRule{}, err
	}
	var result RoutingRule
	_, err = c.request(ctx, http.MethodGet, p, nil, nil, &result, PermissionRoutingRead, PermissionRoutingWrite)
	return result, err
}

func exactAddress(address string) (string, error) {
	parsed, err := mail.ParseAddress(address)
	if err != nil || parsed.Address != address || parsed.Name != "" || strings.ContainsAny(address, "*<>\r\n") {
		return "", invalid("exact email address")
	}
	local, domain, ok := strings.Cut(address, "@")
	if !ok || local == "" {
		return "", invalid("exact email address")
	}
	name, err := domainName(domain)
	if err != nil {
		return "", err
	}
	return local + "@" + name, nil
}

func (c *Client) CreateRoutingRule(ctx context.Context, zoneID, address, worker string) (RoutingRule, error) {
	address, err := exactAddress(address)
	if err != nil {
		return RoutingRule{}, err
	}
	if worker != c.WorkerName() {
		return RoutingRule{}, ownership("routing worker")
	}
	zone, err := c.GetZone(ctx, zoneID)
	if err != nil {
		return RoutingRule{}, err
	}
	_, domain, _ := strings.Cut(address, "@")
	if !inZone(domain, zone.Name) {
		return RoutingRule{}, invalid("routing address outside zone")
	}
	rules, err := c.ListRoutingRules(ctx, zoneID)
	if err != nil {
		return RoutingRule{}, err
	}
	for _, rule := range rules {
		for _, matcher := range rule.Matchers {
			if matcher.Type == "literal" && matcher.Field == "to" && strings.EqualFold(matcher.Value, address) {
				return RoutingRule{}, conflict("existing exact-address rule")
			}
		}
	}
	input := RoutingRule{Name: c.marker(), Enabled: true,
		Matchers: []RoutingMatcher{{Type: "literal", Field: "to", Value: address}},
		Actions:  []RoutingAction{{Type: "worker", Value: []string{worker}}}}
	p, _ := routingPath(zoneID, "rules")
	var result RoutingRule
	_, err = c.request(ctx, http.MethodPost, p, nil, input, &result, PermissionRoutingWrite)
	return result, err
}

// OwnedRoutingRules returns this owner's exact-address rules. Any rule that
// carries the owner's name but not exactly the owned shape is drift.
func (c *Client) OwnedRoutingRules(ctx context.Context, zoneID string) ([]RoutingRule, error) {
	rules, err := c.ListRoutingRules(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	out := []RoutingRule{}
	for _, rule := range rules {
		if rule.Name != c.marker() {
			continue
		}
		if !c.ownedRule(rule) {
			return nil, ownership("routing rule")
		}
		out = append(out, rule)
	}
	return out, nil
}

func (c *Client) ownedRule(rule RoutingRule) bool {
	if rule.Name != c.marker() || len(rule.Matchers) != 1 ||
		rule.Matchers[0].Type != "literal" || rule.Matchers[0].Field != "to" ||
		len(rule.Actions) != 1 || rule.Actions[0].Type != "worker" ||
		len(rule.Actions[0].Value) != 1 || rule.Actions[0].Value[0] != c.WorkerName() {
		return false
	}
	_, err := exactAddress(rule.Matchers[0].Value)
	return err == nil
}

func (c *Client) DeleteRoutingRule(ctx context.Context, zoneID, id string) error {
	// Explicitly refuse the special catch-all path, even when a caller supplies
	// it as an identifier. No mutator can address it.
	if id == "catch_all" {
		return ownership("catch-all rule")
	}
	p, err := routingPath(zoneID, "rules", id)
	if err != nil {
		return err
	}
	var rule RoutingRule
	_, err = c.request(ctx, http.MethodGet, p, nil, nil, &rule, PermissionRoutingRead, PermissionRoutingWrite)
	if IsKind(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if rule.ID != id || !c.ownedRule(rule) {
		return ownership("routing rule")
	}
	_, err = c.request(ctx, http.MethodDelete, p, nil, nil, nil, PermissionRoutingWrite)
	return err
}

// EnsureRoutingRules creates this owner's exact rules for every address that
// has none yet, reading the zone and its rules once. An address routed by any
// other rule is a conflict; an owned rule for an address not asked for is
// drift (ownership error). Already owned addresses are left as they are, so a
// lost reply is reconciled, never sent twice.
func (c *Client) EnsureRoutingRules(ctx context.Context, zoneID string, addresses []string, worker string) error {
	if worker != c.WorkerName() {
		return ownership("routing worker")
	}
	want := map[string]string{}
	for _, a := range addresses {
		exact, err := exactAddress(a)
		if err != nil {
			return err
		}
		want[strings.ToLower(exact)] = exact
	}
	zone, err := c.GetZone(ctx, zoneID)
	if err != nil {
		return err
	}
	for _, exact := range want {
		_, domain, _ := strings.Cut(exact, "@")
		if !inZone(domain, zone.Name) {
			return invalid("routing address outside zone")
		}
	}
	rules, err := c.ListRoutingRules(ctx, zoneID)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, rule := range rules {
		owned := rule.Name == c.marker()
		if owned && !c.ownedRule(rule) {
			return ownership("routing rule")
		}
		for _, m := range rule.Matchers {
			if m.Type != "literal" || m.Field != "to" {
				continue
			}
			key := strings.ToLower(m.Value)
			if _, asked := want[key]; !asked {
				if owned {
					return ownership("routing rule drift")
				}
				continue
			}
			if !owned {
				return conflict("existing exact-address rule")
			}
			have[key] = true
		}
	}
	p, _ := routingPath(zoneID, "rules")
	for key, exact := range want {
		if have[key] {
			continue
		}
		input := RoutingRule{Name: c.marker(), Enabled: true,
			Matchers: []RoutingMatcher{{Type: "literal", Field: "to", Value: exact}},
			Actions:  []RoutingAction{{Type: "worker", Value: []string{worker}}}}
		if _, err := c.request(ctx, http.MethodPost, p, nil, input, nil, PermissionRoutingWrite); err != nil {
			return err
		}
	}
	return nil
}

// LeftoverOwner reports a rule this package made under another owner (an
// earlier setup that was kept, or whose rollback did not finish): named
// "syno-home-keeper:<owner>", one literal "to" matcher with an exact address,
// and one action to that owner's Worker. Anything else is not ours.
func LeftoverOwner(rule RoutingRule) (string, bool) {
	owner, ok := strings.CutPrefix(rule.Name, "syno-home-keeper:")
	if !ok || !ownerID.MatchString(owner) || len(rule.Matchers) != 1 || rule.Matchers[0].Type != "literal" ||
		rule.Matchers[0].Field != "to" || len(rule.Actions) != 1 || rule.Actions[0].Type != "worker" ||
		len(rule.Actions[0].Value) != 1 || rule.Actions[0].Value[0] != "syno-home-keeper-"+owner+"-inbound" {
		return "", false
	}
	if _, err := exactAddress(rule.Matchers[0].Value); err != nil {
		return "", false
	}
	return owner, true
}

// TakeOverRoutingRule points a leftover rule of fromOwner at this owner's
// Worker and name, keeping its address, priority and enabled state. A rule
// already taken over is left as it is (a lost reply); any other shape is
// refused.
// A rule disabled since the plan is refused too: the plan takes over only an
// enabled one (a disabled one would receive nothing).
func (c *Client) TakeOverRoutingRule(ctx context.Context, zoneID, id, address, fromOwner string) error {
	return c.moveRoutingRule(ctx, zoneID, id, address, fromOwner, c.owner, true)
}

// ReturnRoutingRule gives a taken-over rule back to its earlier owner
// (rollback). A rule already returned is left as it is.
func (c *Client) ReturnRoutingRule(ctx context.Context, zoneID, id, address, toOwner string) error {
	return c.moveRoutingRule(ctx, zoneID, id, address, c.owner, toOwner, false)
}

func (c *Client) moveRoutingRule(ctx context.Context, zoneID, id, address, from, to string, enabled bool) error {
	if id == "catch_all" || !ownerID.MatchString(from) || !ownerID.MatchString(to) {
		return ownership("routing rule")
	}
	address, err := exactAddress(address)
	if err != nil {
		return err
	}
	p, err := routingPath(zoneID, "rules", id)
	if err != nil {
		return err
	}
	var rule RoutingRule
	if _, err = c.request(ctx, http.MethodGet, p, nil, nil, &rule, PermissionRoutingRead, PermissionRoutingWrite); err != nil {
		return err
	}
	owner, ok := LeftoverOwner(rule)
	if !ok || rule.ID != id || !strings.EqualFold(rule.Matchers[0].Value, address) {
		return ownership("routing rule")
	}
	switch owner {
	case to:
		return nil // already moved
	case from:
		if enabled && !rule.Enabled {
			return ownership("disabled routing rule")
		}
	default:
		return ownership("routing rule owner")
	}
	rule.ID = ""
	rule.Name = "syno-home-keeper:" + to
	rule.Actions = []RoutingAction{{Type: "worker", Value: []string{"syno-home-keeper-" + to + "-inbound"}}}
	_, err = c.request(ctx, http.MethodPut, p, nil, rule, nil, PermissionRoutingWrite)
	return err
}

// ---------- Catch-all (apex only) ----------

// Cloudflare offers the catch-all rule for the zone apex only ("Email
// Routing subdomains", read 2026-11-13). Reading it needs Email Routing Rules
// Read or Write; changing it needs Email Routing Rules Write
// (PUT /zones/{zone}/email/routing/rules/catch_all).

// CatchAllUnused reports a catch-all nobody uses: disabled, or enabled with
// the drop action only. Anything else (a forward, another Worker) belongs to
// its owner and is never changed.
func CatchAllUnused(rule RoutingRule) bool {
	if !rule.Enabled {
		return true
	}
	return len(rule.Actions) == 1 && rule.Actions[0].Type == "drop"
}

// CatchAllOurs reports the catch-all this owner set: its name, enabled, one
// "all" matcher and one action to this owner's Worker.
func (c *Client) CatchAllOurs(rule RoutingRule) bool {
	return rule.Name == c.marker() && rule.Enabled && len(rule.Matchers) == 1 && rule.Matchers[0].Type == "all" &&
		len(rule.Actions) == 1 && rule.Actions[0].Type == "worker" && len(rule.Actions[0].Value) == 1 &&
		rule.Actions[0].Value[0] == c.WorkerName()
}

// catchAllBody is exactly the documented update body.
type catchAllBody struct {
	Name     string           `json:"name"`
	Enabled  bool             `json:"enabled"`
	Matchers []RoutingMatcher `json:"matchers"`
	Actions  []RoutingAction  `json:"actions"`
}

func catchAllShape(rule RoutingRule) catchAllBody {
	b := catchAllBody{Name: rule.Name, Enabled: rule.Enabled, Matchers: rule.Matchers, Actions: rule.Actions}
	if len(b.Matchers) == 0 {
		b.Matchers = []RoutingMatcher{{Type: "all"}}
	}
	if len(b.Actions) == 0 {
		b.Actions = []RoutingAction{{Type: "drop"}}
	}
	return b
}

// SameCatchAll compares the parts of a catch-all that matter (name, state,
// matchers, actions).
func SameCatchAll(a, b RoutingRule) bool {
	return reflect.DeepEqual(catchAllShape(a), catchAllShape(b))
}

// SetCatchAll points the zone's catch-all at this owner's Worker. It writes
// only when the catch-all is still exactly before (the snapshot taken at
// plan time) and unused; one already ours is left as it is (a lost reply).
func (c *Client) SetCatchAll(ctx context.Context, zoneID string, before RoutingRule) error {
	current, err := c.CatchAll(ctx, zoneID)
	if err != nil {
		return err
	}
	if c.CatchAllOurs(current) {
		return nil
	}
	if !SameCatchAll(current, before) || !CatchAllUnused(current) {
		return ownership("catch-all rule")
	}
	p, err := routingPath(zoneID, "rules", "catch_all")
	if err != nil {
		return err
	}
	body := catchAllBody{Name: c.marker(), Enabled: true, Matchers: []RoutingMatcher{{Type: "all"}},
		Actions: []RoutingAction{{Type: "worker", Value: []string{c.WorkerName()}}}}
	_, err = c.request(ctx, http.MethodPut, p, nil, body, nil, PermissionRoutingWrite)
	return err
}

// RestoreCatchAll puts the snapshot back, only while the catch-all is still
// ours. One somebody changed since is not ours any more and is left as it is
// (restored reports false).
func (c *Client) RestoreCatchAll(ctx context.Context, zoneID string, before RoutingRule) (restored bool, err error) {
	current, err := c.CatchAll(ctx, zoneID)
	if err != nil {
		return false, err
	}
	if SameCatchAll(current, before) {
		return true, nil
	}
	if !c.CatchAllOurs(current) {
		return false, nil
	}
	p, err := routingPath(zoneID, "rules", "catch_all")
	if err != nil {
		return false, err
	}
	_, err = c.request(ctx, http.MethodPut, p, nil, catchAllShape(before), nil, PermissionRoutingWrite)
	return err == nil, err
}

// ---------- Mailbox sync (per-address mode) ----------

// Sync causes for an address that could not get a rule.
const (
	SyncConflict = "conflict" // another rule (not this owner's) routes it
	SyncLimit    = "limit"    // the zone's rule limit or this run's write cap
	SyncFailed   = "failed"   // Cloudflare refused or did not answer
)

// SyncPending is one address the sync could not route.
type SyncPending struct {
	Address string `json:"address"`
	Cause   string `json:"cause"`
}

// SyncResult is what one sync run changed.
type SyncResult struct {
	Added   []string      `json:"added"`
	Removed []string      `json:"removed"`
	Pending []SyncPending `json:"pending"`
	// Held: removals this run left alone because they exceeded its
	// removal limit (SyncRoutingRulesLimited); none was made.
	Held int `json:"held,omitempty"`
}

// RemovalLimit decides how many of this owner's rules for the domain one
// run may delete, given how many it holds there; a run that would delete
// more deletes none (an automatic run's guard).
type RemovalLimit func(owned int) int

// maxZoneRules is Cloudflare's Email Routing rule limit per zone.
const maxZoneRules = 200

// SyncRoutingRules brings this owner's exact-address rules for domain in
// line with want: it adds the missing ones and deletes this owner's rules
// for addresses no longer wanted. Rules that are not this owner's exact
// shape are never touched; an address such a rule routes stays pending.
// It reads the rule list once, needs Email Routing Rules Write only (no zone
// read), writes at most maxWrites times and nothing when nothing differs.
// A refused write (missing permission) stops the run with that error.
func (c *Client) SyncRoutingRules(ctx context.Context, zoneID, domain string, want []string, maxWrites int) (SyncResult, error) {
	return c.SyncRoutingRulesLimited(ctx, zoneID, domain, want, maxWrites, nil)
}

// SyncRoutingRulesLimited is SyncRoutingRules with a removal limit (nil:
// none). Additions are made either way.
func (c *Client) SyncRoutingRulesLimited(ctx context.Context, zoneID, domain string, want []string, maxWrites int, limit RemovalLimit) (SyncResult, error) {
	out := SyncResult{Added: []string{}, Removed: []string{}, Pending: []SyncPending{}}
	domain, err := domainName(domain)
	if err != nil {
		return out, err
	}
	wanted := map[string]string{}
	order := []string{}
	for _, a := range want {
		exact, err := exactAddress(a)
		if err != nil {
			return out, err
		}
		local, d, _ := strings.Cut(exact, "@")
		if d != domain {
			return out, invalid("sync address outside domain")
		}
		key := strings.ToLower(local + "@" + d)
		if _, dup := wanted[key]; !dup {
			wanted[key] = exact
			order = append(order, key)
		}
	}
	rules, err := c.ListRoutingRules(ctx, zoneID)
	if err != nil {
		return out, err
	}
	owned := map[string]RoutingRule{}
	foreign := map[string]bool{}
	counted := 0
	for _, rule := range rules {
		literal := false
		for _, m := range rule.Matchers {
			literal = literal || m.Type == "literal"
		}
		if literal {
			counted++
		}
		if c.ownedRule(rule) {
			owned[strings.ToLower(rule.Matchers[0].Value)] = rule
			continue
		}
		for _, m := range rule.Matchers {
			if m.Type == "literal" && m.Field == "to" {
				foreign[strings.ToLower(m.Value)] = true
			}
		}
	}
	writes := 0
	// Remove first: it frees room under the zone's limit.
	removals := []string{}
	for key, rule := range owned {
		_, d, _ := strings.Cut(key, "@")
		if _, keep := wanted[key]; !keep && d == domain {
			removals = append(removals, rule.Matchers[0].Value)
		}
	}
	sort.Strings(removals)
	if limit != nil {
		ours := 0
		for key := range owned {
			if _, d, _ := strings.Cut(key, "@"); d == domain {
				ours++
			}
		}
		if len(removals) > limit(ours) {
			out.Held, removals = len(removals), nil
		}
	}
	for _, address := range removals {
		if writes >= maxWrites {
			break
		}
		writes++
		rule := owned[strings.ToLower(address)]
		if err := c.DeleteRoutingRule(ctx, zoneID, rule.ID); err != nil {
			if PermissionRefused(err) || errors.Is(err, context.Canceled) {
				return out, err
			}
			continue // stays; the next run tries again
		}
		counted--
		out.Removed = append(out.Removed, address)
	}
	p, err := routingPath(zoneID, "rules")
	if err != nil {
		return out, err
	}
	for _, key := range order {
		exact := wanted[key]
		switch {
		case owned[key].ID != "":
			continue
		case foreign[key]:
			out.Pending = append(out.Pending, SyncPending{Address: exact, Cause: SyncConflict})
			continue
		case counted >= maxZoneRules || writes >= maxWrites:
			out.Pending = append(out.Pending, SyncPending{Address: exact, Cause: SyncLimit})
			continue
		}
		writes++
		input := RoutingRule{Name: c.marker(), Enabled: true,
			Matchers: []RoutingMatcher{{Type: "literal", Field: "to", Value: exact}},
			Actions:  []RoutingAction{{Type: "worker", Value: []string{c.WorkerName()}}}}
		if _, err := c.request(ctx, http.MethodPost, p, nil, input, nil, PermissionRoutingWrite); err != nil {
			if PermissionRefused(err) || errors.Is(err, context.Canceled) {
				return out, err
			}
			out.Pending = append(out.Pending, SyncPending{Address: exact, Cause: SyncFailed})
			continue
		}
		counted++
		out.Added = append(out.Added, exact)
	}
	return out, nil
}
