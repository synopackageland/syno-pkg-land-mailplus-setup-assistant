package cloudflare

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func testZone() Zone { return Zone{ID: "zone", Name: "example.test"} }

func TestSendingOnboardDNSVerifyRollback(t *testing.T) {
	ctx := context.Background()
	domain := SendingDomain{ID: "sender", Name: "mail.example.test", Enabled: true}
	required := []DNSFields{{Type: "MX", Name: "cf-bounce.mail.example.test", Content: "route1.mx.cloudflare.net", TTL: 1}}
	preview := DNSCheck{Records: required, Errors: []DNSCheckIssue{{Code: "mx.missing"}}}
	create := post("/zones/zone/email/sending/subdomains", domain)
	create.check = bodyIs(map[string]string{"name": domain.Name})
	c := fixture(t,
		get("/zones/zone", testZone()), get("/zones/zone/email/sending/subdomains", []SendingDomain{}),
		post("/zones/zone/email/sending/subdomains/preview", preview), get("/zones/zone/dns_records", []DNSRecord{}), create,
		get("/zones/zone/email/sending/subdomains/sender/dns", required),
		get("/zones/zone/email/sending/subdomains/sender/dns/status", DNSCheck{Status: "pending"}),
		get("/zones/zone/email/sending/subdomains/sender/dns/status", DNSCheck{Status: "ready"}),
		get("/zones/zone/email/sending/subdomains/sender", domain), del("/zones/zone/email/sending/subdomains/sender"))
	receipt, err := c.OnboardSendingDomain(ctx, "zone", domain.Name)
	if err != nil || receipt.OwnerID != "fixture" || receipt.Domain.ID != "sender" {
		t.Fatalf("onboard: %+v %v", receipt, err)
	}
	records, err := c.SendingDNS(ctx, "zone", domain.ID)
	if err != nil || len(records) != 1 {
		t.Fatalf("required DNS: %+v %v", records, err)
	}
	status, err := c.PollSendingVerification(ctx, "zone", domain.ID, time.Millisecond, 2)
	if err != nil || status.Status != "ready" {
		t.Fatalf("verification: %+v %v", status, err)
	}
	if err := c.RollbackSendingDomain(ctx, receipt); err != nil {
		t.Fatal(err)
	}
}

func TestSendingGuardsAndPollBudget(t *testing.T) {
	t.Run("existing disabled sender cannot be adopted", func(t *testing.T) {
		c := fixture(t, get("/zones/zone", testZone()), get("/zones/zone/email/sending/subdomains",
			[]SendingDomain{{ID: "existing", Name: "mail.example.test", Enabled: false}}))
		_, err := c.OnboardSendingDomain(context.Background(), "zone", "mail.example.test")
		requireKind(t, err, ErrConflict)
	})
	t.Run("foreign DNS blocks onboarding", func(t *testing.T) {
		foreign := ownedDNS("foreign", "old")
		foreign.Type = "MX"
		foreign.Name = "cf-bounce.mail.example.test"
		foreign.Comment = ""
		c := fixture(t, get("/zones/zone", testZone()),
			get("/zones/zone/email/sending/subdomains", []SendingDomain{}),
			post("/zones/zone/email/sending/subdomains/preview", DNSCheck{Records: []DNSFields{foreign.DNSFields}}),
			get("/zones/zone/dns_records", []DNSRecord{foreign}))
		_, err := c.OnboardSendingDomain(context.Background(), "zone", "mail.example.test")
		requireKind(t, err, ErrConflict)
	})
	t.Run("foreign receipt makes no call", func(t *testing.T) {
		c := fixture(t)
		requireKind(t, c.RollbackSendingDomain(context.Background(), SendingReceipt{OwnerID: "other"}), ErrOwnership)
	})
	t.Run("bounded verification does not claim success", func(t *testing.T) {
		c := fixture(t, get("/zones/zone/email/sending/subdomains/sender/dns/status", DNSCheck{Status: "pending"}))
		status, err := c.PollSendingVerification(context.Background(), "zone", "sender", time.Millisecond, 1)
		if err != nil || status.Status != "pending" {
			t.Fatal("pending verification was lost")
		}
	})
	t.Run("cancel during interval", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		step := get("/zones/zone/email/sending/subdomains/sender/dns/status", DNSCheck{Status: "pending"})
		c := fixture(t, step)
		// Cancel only after the first response was decoded, before a second
		// network request can start. An already-canceled context on the request
		// itself is covered by the HTTP transport contract.
		c.http = doerFunc(func(r *http.Request) (*http.Response, error) {
			resp, err := http.DefaultClient.Do(r)
			cancel()
			return resp, err
		})
		_, err := c.PollSendingVerification(ctx, "zone", "sender", time.Second, 2)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
	})
}

func TestRoutingEnableAndExactRuleLifecycle(t *testing.T) {
	ctx := context.Background()
	status := RoutingDomain{ID: "zone", Name: "example.test"}
	enabled := RoutingDomain{ID: "subdomain", Name: "mail.example.test", Enabled: true, Status: "ready"}
	enable := post("/zones/zone/email/routing/dns", enabled)
	// The API field is "name"; an unknown field would enable the apex.
	enable.check = bodyIs(map[string]string{"name": "mail.example.test"})
	rule := RoutingRule{ID: "rule", Name: "syno-home-keeper:fixture", Enabled: true,
		Matchers: []RoutingMatcher{{Type: "literal", Field: "to", Value: "admin@mail.example.test"}},
		Actions:  []RoutingAction{{Type: "worker", Value: []string{"syno-home-keeper-fixture-inbound"}}}}
	catchAll := RoutingRule{ID: "catch", Name: "operator catch-all", Matchers: []RoutingMatcher{{Type: "all"}}}
	create := post("/zones/zone/email/routing/rules", rule)
	input := rule
	input.ID = ""
	create.check = bodyIs(input)
	dns := get("/zones/zone/email/routing/dns", DNSCheck{Errors: []DNSCheckIssue{{Code: "mx.missing"}}})
	dns.check = func(t *testing.T, r *http.Request) {
		if r.URL.Query().Get("subdomain") != "mail.example.test" {
			t.Error("wrong routing DNS subdomain")
		}
	}
	c := fixture(t, get("/zones/zone", testZone()), get("/zones/zone/email/routing", status), dns,
		get("/zones/zone/dns_records", []DNSRecord{}), enable,
		get("/zones/zone/email/routing/rules/catch_all", catchAll),
		get("/zones/zone", testZone()), get("/zones/zone/email/routing/rules", []RoutingRule{}), create,
		get("/zones/zone/email/routing/rules/rule", rule), del("/zones/zone/email/routing/rules/rule"))
	got, err := c.EnableRouting(ctx, "zone", "mail.example.test")
	if err != nil || !got.Enabled {
		t.Fatalf("routing enable: %+v %v", got, err)
	}
	caught, err := c.CatchAll(ctx, "zone")
	if err != nil || caught.Name != catchAll.Name {
		t.Fatal("catch-all read failed")
	}
	created, err := c.CreateRoutingRule(ctx, "zone", rule.Matchers[0].Value, c.WorkerName())
	if err != nil || created.Actions[0].Type != "worker" {
		t.Fatalf("rule create: %+v %v", created, err)
	}
	if err := c.DeleteRoutingRule(ctx, "zone", created.ID); err != nil {
		t.Fatal(err)
	}
}

func TestRoutingRefusalsAndExistingSettings(t *testing.T) {
	t.Run("no catch-all or wildcard writes", func(t *testing.T) {
		c := fixture(t)
		requireKind(t, c.DeleteRoutingRule(context.Background(), "zone", "catch_all"), ErrOwnership)
		for _, address := range []string{"*@mail.example.test", "Name <a@mail.example.test>", "bad\r\n@mail.example.test"} {
			_, err := c.CreateRoutingRule(context.Background(), "zone", address, c.WorkerName())
			requireKind(t, err, ErrInvalid)
		}
	})
	t.Run("foreign rule cannot be deleted", func(t *testing.T) {
		c := fixture(t, get("/zones/zone/email/routing/rules/foreign", RoutingRule{ID: "foreign", Name: "somebody else"}))
		requireKind(t, c.DeleteRoutingRule(context.Background(), "zone", "foreign"), ErrOwnership)
	})
	t.Run("apex enable names the zone", func(t *testing.T) {
		enable := post("/zones/zone/email/routing/dns", RoutingDomain{Name: "example.test", Enabled: true})
		enable.check = bodyIs(map[string]string{"name": "example.test"})
		c := fixture(t, get("/zones/zone", testZone()), get("/zones/zone/email/routing", RoutingDomain{}),
			get("/zones/zone/email/routing/dns", DNSCheck{}), get("/zones/zone/dns_records", []DNSRecord{}), enable)
		if _, err := c.EnableRouting(context.Background(), "zone", ""); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("owned rules: drift under our name is refused", func(t *testing.T) {
		drift := RoutingRule{ID: "x", Name: "syno-home-keeper:fixture", Matchers: []RoutingMatcher{{Type: "all"}},
			Actions: []RoutingAction{{Type: "worker", Value: []string{"syno-home-keeper-fixture-inbound"}}}}
		c := fixture(t, get("/zones/zone/email/routing/rules", []RoutingRule{drift}))
		_, err := c.OwnedRoutingRules(context.Background(), "zone")
		requireKind(t, err, ErrOwnership)
	})
	t.Run("already enabled does not write", func(t *testing.T) {
		c := fixture(t, get("/zones/zone", testZone()),
			get("/zones/zone/email/routing", RoutingDomain{Name: "example.test", Enabled: true}))
		if _, err := c.EnableRouting(context.Background(), "zone", ""); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("foreign MX does not get replaced", func(t *testing.T) {
		mx := ownedDNS("foreign", "mx.operator.test")
		mx.Name, mx.Type, mx.Comment = "example.test", "MX", ""
		c := fixture(t, get("/zones/zone", testZone()), get("/zones/zone/email/routing", RoutingDomain{}),
			get("/zones/zone/email/routing/dns", DNSCheck{}), get("/zones/zone/dns_records", []DNSRecord{mx}))
		_, err := c.EnableRouting(context.Background(), "zone", "")
		requireKind(t, err, ErrConflict)
	})
	t.Run("exact address conflict does not shadow existing rule", func(t *testing.T) {
		c := fixture(t, get("/zones/zone", testZone()),
			get("/zones/zone/email/routing/rules", []RoutingRule{{Matchers: []RoutingMatcher{{Type: "literal", Field: "to", Value: "admin@mail.example.test"}}}}))
		_, err := c.CreateRoutingRule(context.Background(), "zone", "admin@mail.example.test", c.WorkerName())
		requireKind(t, err, ErrConflict)
	})
}

func TestEnsureRoutingRules(t *testing.T) {
	ctx := context.Background()
	owned := func(id, address string) RoutingRule {
		return RoutingRule{ID: id, Name: "syno-home-keeper:fixture", Enabled: true,
			Matchers: []RoutingMatcher{{Type: "literal", Field: "to", Value: address}},
			Actions:  []RoutingAction{{Type: "worker", Value: []string{"syno-home-keeper-fixture-inbound"}}}}
	}
	t.Run("creates only what is missing", func(t *testing.T) {
		create := post("/zones/zone/email/routing/rules", owned("new", "info@mail.example.test"))
		input := owned("", "info@mail.example.test")
		create.check = bodyIs(input)
		c := fixture(t, get("/zones/zone", testZone()),
			get("/zones/zone/email/routing/rules", []RoutingRule{owned("r1", "Admin@mail.example.test")}), create)
		if err := c.EnsureRoutingRules(ctx, "zone", []string{"admin@mail.example.test", "info@mail.example.test"}, c.WorkerName()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("another owner's rule on an address is a conflict", func(t *testing.T) {
		foreign := owned("f", "admin@mail.example.test")
		foreign.Name = "operator"
		foreign.Actions = []RoutingAction{{Type: "forward", Value: []string{"x@example.org"}}}
		c := fixture(t, get("/zones/zone", testZone()), get("/zones/zone/email/routing/rules", []RoutingRule{foreign}))
		requireKind(t, c.EnsureRoutingRules(ctx, "zone", []string{"admin@mail.example.test"}, c.WorkerName()), ErrConflict)
	})
	t.Run("an own rule for an address not asked for is drift", func(t *testing.T) {
		c := fixture(t, get("/zones/zone", testZone()),
			get("/zones/zone/email/routing/rules", []RoutingRule{owned("r1", "admin@mail.example.test"), owned("r2", "old@mail.example.test")}))
		requireKind(t, c.EnsureRoutingRules(ctx, "zone", []string{"admin@mail.example.test"}, c.WorkerName()), ErrOwnership)
	})
	t.Run("a rule under our name of another shape is drift", func(t *testing.T) {
		bad := owned("r1", "admin@mail.example.test")
		bad.Actions[0].Value = []string{"someone-else"}
		c := fixture(t, get("/zones/zone", testZone()), get("/zones/zone/email/routing/rules", []RoutingRule{bad}))
		requireKind(t, c.EnsureRoutingRules(ctx, "zone", []string{"admin@mail.example.test"}, c.WorkerName()), ErrOwnership)
	})
	t.Run("only this owner's Worker and addresses in the zone", func(t *testing.T) {
		c := fixture(t)
		requireKind(t, c.EnsureRoutingRules(ctx, "zone", []string{"admin@mail.example.test"}, "other-worker"), ErrOwnership)
		c = fixture(t, get("/zones/zone", testZone()))
		requireKind(t, c.EnsureRoutingRules(ctx, "zone", []string{"admin@other.test"}, c.WorkerName()), ErrInvalid)
	})
}

func TestForbiddenWithoutCodeIsNotAPermissionRefusal(t *testing.T) {
	c := fixture(t, exchange{method: "GET", path: "/zones/zone/email/routing/rules", status: 403})
	_, err := c.ListRoutingRules(context.Background(), "zone")
	if err == nil || HTTPStatus(err) != 403 || PermissionRefused(err) {
		t.Fatalf("403 without a code: %v", err)
	}
}

func TestLeftoverRuleTakeOverAndReturn(t *testing.T) {
	ctx := context.Background()
	left := func(owner string) RoutingRule {
		return RoutingRule{ID: "old", Name: "syno-home-keeper:" + owner, Enabled: true, Priority: 3,
			Matchers: []RoutingMatcher{{Type: "literal", Field: "to", Value: "admin@mail.example.test"}},
			Actions:  []RoutingAction{{Type: "worker", Value: []string{"syno-home-keeper-" + owner + "-inbound"}}}}
	}
	if owner, ok := LeftoverOwner(left("hk-earlier")); !ok || owner != "hk-earlier" {
		t.Fatal("leftover not recognized")
	}
	foreign := left("hk-earlier")
	foreign.Actions[0].Value = []string{"someone-else"}
	if _, ok := LeftoverOwner(foreign); ok {
		t.Fatal("a rule to another Worker is not ours")
	}
	t.Run("take over", func(t *testing.T) {
		put := exchange{method: "PUT", path: "/zones/zone/email/routing/rules/old", result: left("fixture")}
		want := left("fixture")
		want.ID = ""
		put.check = bodyIs(want)
		c := fixture(t, get("/zones/zone/email/routing/rules/old", left("hk-earlier")), put,
			get("/zones/zone/email/routing/rules/old", left("fixture")))
		if err := c.TakeOverRoutingRule(ctx, "zone", "old", "admin@mail.example.test", "hk-earlier"); err != nil {
			t.Fatal(err)
		}
		// Already ours (a lost reply): nothing is sent again.
		if err := c.TakeOverRoutingRule(ctx, "zone", "old", "admin@mail.example.test", "hk-earlier"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a rule that changed meanwhile is refused", func(t *testing.T) {
		c := fixture(t, get("/zones/zone/email/routing/rules/old", left("hk-third")))
		requireKind(t, c.TakeOverRoutingRule(ctx, "zone", "old", "admin@mail.example.test", "hk-earlier"), ErrOwnership)
		c = fixture(t, get("/zones/zone/email/routing/rules/old", foreign))
		requireKind(t, c.TakeOverRoutingRule(ctx, "zone", "old", "admin@mail.example.test", "hk-earlier"), ErrOwnership)
	})
	t.Run("give back", func(t *testing.T) {
		put := exchange{method: "PUT", path: "/zones/zone/email/routing/rules/old", result: left("hk-earlier")}
		want := left("hk-earlier")
		want.ID = ""
		put.check = bodyIs(want)
		c := fixture(t, get("/zones/zone/email/routing/rules/old", left("fixture")), put)
		if err := c.ReturnRoutingRule(ctx, "zone", "old", "admin@mail.example.test", "hk-earlier"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestEnableRoutingPassesOverRoutingsOwnRecords(t *testing.T) {
	mx := ownedDNS("mx", "route1.mx.cloudflare.net")
	mx.Name, mx.Type, mx.Comment = "mail.example.test", "MX", ""
	mx.Meta.EmailRouting = true
	spf := ownedDNS("spf", `"v=spf1 include:_spf.mx.cloudflare.net ~all"`)
	spf.Name, spf.Type, spf.Comment = "mail.example.test", "TXT", ""
	enable := post("/zones/zone/email/routing/dns", RoutingDomain{Name: "mail.example.test", Enabled: true})
	c := fixture(t, get("/zones/zone", testZone()), get("/zones/zone/email/routing", RoutingDomain{}),
		get("/zones/zone/email/routing/dns", DNSCheck{}), get("/zones/zone/dns_records", []DNSRecord{mx, spf}), enable)
	if _, err := c.EnableRouting(context.Background(), "zone", "mail.example.test"); err != nil {
		t.Fatal(err)
	}
}

// A2: a rule is a leftover of this package only in its exact shape: our name
// with a valid owner, one literal "to" matcher with an exact address, one
// Worker action to that same owner's Worker. Every other shape is foreign.
func TestLeftoverOwnerNeedsTheExactLiteralShape(t *testing.T) {
	base := func() RoutingRule {
		return RoutingRule{ID: "old", Name: "syno-home-keeper:hk-earlier", Enabled: true,
			Matchers: []RoutingMatcher{{Type: "literal", Field: "to", Value: "admin@mail.example.test"}},
			Actions:  []RoutingAction{{Type: "worker", Value: []string{"syno-home-keeper-hk-earlier-inbound"}}}}
	}
	if owner, ok := LeftoverOwner(base()); !ok || owner != "hk-earlier" {
		t.Fatalf("exact shape: %q %v", owner, ok)
	}
	cases := map[string]func(*RoutingRule){
		"another name":           func(r *RoutingRule) { r.Name = "home-keeper:hk-earlier" },
		"no owner":               func(r *RoutingRule) { r.Name = "syno-home-keeper:" },
		"owner with a space":     func(r *RoutingRule) { r.Name = "syno-home-keeper:hk earlier" },
		"matcher type all":       func(r *RoutingRule) { r.Matchers[0] = RoutingMatcher{Type: "all"} },
		"matcher type regex":     func(r *RoutingRule) { r.Matchers[0].Type = "regex" },
		"matcher field from":     func(r *RoutingRule) { r.Matchers[0].Field = "from" },
		"no matcher":             func(r *RoutingRule) { r.Matchers = nil },
		"two matchers":           func(r *RoutingRule) { r.Matchers = append(r.Matchers, r.Matchers[0]) },
		"wildcard value":         func(r *RoutingRule) { r.Matchers[0].Value = "*@mail.example.test" },
		"not an address":         func(r *RoutingRule) { r.Matchers[0].Value = "mail.example.test" },
		"forward action":         func(r *RoutingRule) { r.Actions[0].Type = "forward" },
		"two actions":            func(r *RoutingRule) { r.Actions = append(r.Actions, r.Actions[0]) },
		"two Workers":            func(r *RoutingRule) { r.Actions[0].Value = append(r.Actions[0].Value, "x") },
		"another owner's Worker": func(r *RoutingRule) { r.Actions[0].Value = []string{"syno-home-keeper-hk-third-inbound"} },
	}
	for name, change := range cases {
		r := base()
		change(&r)
		if owner, ok := LeftoverOwner(r); ok {
			t.Errorf("%s: taken as a leftover of %q", name, owner)
		}
	}
}

// Email Sending adds _dmarc.<name> ("v=DMARC1; p=reject;") on
// enabling and leaves it after the sender is deleted. The receipt records
// that no _dmarc existed before; the rollback deletes the record only while
// it is the one record at that name with unchanged content.
func TestSendingRollbackRemovesOnlyTheDMARCItAdded(t *testing.T) {
	ctx := context.Background()
	domain := SendingDomain{ID: "sender", Name: "mail.example.test", Enabled: true}
	added := DNSFields{Type: "TXT", Name: "_dmarc.mail.example.test", Content: `"v=DMARC1; p=reject;"`, TTL: 1}
	preview := DNSCheck{Records: []DNSFields{{Type: "MX", Name: "cf-bounce.mail.example.test", Content: "route1.mx.cloudflare.net", TTL: 1}, added}}
	onboard := func(before ...DNSRecord) []exchange {
		return []exchange{get("/zones/zone", testZone()), get("/zones/zone/email/sending/subdomains", []SendingDomain{}),
			post("/zones/zone/email/sending/subdomains/preview", preview), get("/zones/zone/dns_records", append([]DNSRecord{}, before...)),
			post("/zones/zone/email/sending/subdomains", domain)}
	}
	deleteSender := []exchange{get("/zones/zone/email/sending/subdomains/sender", domain), del("/zones/zone/email/sending/subdomains/sender")}
	left := func(id, content string) DNSRecord {
		return DNSRecord{ID: id, DNSFields: DNSFields{Type: "TXT", Name: "_dmarc.mail.example.test", Content: content, TTL: 1}}
	}
	seq := func(parts ...[]exchange) []exchange {
		out := []exchange{}
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	t.Run("added and unchanged: deleted", func(t *testing.T) {
		c := fixture(t, seq(onboard(), deleteSender,
			[]exchange{get("/zones/zone/dns_records", []DNSRecord{left("dmarc1", `"v=DMARC1; p=reject;"`)}), del("/zones/zone/dns_records/dmarc1")})...)
		receipt, err := c.OnboardSendingDomain(ctx, "zone", domain.Name)
		if err != nil || receipt.DMARC == nil || receipt.DMARC.Name != "_dmarc.mail.example.test" {
			t.Fatalf("receipt: %+v %v", receipt, err)
		}
		if err := c.RollbackSendingDomain(ctx, receipt); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("existed before: not recorded, never touched", func(t *testing.T) {
		c := fixture(t, seq(onboard(left("mine", `"v=DMARC1; p=none"`)), deleteSender)...)
		receipt, err := c.OnboardSendingDomain(ctx, "zone", domain.Name)
		if err != nil || receipt.DMARC != nil {
			t.Fatalf("receipt: %+v %v", receipt, err)
		}
		if err := c.RollbackSendingDomain(ctx, receipt); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("changed content: kept", func(t *testing.T) {
		c := fixture(t, seq(onboard(), deleteSender, []exchange{get("/zones/zone/dns_records", []DNSRecord{left("dmarc1", `"v=DMARC1; p=quarantine;"`)})})...)
		receipt, _ := c.OnboardSendingDomain(ctx, "zone", domain.Name)
		if err := c.RollbackSendingDomain(ctx, receipt); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("another record at the name: kept", func(t *testing.T) {
		c := fixture(t, seq(onboard(), deleteSender, []exchange{get("/zones/zone/dns_records",
			[]DNSRecord{left("dmarc1", `"v=DMARC1; p=reject;"`), left("dmarc2", `"v=DMARC1; p=reject;"`)})})...)
		receipt, _ := c.OnboardSendingDomain(ctx, "zone", domain.Name)
		if err := c.RollbackSendingDomain(ctx, receipt); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("sender already gone: the record is still removed", func(t *testing.T) {
		c := fixture(t, exchange{method: http.MethodGet, path: "/zones/zone/email/sending/subdomains/sender", status: 404},
			get("/zones/zone/dns_records", []DNSRecord{left("dmarc1", "v=DMARC1; p=reject;")}), del("/zones/zone/dns_records/dmarc1"))
		receipt := SendingReceipt{OwnerID: "fixture", ZoneID: "zone", Domain: domain, DMARC: &SendingDMARC{Name: "_dmarc.mail.example.test", Content: `"v=DMARC1; p=reject;"`}}
		if err := c.RollbackSendingDomain(ctx, receipt); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a receipt from before build 52 keeps every record", func(t *testing.T) {
		c := fixture(t, deleteSender...)
		if err := c.RollbackSendingDomain(ctx, SendingReceipt{OwnerID: "fixture", ZoneID: "zone", Domain: domain}); err != nil {
			t.Fatal(err)
		}
	})
}
