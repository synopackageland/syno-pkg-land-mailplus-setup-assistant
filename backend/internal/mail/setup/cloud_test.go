package setup

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

// viaCloudflare: the domain comes from the sign-in and the Cloudflare route
// was chosen, so the checks cannot allow a direct path.
var viaCloudflare = Answers{Source: SourceCloudflare, Route: RouteCloudflare}

// cloudYes: the domain comes from the sign-in, and the own-IP route was confirmed.
var cloudYes = Answers{Source: SourceCloudflare, Route: RouteDirect}

// Where the domain comes from decides no mail path: the route and the
// checks do, exactly as for the own-domain source.
func TestCloudflareSourceDoesNotForceThePath(t *testing.T) {
	for _, tc := range []struct {
		a             Answers
		send, receive Branch
	}{
		{cloudYes, DirectSend, DirectReceive},
		{viaCloudflare, RelaySend, RoutingReceive},
		{Answers{Source: SourceCloudflare}, RelaySend, RoutingReceive}, // no route is not the own-IP route
	} {
		d := Decide(healthy(), Both, tc.a)
		if d.Send != tc.send || d.Receive != tc.receive {
			t.Fatalf("%+v: %+v", tc.a, d)
		}
		own := tc.a
		own.Source = SourceOwn
		if o := Decide(healthy(), Both, own); o.Send != d.Send || o.Receive != d.Receive || o.Reason != d.Reason || len(o.SendWhy) != len(d.SendWhy) {
			t.Fatalf("source changed the decision: %+v vs %+v", o, d)
		}
	}
}

func TestSourceValues(t *testing.T) {
	if (Answers{Source: "direct"}).Valid() {
		t.Fatal("unknown source accepted")
	}
	if !cloudYes.Valid() || !(Answers{Source: SourceOwn, Route: RouteDirect}).Valid() {
		t.Fatal("valid sources refused")
	}
	if got := (Answers{Source: SourceOwn, Route: RouteDirect}).For(Send); got.Source != "" || got.Route != RouteDirect {
		t.Fatalf("own source must normalize to the default: %+v", got)
	}
	if got := cloudYes.For(Send); got != cloudYes {
		t.Fatalf("cloudflare source keeps its route: %+v", got)
	}
}

func TestSignInChoosesTheOnlyAccountSilently(t *testing.T) {
	dir := newDirectory()
	w := New(Options{Directory: dir})
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	v, e := w.Connect(ctx, env, owner, flow.ID, fixtureToken)
	if e != nil || v.AccountID != testAccount || len(v.Zones) != 1 || v.Zones[0].Name != "example.test" || v.Zones[0].Status != "active" || len(v.Missing) != 0 {
		t.Fatalf("view: %+v %v", v, e)
	}
	// The directory resolved the sealed token; the flow record holds only the reference.
	if dir.tokens[0] != "fixture-credential-must-never-appear" {
		t.Fatalf("token: %q", dir.tokens[0])
	}
	assertNoCredential(t, env)
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), "secret:") || strings.Contains(string(raw), "fixture-credential") {
		t.Fatalf("the reply names the token: %s", raw)
	}
}

func assertNoCredential(t *testing.T, env core.Env) {
	t.Helper()
	kv := env.KV.(*memoryKV)
	kv.mu.Lock()
	defer kv.mu.Unlock()
	for k, v := range kv.values {
		if strings.Contains(string(v), "fixture-credential") {
			t.Fatalf("%s holds the token value", k)
		}
	}
}

func TestSignInSeveralAccountsAreAChoice(t *testing.T) {
	dir := newDirectory()
	other := strings.Repeat("c", 32)
	dir.accounts = append(dir.accounts, CloudAccount{ID: other, Name: "Work"})
	dir.zones[other] = []CloudZone{{ID: strings.Repeat("d", 32), Name: "work.test", Status: "active"}}
	w := New(Options{Directory: dir})
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	v, e := w.Connect(ctx, env, owner, flow.ID, fixtureToken)
	if e != nil || len(v.Accounts) != 2 || v.AccountID != "" || len(v.Zones) != 0 {
		t.Fatalf("several: %+v %v", v, e)
	}
	if v, e = w.Zones(ctx, env, owner, flow.ID, other, ""); e != nil || v.AccountID != other || len(v.Zones) != 1 || v.Zones[0].Name != "work.test" {
		t.Fatalf("zones: %+v %v", v, e)
	}
	// Only an account the sign-in listed: no typed ID.
	if _, e = w.Zones(ctx, env, owner, flow.ID, strings.Repeat("e", 32), ""); !errors.Is(e, ErrInvalid) {
		t.Fatalf("unlisted account: %v", e)
	}
}

func TestSignInWithNoAccountListsNothing(t *testing.T) {
	dir := newDirectory()
	dir.accounts = nil
	w := New(Options{Directory: dir})
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	v, e := w.Connect(ctx, env, owner, flow.ID, fixtureToken)
	if e != nil || len(v.Accounts) != 0 || v.AccountID != "" {
		t.Fatalf("none: %+v %v", v, e)
	}
}

func TestSignInInvalidTokenKeepsNothing(t *testing.T) {
	dir := newDirectory()
	dir.err = ErrTokenInvalid
	w := New(Options{Directory: dir})
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	if _, e := w.Connect(ctx, env, owner, flow.ID, fixtureToken); !errors.Is(e, ErrTokenInvalid) {
		t.Fatalf("invalid: %v", e)
	}
	if f, _ := w.load(ctx, env, owner, flow.ID); f.Cloud != nil {
		t.Fatalf("kept: %+v", f.Cloud)
	}
	// Anything else is unknown, never a guess.
	dir.err = errors.New("cloudflare transport")
	if _, e := w.Connect(ctx, env, owner, flow.ID, fixtureToken); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("transport: %v", e)
	}
}

func TestSignInNamesMissingPermissions(t *testing.T) {
	dir := newDirectory()
	dir.probe = []string{PermSendingEdit, "unknownCode", PermDNSEdit}
	w, _ := cloudRouteWizard(dir)
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	if _, e := w.Connect(ctx, env, owner, flow.ID, fixtureToken); e != nil {
		t.Fatal(e)
	}
	v, e := w.Zones(ctx, env, owner, flow.ID, testAccount, testZone)
	if e != nil || strings.Join(v.Missing, ",") != PermDNSEdit+","+PermSendingEdit {
		t.Fatalf("missing (known codes, fixed order): %+v %v", v, e)
	}
	// Before any decision only DNS is read: a direct path never needs Email Sending.
	if dir.calls[len(dir.calls)-1] != "probe:"+testZone {
		t.Fatalf("calls: %v", dir.calls)
	}
	// A refused permission blocks the detection until the token is replaced.
	if _, e := w.Detect(ctx, env, owner, flow.ID, Send, "example.test", viaCloudflare, false); !errors.Is(e, ErrStale) {
		t.Fatalf("detect with a missing permission: %v", e)
	}
	// Zone Read refused at sign-in: no account is chosen, nothing is listed.
	dir.missing, dir.probe = []string{PermZoneRead}, nil
	if v, e = w.Connect(ctx, env, owner, flow.ID, fixtureToken); e != nil || v.AccountID != "" || len(v.Missing) != 1 || v.Missing[0] != PermZoneRead {
		t.Fatalf("zone read: %+v %v", v, e)
	}
	dir.missing = nil
	if err := signIn(w, ctx, env, owner, flow.ID); err != nil {
		t.Fatal(err)
	}
	// The decision takes the relay: choosing the zone again reads Email Sending,
	// and a refusal there stops the preview until the token is replaced.
	detectDone(t, w, env, flow.ID, Send, "example.test", viaCloudflare)
	dir.probe = []string{PermSendingEdit}
	if v, e = w.Zones(ctx, env, owner, flow.ID, testAccount, testZone); e != nil || dir.calls[len(dir.calls)-1] != "probe:"+testZone+":send" || len(v.Missing) != 1 {
		t.Fatalf("relay probe: %v %+v %v", dir.calls, v, e)
	}
	if _, e = w.Preview(ctx, env, owner, flow.ID, Configuration{}); !errors.Is(e, ErrStale) {
		t.Fatalf("preview with Email Sending refused: %v", e)
	}
	// A direct decision ("Yes" everywhere) reads DNS only.
	dir.probe = nil
	if err := signIn(w, ctx, env, owner, flow.ID); err != nil {
		t.Fatal(err)
	}
	detectDone(t, w, env, flow.ID, Send, "example.test", cloudYes)
	if _, e = w.Zones(ctx, env, owner, flow.ID, testAccount, testZone); e != nil || dir.calls[len(dir.calls)-1] != "probe:"+testZone {
		t.Fatalf("direct probe: %v %v", dir.calls, e)
	}
}

// Path B with "Yes" answers takes the direct path: DNS records through the
// sign-in's token on the chosen zone, no relay and no SMTP token.
func TestCloudflareSourceDirectPathUsesTheSignIn(t *testing.T) {
	cloud := &fakeCloud{restorable: true, value: "original"}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: cloud, Directory: newDirectory(), Verifier: verifier{result: Verification{Readback: true, Delivery: true}}})
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	if err := signIn(w, ctx, env, owner, flow.ID); err != nil {
		t.Fatal(err)
	}
	b := detectDone(t, w, env, flow.ID, Send, "example.test", cloudYes).Branch
	if b.Kind != "configure" || b.NeedsAccount || b.Paths[0].Branch != DirectSend {
		t.Fatalf("branch: %+v", b)
	}
	p, e := w.Preview(ctx, env, owner, flow.ID, Configuration{})
	for e == nil && p.Pending {
		time.Sleep(time.Millisecond)
		p, e = w.PollPreview(ctx, env, owner, flow.ID)
	}
	if e != nil || len(p.Changes) != 3 {
		t.Fatalf("preview: %+v %v", p, e)
	}
	f, _ := w.load(ctx, env, owner, flow.ID)
	if r := f.Plan.Request; !strings.HasPrefix(r.TokenRef, "secret:mail.setup."+flow.ID+".token.") || r.SMTPTokenRef != "" || r.AccountID != testAccount || r.ZoneID != testZone {
		t.Fatalf("request: %+v", r)
	}
}

func TestPendingZoneCannotBeChosen(t *testing.T) {
	dir := newDirectory()
	dir.zones[testAccount] = []CloudZone{{ID: testZone, Name: "example.test", Status: "pending"}}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: &fakeCloud{}, Directory: dir, Verifier: verifier{}})
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	v, e := w.Connect(ctx, env, owner, flow.ID, fixtureToken)
	if e != nil || len(v.Zones) != 1 || v.Zones[0].Status != "pending" {
		t.Fatalf("listed with its status: %+v %v", v, e)
	}
	if _, e = w.Zones(ctx, env, owner, flow.ID, testAccount, testZone); !errors.Is(e, ErrInvalid) {
		t.Fatalf("pending chosen: %v", e)
	}
	if _, e = w.Detect(ctx, env, owner, flow.ID, Send, "example.test", viaCloudflare, false); !errors.Is(e, ErrStale) {
		t.Fatalf("detect without a zone: %v", e)
	}
	// The nameservers changed: checking again lists it active, and it can be chosen.
	dir.zones[testAccount][0].Status = "active"
	if v, e = w.Zones(ctx, env, owner, flow.ID, testAccount, testZone); e != nil || v.ZoneID != testZone {
		t.Fatalf("active: %+v %v", v, e)
	}
}

func TestNoZonesThenCheckAgain(t *testing.T) {
	dir := newDirectory()
	dir.zones = map[string][]CloudZone{}
	w := New(Options{Directory: dir})
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	v, e := w.Connect(ctx, env, owner, flow.ID, fixtureToken)
	if e != nil || v.AccountID != testAccount || len(v.Zones) != 0 {
		t.Fatalf("no zones: %+v %v", v, e)
	}
	// Registered meanwhile: Check again lists the account's zones once more.
	dir.zones[testAccount] = []CloudZone{{ID: testZone, Name: "example.test", Status: "active"}}
	if v, e = w.Zones(ctx, env, owner, flow.ID, testAccount, ""); e != nil || len(v.Zones) != 1 {
		t.Fatalf("again: %+v %v", v, e)
	}
}

// cloudPlan is a Cloudflare, relay and MailPlus side that records the plan
// request: enough for the relay send path's preview.
type cloudPlan struct {
	*fakeCloud
	request PlanRequest
}

func (c *cloudPlan) RequiredPermissions(r PlanRequest) ([]Permission, error) {
	return []Permission{{Scope: "zone", Resource: r.ZoneID, Name: "Zone Read"}, {Scope: "zone", Resource: r.ZoneID, Name: "DNS Write"},
		{Scope: "account", Resource: r.AccountID, Name: "Email Sending Write"}}, nil
}
func (c *cloudPlan) Plan(_ context.Context, _ core.Env, r PlanRequest) (Prepared, error) {
	c.request = r
	ps, _ := c.RequiredPermissions(r)
	return Prepared{Restorable: true, Permissions: ps, Changes: []core.Change{{ID: "cloudflare.sending", Target: "cloudflare.sending",
		ActionKey: "mail.setup.change.cloudflare.sending", Params: map[string]string{"domain": r.Domain}, Before: "missing", After: "sender"}}}, nil
}

type fakeRelay struct{ *fakeCloud }

func (fakeRelay) Plan(_ context.Context, _ core.Env, r PlanRequest) (Prepared, error) {
	if r.SMTPTokenRef == "" {
		return Prepared{}, ErrUnavailable
	}
	return Prepared{Restorable: true, Changes: []core.Change{{ID: "relay.configure", Target: "homekeeper.relay",
		ActionKey: "mail.setup.change.relay.configure", Params: map[string]string{"domain": r.Domain}, Before: "disabled", After: "enabled"}}}, nil
}

type fakeMailPlus struct{ *fakeCloud }

func (fakeMailPlus) Plan(_ context.Context, _ core.Env, r PlanRequest, _ []core.Change) (Prepared, error) {
	return Prepared{Restorable: true, Changes: []core.Change{
		{ID: "mailplus.delivery", Target: "mailplus.delivery", ActionKey: "mail.setup.change.mailplus.delivery", Params: map[string]string{"domain": r.Domain}, Before: "none", After: "relay"},
		{ID: "mailplus.dkim", Target: "mailplus.dkim", ActionKey: "mail.setup.change.mailplus.dkim", Params: map[string]string{"domain": r.Domain}, Before: "on", After: "off"},
	}}, nil
}

func cloudRouteWizard(dir *fakeDirectory) (*Wizard, *cloudPlan) {
	c := &cloudPlan{fakeCloud: &fakeCloud{restorable: true}}
	return New(Options{Detector: source{state: healthy()}, Cloudflare: c, Directory: dir, Relay: fakeRelay{&fakeCloud{}},
		MailPlus: fakeMailPlus{&fakeCloud{}}, Verifier: verifier{result: Verification{Readback: true, Delivery: true}}}), c
}

// detectDone polls the detection until it is done.
func detectDone(t *testing.T, w *Wizard, env core.Env, id string, intent Intent, domain string, a Answers) DetectView {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(time.Second)
	for {
		v, e := w.Detect(ctx, env, owner, id, intent, domain, a, false)
		if e != nil {
			t.Fatalf("detect: %v", e)
		}
		if v.Done {
			return v
		}
		if time.Now().After(deadline) {
			t.Fatal("detection did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}

// Path B end to end: sign in, choose the zone, detect, configure, preview.
// No Account ID, Zone ID or token is asked again: the plan uses the sign-in's.
func TestCloudflareSourcePreviewUsesTheSignIn(t *testing.T) {
	w, cloud := cloudRouteWizard(newDirectory())
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	if err := signIn(w, ctx, env, owner, flow.ID); err != nil {
		t.Fatal(err)
	}
	v := detectDone(t, w, env, flow.ID, Send, "example.test", viaCloudflare)
	b := v.Branch
	if b.Kind != "configure" || b.NeedsAccount || len(b.Fields) != 0 || len(b.Paths) != 1 || b.Paths[0].Branch != RelaySend ||
		b.Paths[0].Why[0] != "mail.setup.why.routeCloudflare" {
		t.Fatalf("branch: %+v", b)
	}
	// The browser never answers with typed IDs: Permissions is not needed.
	p, e := w.Preview(ctx, env, owner, flow.ID, Configuration{})
	for e == nil && p.Pending {
		time.Sleep(time.Millisecond)
		p, e = w.PollPreview(ctx, env, owner, flow.ID)
	}
	if e != nil || len(p.Changes) != 4 {
		t.Fatalf("preview: %+v %v", p, e)
	}
	r := cloud.request
	if r.AccountID != testAccount || r.ZoneID != testZone || !strings.HasPrefix(r.TokenRef, "secret:mail.setup."+flow.ID+".token.") || r.SMTPTokenRef != r.TokenRef || r.Decision.Send != RelaySend {
		t.Fatalf("request: %+v", r)
	}
	assertNoCredential(t, env)
	// Resume after apply keeps the route.
	if _, e = w.Apply(ctx, env, owner, flow.ID); e != nil {
		t.Fatal(e)
	}
	w.Wait()
	again, e := w.Start(ctx, env, owner)
	if e != nil || !again.Resume || again.Source != SourceCloudflare || again.Domain != "example.test" {
		t.Fatalf("resume: %+v %v", again, e)
	}
}

// Path B: choosing the zone lists MailPlus Server's domains in it (label
// boundary, any depth, sorted); the mail domain is one of them, never the
// apex by default.
func TestCloudflareSourceMailDomainIsPickedFromMailPlus(t *testing.T) {
	ctx := context.Background()
	withDomains := func(names ...string) source {
		ds := []detect.Domain{}
		for i, n := range names {
			ds = append(ds, detect.Domain{ID: i + 1, Name: n})
		}
		st := healthy()
		st.Domains = detect.Fact(ds)
		return source{state: st, domain: true}
	}
	t.Run("the zone's domains, any depth", func(t *testing.T) {
		w, _ := cloudRouteWizard(newDirectory())
		w.options.Detector = withDomains("mail.example.test", "other.test", "a.b.example.test", "notexample.test", "example.test")
		env := fakeEnv()
		flow, _ := w.Start(ctx, env, owner)
		if _, err := w.Connect(ctx, env, owner, flow.ID, fixtureToken); err != nil {
			t.Fatal(err)
		}
		v, err := w.Zones(ctx, env, owner, flow.ID, testAccount, testZone)
		if err != nil || v.MailDomainsState != "read" || strings.Join(v.MailDomains, ",") != "a.b.example.test,example.test,mail.example.test" {
			t.Fatalf("mail domains: %+v %v", v, err)
		}
		for _, ok := range []string{"mail.example.test", "a.b.example.test", "example.test"} {
			if _, e := w.Detect(ctx, env, owner, flow.ID, Send, ok, viaCloudflare, false); e != nil {
				t.Fatalf("%s: %v", ok, e)
			}
		}
		for _, bad := range []string{"other.test", "notexample.test"} {
			if _, e := w.Detect(ctx, env, owner, flow.ID, Send, bad, viaCloudflare, false); !errors.Is(e, ErrInvalid) {
				t.Fatalf("%s: %v", bad, e)
			}
		}
		// a name in the zone MailPlus Server lacks is a domain the
		// setup creates when it sends; receiving alone needs an existing one.
		if _, e := w.Detect(ctx, env, owner, flow.ID, Receive, "x.example.test", viaCloudflare, false); !errors.Is(e, ErrInvalid) {
			t.Fatalf("receive into a new domain: %v", e)
		}
		for _, intent := range []Intent{Send, Both} {
			v, e := w.Detect(ctx, env, owner, flow.ID, intent, "x.example.test", viaCloudflare, false)
			for i := 0; e == nil && !v.Done && i < 200; i++ {
				time.Sleep(5 * time.Millisecond)
				v, e = w.Detect(ctx, env, owner, flow.ID, intent, "x.example.test", viaCloudflare, false)
			}
			if e != nil || !v.Done || v.Branch == nil || !v.Branch.CreatesDomain {
				t.Fatalf("%s into a new domain: %+v %v", intent, v.Branch, e)
			}
		}
	})
	t.Run("none in the zone is said, and the apex is not assumed", func(t *testing.T) {
		w, _ := cloudRouteWizard(newDirectory())
		w.options.Detector = withDomains("sample-nas.test")
		env := fakeEnv()
		flow, _ := w.Start(ctx, env, owner)
		_, _ = w.Connect(ctx, env, owner, flow.ID, fixtureToken)
		v, err := w.Zones(ctx, env, owner, flow.ID, testAccount, testZone)
		if err != nil || v.MailDomainsState != "read" || len(v.MailDomains) != 0 {
			t.Fatalf("none: %+v %v", v, err)
		}
		// The apex is not preselected (the zone step offers a new domain
		// instead); receiving alone cannot use a domain MailPlus lacks.
		if _, e := w.Detect(ctx, env, owner, flow.ID, Receive, "example.test", viaCloudflare, false); !errors.Is(e, ErrInvalid) {
			t.Fatalf("apex accepted: %v", e)
		}
	})
	t.Run("an unread list allows nothing", func(t *testing.T) {
		w, _ := cloudRouteWizard(newDirectory())
		st := healthy()
		st.Domains = detect.Unavailable[[]detect.Domain]()
		w.options.Detector = source{state: st}
		env := fakeEnv()
		flow, _ := w.Start(ctx, env, owner)
		_, _ = w.Connect(ctx, env, owner, flow.ID, fixtureToken)
		v, err := w.Zones(ctx, env, owner, flow.ID, testAccount, testZone)
		if err != nil || v.MailDomainsState != "unknown" || v.MailDomainsCause == "" {
			t.Fatalf("unknown: %+v %v", v, err)
		}
		if _, e := w.Detect(ctx, env, owner, flow.ID, Send, "example.test", viaCloudflare, false); !errors.Is(e, ErrInvalid) {
			t.Fatalf("unread list accepted: %v", e)
		}
	})
}

// Path A: the zone that holds the mail domain is the longest label-boundary
// suffix among the token's zones; the mail domain itself stays the subdomain.
func TestMatchZoneLongestLabelSuffix(t *testing.T) {
	zones := []CloudZone{{ID: "apex", Name: "example.org"}, {ID: "evil", Name: "evilexample.org"}, {ID: "deep", Name: "in.example.org"}, {ID: "other", Name: "example.test"}}
	for domain, want := range map[string]string{
		"example.org":             "apex", // exact
		"mx.example.org":          "apex", // a subdomain
		"a.b.mx.example.org":      "apex", // multi-level
		"mail.in.example.org":     "deep", // the longest of two matching zones
		"in.example.org":          "deep",
		"evilexample.org":         "evil",
		"mail.evilexample.org":    "evil", // never example.org
		"xexample.org":            "",     // label boundary
		"example.org.example.net": "",
	} {
		if got := matchZone(domain, zones); got != want {
			t.Errorf("%s: got %q want %q", domain, got, want)
		}
	}
	if got := matchZone("mx.example.org", zones[:1]); got != "apex" {
		t.Fatalf("single zone: %q", got)
	}
}

// Path A after path B in the same opening: listing the zones again gives the
// match for the domain detected now (the subdomain), not the old view's.
func TestOwnSourceRelistMatchesAfterTheCloudflareSource(t *testing.T) {
	ctx := context.Background()
	w, _ := cloudRouteWizard(newDirectory())
	env := fakeEnv()
	flow, _ := w.Start(ctx, env, owner)
	if err := signIn(w, ctx, env, owner, flow.ID); err != nil {
		t.Fatal(err)
	}
	detectDone(t, w, env, flow.ID, Send, "example.test", viaCloudflare)
	detectDone(t, w, env, flow.ID, Send, "mail.example.test", yes)
	v, err := w.Zones(ctx, env, owner, flow.ID, testAccount, "")
	if err != nil || v.Match != testZone {
		t.Fatalf("relist: %+v %v", v, err)
	}
	f, _ := w.load(ctx, env, owner, flow.ID)
	if f.Domain != "mail.example.test" {
		t.Fatalf("mail domain must stay the subdomain: %q", f.Domain)
	}
}

// Changing the path, the token, the account or the zone discards the
// detection and the plan, as changing the domain does.
func TestChangingSourceTokenAccountOrZoneDiscardsDetectionAndPlan(t *testing.T) {
	dir := newDirectory()
	second := strings.Repeat("f", 32)
	dir.zones[testAccount] = append(dir.zones[testAccount], CloudZone{ID: second, Name: "second.test", Status: "active"})
	w, _ := cloudRouteWizard(dir)
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	planned := func() {
		t.Helper()
		if err := signIn(w, ctx, env, owner, flow.ID); err != nil {
			t.Fatal(err)
		}
		detectDone(t, w, env, flow.ID, Send, "example.test", viaCloudflare)
		p, e := w.Preview(ctx, env, owner, flow.ID, Configuration{})
		for e == nil && p.Pending {
			time.Sleep(time.Millisecond)
			p, e = w.PollPreview(ctx, env, owner, flow.ID)
		}
		if e != nil {
			t.Fatal(e)
		}
		if f, _ := w.load(ctx, env, owner, flow.ID); f.Plan == nil || f.State == nil || f.Account == nil {
			t.Fatalf("not planned: %+v", f)
		}
	}
	discarded := func(what string) {
		t.Helper()
		f, _ := w.load(ctx, env, owner, flow.ID)
		if f.Plan != nil || f.State != nil || f.Account != nil || f.DetectKey != "" {
			t.Fatalf("%s kept the detection or plan: plan=%v state=%v account=%v", what, f.Plan != nil, f.State != nil, f.Account)
		}
	}
	planned()
	if _, e := w.Zones(ctx, env, owner, flow.ID, testAccount, second); e != nil {
		t.Fatal(e)
	}
	discarded("another zone")

	planned()
	if _, e := w.Connect(ctx, env, owner, flow.ID, fixtureToken); e != nil {
		t.Fatal(e)
	}
	discarded("a new token")

	planned()
	other := strings.Repeat("c", 32)
	dir.accounts = append(dir.accounts, CloudAccount{ID: other, Name: "Work"})
	if _, e := w.Connect(ctx, env, owner, flow.ID, fixtureToken); e != nil {
		t.Fatal(e)
	}
	if _, e := w.Zones(ctx, env, owner, flow.ID, testAccount, testZone); e != nil {
		t.Fatal(e)
	}
	detectDone(t, w, env, flow.ID, Send, "example.test", viaCloudflare)
	if _, e := w.Zones(ctx, env, owner, flow.ID, other, ""); e != nil {
		t.Fatal(e)
	}
	discarded("another account")
	dir.accounts = dir.accounts[:1]

	// The path: the own-domain route reads afresh (a new detection key) and
	// keeps no account or plan from the Cloudflare route.
	planned()
	f, _ := w.load(ctx, env, owner, flow.ID)
	key := f.DetectKey
	if _, e := w.Detect(ctx, env, owner, flow.ID, Send, "example.test", yes, false); e != nil {
		t.Fatal(e)
	}
	f, _ = w.load(ctx, env, owner, flow.ID)
	if f.DetectKey == key || f.Plan != nil || f.Account != nil {
		t.Fatalf("route change kept: key same=%v plan=%v account=%v", f.DetectKey == key, f.Plan != nil, f.Account)
	}
}

// Path A: the account step binds only the signed-in account and the zone
// that holds the domain; nobody types IDs.
func TestOwnSourcePermissionsNeedTheSignedInZone(t *testing.T) {
	dir := newDirectory()
	other := strings.Repeat("f", 32)
	dir.zones[testAccount] = append(dir.zones[testAccount], CloudZone{ID: other, Name: "other.test", Status: "active"})
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: &fakeCloud{restorable: true}, Directory: dir, Verifier: verifier{}})
	env := fakeEnv()
	ctx := context.Background()
	id, v := ready(t, w, env, Send)
	if !v.Branch.NeedsAccount {
		t.Fatalf("branch: %+v", v.Branch)
	}
	if _, e := w.Permissions(ctx, env, owner, id, testAccount, testZone); !errors.Is(e, ErrInvalid) {
		t.Fatalf("without sign-in: %v", e)
	}
	c, e := w.Connect(ctx, env, owner, id, fixtureToken)
	if e != nil || c.Match != testZone {
		t.Fatalf("match: %+v %v", c, e)
	}
	if _, e = w.Zones(ctx, env, owner, id, testAccount, other); e != nil {
		t.Fatal(e)
	}
	if _, e = w.Permissions(ctx, env, owner, id, testAccount, other); !errors.Is(e, ErrInvalid) {
		t.Fatalf("zone without the domain: %v", e)
	}
	if _, e = w.Zones(ctx, env, owner, id, testAccount, testZone); e != nil {
		t.Fatal(e)
	}
	if _, e = w.Permissions(ctx, env, owner, id, testAccount, other); !errors.Is(e, ErrInvalid) {
		t.Fatalf("a zone other than the chosen one: %v", e)
	}
	if ps, e := w.Permissions(ctx, env, owner, id, testAccount, testZone); e != nil || len(ps) != 2 {
		t.Fatalf("permissions: %+v %v", ps, e)
	}
	// The own route's detection survives a new sign-in; the binding does not.
	if _, e = w.Connect(ctx, env, owner, id, fixtureToken); e != nil {
		t.Fatal(e)
	}
	if f, _ := w.load(ctx, env, owner, id); f.State == nil || f.Account != nil {
		t.Fatalf("own route after sign-in: state=%v account=%v", f.State != nil, f.Account)
	}
}

// A new wizard opening signs in again: Start forgets the sign-in.
func TestStartForgetsTheSignIn(t *testing.T) {
	w := New(Options{Directory: newDirectory()})
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	if _, e := w.Connect(ctx, env, owner, flow.ID, fixtureToken); e != nil {
		t.Fatal(e)
	}
	again, e := w.Start(ctx, env, owner)
	if e != nil || again.ID != flow.ID {
		t.Fatalf("start: %+v %v", again, e)
	}
	if f, _ := w.load(ctx, env, owner, flow.ID); f.Cloud != nil {
		t.Fatalf("kept: %+v", f.Cloud)
	}
	if _, e = w.Zones(ctx, env, owner, flow.ID, testAccount, ""); !errors.Is(e, ErrStale) {
		t.Fatalf("zones without sign-in: %v", e)
	}
}

func TestCloudKeysInNineLocales(t *testing.T) {
	keys := []string{ErrTokenInvalid.Error(), ErrCloudflareUnavailable.Error(), "mail.setup.start", "mail.setup.startBody", "mail.setup.start.own", "mail.setup.start.ownHint",
		"mail.setup.start.cloudflare", "mail.setup.start.cloudflareHint", "mail.setup.cloudflare", "mail.setup.cloudflareBody",
		"mail.setup.cloudflare.create", "mail.setup.cloudflare.step1", "mail.setup.cloudflare.step2", "mail.setup.cloudflare.step2Hint", "mail.setup.cloudflare.step3", "mail.setup.cloudflare.permissions", "mail.setup.cloudflare.readOnlyCheck", "mail.setup.cloudflare.token", "mail.setup.cloudflare.tokenHint",
		"mail.setup.cloudflare.connected", "mail.setup.cloudflare.missing", "mail.setup.cloudflare.relayNote", "mail.setup.cloudflare.replace", "mail.setup.zone", "mail.setup.zoneBody",
		"mail.setup.zone.account", "mail.setup.zone.domain", "mail.setup.zone.pending", "mail.setup.zone.inactive", "mail.setup.zone.pendingNote",
		"mail.setup.cloudflare.oneRun", "mail.setup.cause.notStarted", "mail.setup.zone.mailDomain", "mail.setup.zone.mailDomainHint", "mail.setup.zone.help.firstRun.title", "mail.setup.zone.help.addDomain.title", "mail.setup.zone.help.either.title", "mail.setup.zone.mailDomainsUnknown", "mail.setup.zone.reading", "mail.setup.zone.noAccount", "mail.setup.zone.none", "mail.setup.zone.noneBody",
		"mail.setup.zone.register", "mail.setup.zone.recheck", "mail.setup.zone.matched", "mail.setup.zone.noMatch",
		"mail.setup.routingConflict", "mail.setup.routingLeftover", "mail.setup.routingLeftoverDisabled"}
	for _, code := range PermissionCodes {
		keys = append(keys, "mail.setup.cloudflare.permission."+code)
	}
	for _, locale := range []string{"en", "zh-TW", "zh-CN", "ja", "ko", "de", "fr", "es", "it"} {
		raw, err := os.ReadFile(filepath.Join("../../../../i18n/messages", locale+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var catalog map[string]string
		if err = json.Unmarshal(raw, &catalog); err != nil {
			t.Fatal(err)
		}
		for _, key := range keys {
			if text := catalog[key]; text == "" || strings.HasSuffix(text, ".") || strings.HasSuffix(text, "。") {
				t.Fatalf("%s: missing or invalid %s", locale, key)
			}
		}
		if locale == "zh-TW" && (strings.Contains(catalog["mail.setup.start"], "你") || !strings.Contains(catalog["mail.setup.start"], "您")) {
			t.Fatal("zh-TW addresses the reader as 您")
		}
		// Every zh message addresses the reader as 您, DSM-term messages
		// included (glossary term connection_failed carries 您 locally).
		if strings.HasPrefix(locale, "zh-") {
			for key, text := range catalog {
				if strings.Contains(text, "你") {
					t.Errorf("%s %s uses 你: %s", locale, key, text)
				}
			}
		}
	}
}

// tokenRefs lists the sealed sign-in tokens of the fake secret store.
func tokenRefs(env core.Env) []string {
	secretsMu.Lock()
	defer secretsMu.Unlock()
	out := []string{}
	for k := range env.Secrets.(secrets) {
		if strings.Contains(k, ".token.") {
			out = append(out, k)
		}
	}
	return out
}

// A refused new token never replaces the sealed one in use.
func TestRefusedNewTokenKeepsTheSignIn(t *testing.T) {
	dir := newDirectory()
	w := New(Options{Directory: dir})
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	if _, e := w.Connect(ctx, env, owner, flow.ID, fixtureToken); e != nil {
		t.Fatal(e)
	}
	before, _ := w.load(ctx, env, owner, flow.ID)
	refs := tokenRefs(env)
	if len(refs) != 1 || refs[0] != before.Cloud.TokenRef {
		t.Fatalf("sealed: %v %+v", refs, before.Cloud)
	}
	dir.err = ErrTokenInvalid
	if _, e := w.Connect(ctx, env, owner, flow.ID, "a-refused-token"); !errors.Is(e, ErrTokenInvalid) {
		t.Fatalf("refused: %v", e)
	}
	after, _ := w.load(ctx, env, owner, flow.ID)
	if digest(after.Cloud) != digest(before.Cloud) {
		t.Fatalf("sign-in changed: %+v", after.Cloud)
	}
	if v, _ := env.Secrets.Get(ctx, before.Cloud.TokenRef); v != fixtureToken {
		t.Fatalf("the sealed token was overwritten: %q", v)
	}
	if got := tokenRefs(env); len(got) != 1 {
		t.Fatalf("the refused candidate stayed sealed: %v", got)
	}
	// An accepted new token replaces the old one, whose secret is deleted.
	dir.err = nil
	if _, e := w.Connect(ctx, env, owner, flow.ID, "a-second-token"); e != nil {
		t.Fatal(e)
	}
	again, _ := w.load(ctx, env, owner, flow.ID)
	if got := tokenRefs(env); len(got) != 1 || got[0] != again.Cloud.TokenRef || got[0] == before.Cloud.TokenRef {
		t.Fatalf("old token kept: %v", got)
	}
}

// Only a flow still collecting answers may sign in again; a flow
// with a transaction keeps its token reference, so resume and rollback keep
// their token. a new token for such a flow (the old one was deleted
// in Cloudflare) replaces the sealed value in place, under the same
// reference, only once it is active and makes the path's reads; a token
// missing a permission writes nothing.
func TestSignInOnANonNewFlowWritesNothing(t *testing.T) {
	dir := newDirectory()
	w, _ := cloudRouteWizard(dir)
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	if err := signIn(w, ctx, env, owner, flow.ID); err != nil {
		t.Fatal(err)
	}
	detectDone(t, w, env, flow.ID, Send, "example.test", viaCloudflare)
	p, e := w.Preview(ctx, env, owner, flow.ID, Configuration{})
	for e == nil && p.Pending {
		time.Sleep(time.Millisecond)
		p, e = w.PollPreview(ctx, env, owner, flow.ID)
	}
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.Apply(ctx, env, owner, flow.ID); e != nil {
		t.Fatal(e)
	}
	w.Wait()
	secretsMu.Lock()
	n := len(env.Secrets.(secrets))
	secretsMu.Unlock()
	refs := tokenRefs(env)
	dir.mu.Lock()
	dir.probe = []string{PermDNSEdit}
	dir.mu.Unlock()
	var missing PermissionsMissing
	if _, e = w.Connect(ctx, env, owner, flow.ID, "lacking-token"); !errors.As(e, &missing) || strings.Join(missing.Codes, ",") != PermDNSEdit {
		t.Fatalf("a token missing a permission: %v", e)
	}
	if v, _ := env.Secrets.Get(ctx, refs[0]); v != fixtureToken {
		t.Fatal("a token missing a permission replaced the sealed one")
	}
	dir.mu.Lock()
	dir.probe = nil
	dir.mu.Unlock()
	if _, e = w.Connect(ctx, env, owner, flow.ID, "another-token"); e != nil {
		t.Fatalf("decision phase: a new token was refused: %v", e)
	}
	secretsMu.Lock()
	m := len(env.Secrets.(secrets))
	secretsMu.Unlock()
	if m != n || strings.Join(tokenRefs(env), ",") != strings.Join(refs, ",") {
		t.Fatalf("a secret reference changed: %d → %d", n, m)
	}
	if v, _ := env.Secrets.Get(ctx, refs[0]); v != "another-token" {
		t.Fatal("the sealed token was not replaced in place")
	}
	// Decision: the token stays for a rollback. Kept: it goes.
	if len(refs) != 1 {
		t.Fatalf("token gone before the decision: %v", refs)
	}
	if _, e = w.Decide(ctx, env, owner, flow.ID, "keep"); e != nil {
		t.Fatal(e)
	}
	if got := tokenRefs(env); len(got) != 0 {
		t.Fatalf("kept flow still holds the token: %v", got)
	}
}

// The sealed token goes when nothing can need it any more.
func TestSealedTokenIsDeletedWhenNoLongerNeeded(t *testing.T) {
	ctx := context.Background()
	// A new wizard on an open flow.
	w := New(Options{Directory: newDirectory()})
	env := fakeEnv()
	flow, _ := w.Start(ctx, env, owner)
	if _, e := w.Connect(ctx, env, owner, flow.ID, fixtureToken); e != nil {
		t.Fatal(e)
	}
	if _, e := w.Start(ctx, env, owner); e != nil || len(tokenRefs(env)) != 0 {
		t.Fatalf("start kept the token: %v %v", tokenRefs(env), e)
	}
	// A completed rollback.
	w2, _ := cloudRouteWizard(newDirectory())
	env2 := fakeEnv()
	flow2, _ := w2.Start(ctx, env2, owner)
	if err := signIn(w2, ctx, env2, owner, flow2.ID); err != nil {
		t.Fatal(err)
	}
	detectDone(t, w2, env2, flow2.ID, Send, "example.test", viaCloudflare)
	p, e := w2.Preview(ctx, env2, owner, flow2.ID, Configuration{})
	for e == nil && p.Pending {
		time.Sleep(time.Millisecond)
		p, e = w2.PollPreview(ctx, env2, owner, flow2.ID)
	}
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w2.Apply(ctx, env2, owner, flow2.ID); e != nil {
		t.Fatal(e)
	}
	w2.Wait()
	if len(tokenRefs(env2)) != 1 {
		t.Fatal("token gone while a rollback could need it")
	}
	if _, e = w2.Decide(ctx, env2, owner, flow2.ID, "rollback"); e != nil {
		t.Fatal(e)
	}
	w2.Wait()
	if v, _ := w2.Status(ctx, env2, owner, flow2.ID); v.Phase != PhaseRolledBack || len(tokenRefs(env2)) != 0 {
		t.Fatalf("rolled back: %s, tokens %v", v.Phase, tokenRefs(env2))
	}
}

// A token Cloudflare accepts, with no zone yet and /accounts
// refused, is "account unknown, no zones": register, then check again.
func TestAccountUnknownUntilTheFirstZone(t *testing.T) {
	dir := newDirectory()
	dir.accounts, dir.unknown = nil, true
	w := New(Options{Directory: dir})
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	v, e := w.Connect(ctx, env, owner, flow.ID, fixtureToken)
	if e != nil || !v.AccountUnknown || len(v.Accounts) != 0 || len(v.Zones) != 0 {
		t.Fatalf("unknown: %+v %v", v, e)
	}
	// Registered: the zone names the account; check again chooses it.
	dir.accounts, dir.unknown = []CloudAccount{{ID: testAccount, Name: "Home"}}, false
	if v, e = w.Zones(ctx, env, owner, flow.ID, "", ""); e != nil || v.AccountUnknown || v.AccountID != testAccount || len(v.Zones) != 1 {
		t.Fatalf("again: %+v %v", v, e)
	}
	// The re-check reads with the sealed token: no new secret.
	if got := tokenRefs(env); len(got) != 1 {
		t.Fatalf("tokens: %v", got)
	}
	// Only while the account is unknown.
	if _, e = w.Zones(ctx, env, owner, flow.ID, "", ""); !errors.Is(e, ErrStale) {
		t.Fatalf("re-check with a known account: %v", e)
	}
}

// Zones stores only a zone of the list it just read.
func TestZonesStoresOnlyAListedZone(t *testing.T) {
	dir := newDirectory()
	w := New(Options{Directory: dir})
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	if _, e := w.Connect(ctx, env, owner, flow.ID, fixtureToken); e != nil {
		t.Fatal(e)
	}
	dir.zoneMiss, dir.zones[testAccount] = []string{PermZoneRead}, nil
	if _, e := w.Zones(ctx, env, owner, flow.ID, testAccount, testZone); !errors.Is(e, ErrInvalid) {
		t.Fatalf("unlisted zone: %v", e)
	}
	if f, _ := w.load(ctx, env, owner, flow.ID); f.Cloud.ZoneID != "" {
		t.Fatalf("stored: %+v", f.Cloud)
	}
}

// An unclear Cloudflare answer stays Cloudflare-unavailable through the
// wizard (its own text), and keeps nothing.
func TestCloudflareUnavailablePassesThrough(t *testing.T) {
	dir := newDirectory()
	dir.err = ErrCloudflareUnavailable
	w := New(Options{Directory: dir})
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	if _, e := w.Connect(ctx, env, owner, flow.ID, fixtureToken); !errors.Is(e, ErrCloudflareUnavailable) {
		t.Fatalf("connect: %v", e)
	}
	if got := tokenRefs(env); len(got) != 0 {
		t.Fatalf("candidate kept: %v", got)
	}
}

// recordingSecrets records every write.
type recordingSecrets struct {
	secrets
	puts []string
}

func (r *recordingSecrets) Put(ctx context.Context, k, v string) error {
	r.puts = append(r.puts, k)
	return r.secrets.Put(ctx, k, v)
}

// NAS, build 21: a token no verify endpoint accepted is never sealed, not
// even for a moment, and reports no missing permission.
func TestUnverifiedTokenIsNeverSealed(t *testing.T) {
	dir := newDirectory()
	w := New(Options{Directory: dir})
	rec := &recordingSecrets{secrets: secrets{}}
	env := core.Env{KV: &memoryKV{}, Secrets: rec}
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	for _, refusal := range []error{ErrTokenInvalid, ErrCloudflareUnavailable} {
		dir.err = refusal
		v, e := w.Connect(ctx, env, owner, flow.ID, "abcdefghijklmnopqrstuvwxyz0123456789ABCE")
		if !errors.Is(e, refusal) || len(v.Missing) != 0 {
			t.Fatalf("%v: %+v %v", refusal, v, e)
		}
		if len(rec.puts) != 0 {
			t.Fatalf("%v: sealed before a verify accepted it: %v", refusal, rec.puts)
		}
	}
	if f, _ := w.load(ctx, env, owner, flow.ID); f.Cloud != nil {
		t.Fatalf("promoted: %+v", f.Cloud)
	}
	// Accepted: sealed once, under the fresh reference.
	dir.err = nil
	if _, e := w.Connect(ctx, env, owner, flow.ID, fixtureToken); e != nil || len(rec.puts) != 1 || !strings.Contains(rec.puts[0], ".token.") {
		t.Fatalf("accepted: %v %v", rec.puts, e)
	}
}

// blockingDomains answers MailDomains only when released.
type blockingDomains struct {
	source
	release chan struct{}
}

func (b blockingDomains) MailDomains(ctx context.Context, env core.Env) ([]string, error) {
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return b.source.MailDomains(ctx, env)
}

// A domain read that belonged to another zone or another sign-in never
// writes the current zone's state.
func TestDomainReadResultsStayWithTheirZone(t *testing.T) {
	ctx := context.Background()
	dir := newDirectory()
	second := strings.Repeat("f", 32)
	dir.zones[testAccount] = append(dir.zones[testAccount], CloudZone{ID: second, Name: "second.test", Status: "active"})
	w, _ := cloudRouteWizard(dir)
	st := healthy()
	st.Domains = detect.Fact([]detect.Domain{{ID: 1, Name: "mail.example.test"}, {ID: 2, Name: "mail.second.test"}})
	release := make(chan struct{})
	w.options.Detector = blockingDomains{source: source{state: st}, release: release}
	w.domainWait = 20 * time.Millisecond
	env := fakeEnv()
	flow, _ := w.Start(ctx, env, owner)
	if _, err := w.Connect(ctx, env, owner, flow.ID, fixtureToken); err != nil {
		t.Fatal(err)
	}
	v, err := w.Zones(ctx, env, owner, flow.ID, testAccount, testZone)
	if err != nil || v.MailDomainsState != "reading" {
		t.Fatalf("first zone: %+v %v", v, err)
	}
	w.mu.Lock()
	first := w.domainReads[flow.ID]
	w.mu.Unlock()
	if v, err = w.Zones(ctx, env, owner, flow.ID, testAccount, second); err != nil || v.MailDomainsState != "reading" {
		t.Fatalf("second zone: %+v %v", v, err)
	}
	f, _ := w.load(ctx, env, owner, flow.ID)
	stale := []*domainRead{
		// The first zone's read, finished late with its names.
		{gen: first.gen, zoneID: testZone, done: closed(), names: []string{"mail.example.test"}, job: first.job},
		// Same zone, but read for an older sign-in.
		{gen: "older", zoneID: second, done: closed(), names: []string{"mail.example.test"}, job: first.job},
	}
	for i, r := range stale {
		v, err := w.awaitDomainRead(ctx, env, owner, flow.ID, r)
		if err != nil || v.ZoneID != second || v.MailDomainsState != "reading" || len(v.MailDomains) != 0 {
			t.Fatalf("stale %d stored: %+v %v", i, v, err)
		}
	}
	if g, _ := w.load(ctx, env, owner, flow.ID); g.Cloud.Gen != f.Cloud.Gen || !g.Cloud.MailDomainsReading {
		t.Fatalf("state changed: %+v", g.Cloud)
	}
	close(release)
	for i := 0; i < 50; i++ {
		if v, err = w.PollZone(ctx, env, owner, flow.ID); err != nil || v.MailDomainsState != "reading" {
			break
		}
	}
	if err != nil || v.MailDomainsState != "read" || strings.Join(v.MailDomains, ",") != "mail.second.test" {
		t.Fatalf("second zone's own read: %+v %v", v, err)
	}
}

func closed() chan struct{} { c := make(chan struct{}); close(c); return c }

// stubbornDomains ignores cancellation: it answers only when released, the
// way an executor call already sent keeps running past its job's cancel.
type stubbornDomains struct {
	source
	release chan struct{}
}

func (b stubbornDomains) MailDomains(ctx context.Context, env core.Env) ([]string, error) {
	<-b.release
	return b.source.MailDomains(ctx, env)
}

// zoneReadFixture signs in and returns the wizard with the zone step's
// MailPlus domains answered by d.
func zoneReadFixture(t *testing.T, d detect.Source, bg *core.Background) (*Wizard, core.Env, string) {
	t.Helper()
	w, _ := cloudRouteWizard(newDirectory())
	w.options.Detector, w.options.Background = d, bg
	w.domainWait = 20 * time.Millisecond
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	if _, err := w.Connect(ctx, env, owner, flow.ID, fixtureToken); err != nil {
		t.Fatal(err)
	}
	return w, env, flow.ID
}

// Choosing the same zone again replaces the read: the replaced read (canceled,
// finished with "unavailable") has the same sign-in and zone, but only the
// flow's current read may store, so the new one stays "reading" and then
// stores its own names.
func TestReplacedDomainReadOfTheSameZoneNeverStores(t *testing.T) {
	ctx := context.Background()
	release := make(chan struct{})
	st := healthy()
	w, env, id := zoneReadFixture(t, blockingDomains{source: source{state: st}, release: release}, nil)
	if v, err := w.Zones(ctx, env, owner, id, testAccount, testZone); err != nil || v.MailDomainsState != "reading" {
		t.Fatalf("first read: %+v %v", v, err)
	}
	w.mu.Lock()
	first := w.domainReads[id]
	w.mu.Unlock()
	if v, err := w.Zones(ctx, env, owner, id, testAccount, testZone); err != nil || v.MailDomainsState != "reading" {
		t.Fatalf("same zone again: %+v %v", v, err)
	}
	<-first.done // canceled by the replacement: finished, cause unavailable
	if first.cause == "" || !first.job.Interrupted() {
		t.Fatalf("replaced read: cause %q interrupted %v", first.cause, first.job.Interrupted())
	}
	v, err := w.awaitDomainRead(ctx, env, owner, id, first)
	if err != nil || v.MailDomainsState != "reading" {
		t.Fatalf("the replaced read stored: %+v %v", v, err)
	}
	if f, _ := w.load(ctx, env, owner, id); !f.Cloud.MailDomainsReading || f.Cloud.MailDomainsCause != "" {
		t.Fatalf("state changed: %+v", f.Cloud)
	}
	close(release)
	for range 50 {
		if v, err = w.PollZone(ctx, env, owner, id); err != nil || v.MailDomainsState != "reading" {
			break
		}
	}
	if err != nil || v.MailDomainsState != "read" || strings.Join(v.MailDomains, ",") != "example.test" {
		t.Fatalf("current read: %+v %v", v, err)
	}
}

// D6: a read nobody polled is abandoned (job interrupted) while its DSM call
// is still out. The next poll does not wait for it: unknown ("unavailable"),
// stored, and the zone step offers Check again.
func TestInterruptedDomainReadIsUnknown(t *testing.T) {
	ctx := context.Background()
	release := make(chan struct{})
	bg := &core.Background{Abandon: 30 * time.Millisecond}
	w, env, id := zoneReadFixture(t, stubbornDomains{source: source{state: healthy()}, release: release}, bg)
	defer func() { close(release); bg.Wait() }()
	if v, err := w.Zones(ctx, env, owner, id, testAccount, testZone); err != nil || v.MailDomainsState != "reading" {
		t.Fatalf("read: %+v %v", v, err)
	}
	w.mu.Lock()
	r := w.domainReads[id]
	w.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for !r.job.Interrupted() {
		if time.Now().After(deadline) {
			t.Fatal("the unpolled read was never abandoned")
		}
		time.Sleep(5 * time.Millisecond)
	}
	v, err := w.PollZone(ctx, env, owner, id)
	if err != nil || v.MailDomainsState != "unknown" || v.MailDomainsCause != core.CauseUnavailable || len(v.MailDomains) != 0 {
		t.Fatalf("interrupted: %+v %v", v, err)
	}
	if f, _ := w.load(ctx, env, owner, id); f.Cloud.MailDomainsReading || f.Cloud.MailDomainsCause != core.CauseUnavailable {
		t.Fatalf("not stored: %+v", f.Cloud)
	}
	w.mu.Lock()
	_, kept := w.domainReads[id]
	w.mu.Unlock()
	if kept {
		t.Fatal("the interrupted read is still the flow's read")
	}
}

// D7: the worker restarted while a read was in flight. The new worker has no
// read for the flow but the stored sign-in still says "reading": the poll
// turns that into unknown ("unavailable") and stores it, never "reading"
// forever and never an empty list as if read.
func TestDomainReadLostByAWorkerRestartIsUnknown(t *testing.T) {
	ctx := context.Background()
	release := make(chan struct{})
	defer close(release)
	w, env, id := zoneReadFixture(t, blockingDomains{source: source{state: healthy()}, release: release}, nil)
	if v, err := w.Zones(ctx, env, owner, id, testAccount, testZone); err != nil || v.MailDomainsState != "reading" {
		t.Fatalf("read: %+v %v", v, err)
	}
	restarted, _ := cloudRouteWizard(newDirectory())
	restarted.options.Detector, restarted.domainWait = w.options.Detector, w.domainWait
	v, err := restarted.PollZone(ctx, env, owner, id)
	if err != nil || v.ZoneID != testZone || v.MailDomainsState != "unknown" || v.MailDomainsCause != core.CauseUnavailable || len(v.MailDomains) != 0 {
		t.Fatalf("after restart: %+v %v", v, err)
	}
	if f, _ := restarted.load(ctx, env, owner, id); f.Cloud.MailDomainsReading || f.Cloud.MailDomainsCause != core.CauseUnavailable {
		t.Fatalf("not stored: %+v", f.Cloud)
	}
	// Choosing the zone again (Check again) starts a fresh read.
	if v, err = restarted.Zones(ctx, env, owner, id, testAccount, testZone); err != nil || v.MailDomainsState != "reading" {
		t.Fatalf("check again: %+v %v", v, err)
	}
}

// newDomainMailPlus plans what the decision needs (the domain step first in
// its own list is not assumed) and refuses to create the domain when fail is set.
type newDomainMailPlus struct {
	*fakeCloud
	fail bool
}

func (m newDomainMailPlus) Plan(_ context.Context, _ core.Env, r PlanRequest, _ []core.Change) (Prepared, error) {
	p := Prepared{Restorable: true}
	for _, need := range r.Decision.Needs {
		switch need {
		case "mailplus.delivery", "mailplus.domain":
			p.Changes = append(p.Changes, core.Change{ID: need, Target: need, ActionKey: "mail.setup.change." + need, Params: map[string]string{"domain": r.Domain}, Before: "before", After: "after"})
		}
	}
	return p, nil
}
func (m newDomainMailPlus) Apply(ctx context.Context, env core.Env, c core.Change) error {
	if m.fail && c.Target == "mailplus.domain" {
		return core.AuthorityRequired{Profile: "mail-write"}
	}
	return m.fakeCloud.Apply(ctx, env, c)
}

// the MailPlus Server mail domain is created before any Cloudflare
// write. When creating it fails, nothing touched Cloudflare (or the relay),
// and the rollback still runs.
func TestNewDomainIsCreatedBeforeCloudflare(t *testing.T) {
	ctx := context.Background()
	for _, fail := range []bool{false, true} {
		st := healthy()
		st.Domains = detect.Fact([]detect.Domain{{ID: 7, Name: "other.test"}})
		delete(st.Accounts, st.Domain)
		delete(st.Signing, st.Domain)
		st.Delivery = detect.Fact(detect.Delivery{Type: "none"})
		cloud := &cloudPlan{fakeCloud: &fakeCloud{restorable: true}}
		relay := fakeRelay{&fakeCloud{}}
		mp := newDomainMailPlus{fakeCloud: &fakeCloud{}, fail: fail}
		w := New(Options{Detector: source{state: st}, Cloudflare: cloud, Directory: newDirectory(), Relay: relay,
			MailPlus: mp, Verifier: verifier{result: Verification{Readback: true, Delivery: true}}})
		env := fakeEnv()
		flow, _ := w.Start(ctx, env, owner)
		if err := signIn(w, ctx, env, owner, flow.ID); err != nil {
			t.Fatal(err)
		}
		v := detectDone(t, w, env, flow.ID, Send, "example.test", viaCloudflare)
		if v.Branch.Kind != "configure" || !v.Branch.CreatesDomain {
			t.Fatalf("branch: %+v", v.Branch)
		}
		p, e := w.Preview(ctx, env, owner, flow.ID, Configuration{})
		for e == nil && p.Pending {
			time.Sleep(time.Millisecond)
			p, e = w.PollPreview(ctx, env, owner, flow.ID)
		}
		if e != nil || len(p.Changes) < 4 || p.Changes[0].Target != "mailplus.domain" {
			t.Fatalf("preview: %+v %v", p.Changes, e)
		}
		if _, e = w.Apply(ctx, env, owner, flow.ID); e != nil {
			t.Fatal(e)
		}
		got := wait(t, w, env, flow.ID)
		if !fail {
			if got.Phase != PhaseDecision || cloud.writes != 1 || mp.writes != 2 {
				t.Fatalf("apply: %s cloud=%d mailplus=%d", got.Phase, cloud.writes, mp.writes)
			}
			continue
		}
		if got.Phase != PhaseRolledBack || got.FailedStep != "mailplus.domain" || cloud.writes != 0 || cloud.undos != 0 || relay.writes != 0 || mp.writes != 0 {
			t.Fatalf("failed domain: phase=%s step=%q cloud=%d/%d relay=%d mailplus=%d", got.Phase, got.FailedStep, cloud.writes, cloud.undos, relay.writes, mp.writes)
		}
	}
}
