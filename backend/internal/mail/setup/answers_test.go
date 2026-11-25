package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

// checkCase is one state of the deterministic network checks: good, bad (a
// clear failure that wins over any answer), unknown (a check this version runs
// could not be done: not usable) or unchecked (a fact this version never
// checks: the answer stands for it).
type checkCase struct {
	name   string
	kind   string // good | bad | unknown | unchecked
	why    string // the reason code the check adds; "" for good and unchecked
	mutate func(*detect.State)
}

var sendChecks = []checkCase{
	{"good", "good", "", nil},
	{"ip-changing", "bad", "ipChanging", func(s *detect.State) { s.Network.Addressing = detect.Fact(detect.Changing) }},
	{"fcrdns-fail", "bad", "fcrdnsFail", func(s *detect.State) { s.Network.FCrDNS = detect.Fact(false) }},
	{"ptr-none", "bad", "ptrNone", func(s *detect.State) { s.Network.PTR = detect.Fact([]string{}) }},
	{"outbound-blocked", "bad", "outboundBlocked", func(s *detect.State) { s.Network.Outbound25 = detect.Fact(false) }},
	{"dnsbl-listed", "bad", "dnsblListed", func(s *detect.State) { s.Network.DNSBL[0].Status = "listed" }},
	{"ip-unknown", "unknown", "ipUnknown", func(s *detect.State) {
		s.Network.EgressIPv4 = detect.Unavailable[string]()
		s.Network.PTR = detect.Unavailable[[]string]()
		s.Network.FCrDNS = detect.Unavailable[bool]()
		s.Network.DNSBL = []detect.DNSBL{{Provider: "unconfigured", Status: "unknown"}}
	}},
	{"ptr-unknown", "unknown", "ptrUnknown", func(s *detect.State) { s.Network.PTR = detect.Unavailable[[]string]() }},
	{"fcrdns-unknown", "unknown", "fcrdnsUnknown", func(s *detect.State) { s.Network.FCrDNS = detect.Unavailable[bool]() }},
	{"outbound-unknown", "unknown", "outboundUnknown", func(s *detect.State) { s.Network.Outbound25 = detect.Unavailable[bool]() }},
	{"dnsbl-unknown", "unknown", "dnsblUnknown", func(s *detect.State) { s.Network.DNSBL[0].Status = "unknown" }},
	{"addressing-unchecked", "unchecked", "", func(s *detect.State) {
		s.Network.Addressing = detect.Observation[detect.Addressing]{Status: detect.Unknown, Detail: detect.CauseNotChecked}
	}},
}

var receiveChecks = []checkCase{
	{"good", "good", "", nil},
	{"ip-changing", "bad", "ipChanging", func(s *detect.State) { s.Network.Addressing = detect.Fact(detect.Changing) }},
	{"inbound-blocked", "bad", "inboundBlocked", func(s *detect.State) { s.Network.Inbound25 = detect.Fact(false) }},
	{"ip-unknown", "unknown", "ipUnknown", func(s *detect.State) { s.Network.EgressIPv4 = detect.Unavailable[string]() }},
	{"inbound-unchecked", "unchecked", "", func(s *detect.State) {
		s.Network.Inbound25 = detect.Observation[bool]{Status: detect.Unknown, Detail: detect.CauseNotChecked}
	}},
	{"addressing-unchecked", "unchecked", "", func(s *detect.State) {
		s.Network.Addressing = detect.Observation[detect.Addressing]{Status: detect.Unknown, Detail: detect.CauseNotChecked}
	}},
}

var routes = []Route{RouteDirect, RouteCloudflare, ""}

// TestRouteCrossChecks covers every route choice (own IP, Cloudflare, none
// yet) crossed with each direction's checks being good, bad, unknown or
// unchecked. Only the own-IP route with no bad or unknown check gives a
// direct path, and the decision names every reason.
func TestRouteCrossChecks(t *testing.T) {
	for _, dir := range []struct {
		intent Intent
		checks []checkCase
	}{{Send, sendChecks}, {Receive, receiveChecks}} {
		for _, c := range dir.checks {
			for _, route := range routes {
				a := Answers{Route: route}
				t.Run(fmt.Sprintf("%s/%s/route=%q", dir.intent, c.name, route), func(t *testing.T) {
					s := healthy()
					if c.mutate != nil {
						c.mutate(&s)
					}
					d := Decide(s, dir.intent, a)
					if d.Gate != "" {
						t.Fatalf("a path decision must not stop: %+v", d)
					}
					wantDirect := route == RouteDirect && (c.kind == "good" || c.kind == "unchecked")
					var want []string
					switch {
					case route == RouteCloudflare:
						want = []string{"routeCloudflare"}
					case route == "":
						want = []string{"routeUnset"}
					case c.kind == "bad" || c.kind == "unknown":
						want = []string{c.why}
					}
					got, branch := d.SendWhy, d.Send
					direct, other := DirectSend, RelaySend
					if dir.intent == Receive {
						got, branch, direct, other = d.ReceiveWhy, d.Receive, DirectReceive, RoutingReceive
					}
					if wantDirect {
						if branch != direct {
							t.Fatalf("want %s, got %+v", direct, d)
						}
						want = []string{"routeDirect"}
						if dir.intent == Send {
							want = append(want, "sendChecksPass")
						}
					} else if branch != other {
						t.Fatalf("want %s, got %+v", other, d)
					}
					if !slices.Equal(got, want) {
						t.Fatalf("why = %v, want %v", got, want)
					}
					for _, code := range got {
						if !slices.Contains(WhyCodes, code) {
							t.Fatalf("code %q is not in WhyCodes", code)
						}
					}
				})
			}
		}
	}
}

// A bad check forces the Cloudflare path even on the own-IP route, and
// both directions are decided and explained independently.
func TestBadCheckWinsOverYes(t *testing.T) {
	s := healthy()
	s.Network.FCrDNS = detect.Fact(false)
	d := Decide(s, Both, yes)
	if d.Send != RelaySend || !slices.Equal(d.SendWhy, []string{"fcrdnsFail"}) {
		t.Fatalf("send %+v", d)
	}
	// Reverse DNS does not matter for receiving.
	if d.Receive != DirectReceive || !slices.Equal(d.ReceiveWhy, []string{"routeDirect"}) {
		t.Fatalf("receive %+v", d)
	}
	// The Cloudflare route decides alone: the bad check is not a reason.
	d = Decide(s, Both, Answers{Route: RouteCloudflare})
	if d.Send != RelaySend || d.Receive != RoutingReceive || !slices.Equal(d.SendWhy, []string{"routeCloudflare"}) || !slices.Equal(d.ReceiveWhy, []string{"routeCloudflare"}) {
		t.Fatalf("cloudflare route %+v", d)
	}
}

func TestAnswersValidAndFor(t *testing.T) {
	if !(Answers{}).Valid() || !yes.Valid() || !(Answers{Route: RouteCloudflare}).Valid() || (Answers{Route: "maybe"}).Valid() || (Answers{Route: "DIRECT"}).Valid() || (Answers{Source: "other"}).Valid() {
		t.Fatal("Valid accepts only direct, cloudflare or no route, and a known source")
	}
	for _, i := range []Intent{Send, Receive, Both} {
		if got := yes.For(i); got != yes {
			t.Fatalf("%s keeps %+v", i, got)
		}
	}
	if got := (Answers{Source: SourceOwn, Route: RouteCloudflare}).For(Send); got != (Answers{Route: RouteCloudflare}) {
		t.Fatalf("own source is no source: %+v", got)
	}
}

// The branch view carries each decided direction's path and its reasons as
// catalog keys; an already-correct direction has none.
func TestBranchPaths(t *testing.T) {
	w := New(Options{})
	s := healthy()
	b := w.branch(s, Both, Answers{Route: RouteCloudflare})
	want := []PathView{
		{Direction: "send", Branch: RelaySend, TitleKey: "mail.setup.path.cloudflare-relay", Why: []string{"mail.setup.why.routeCloudflare"}},
		{Direction: "receive", Branch: RoutingReceive, TitleKey: "mail.setup.path.cloudflare-routing", Why: []string{"mail.setup.why.routeCloudflare"}},
	}
	if len(b.Paths) != 2 || !slices.EqualFunc(b.Paths, want, func(a, b PathView) bool {
		return a.Direction == b.Direction && a.Branch == b.Branch && a.TitleKey == b.TitleKey && slices.Equal(a.Why, b.Why)
	}) {
		t.Fatalf("paths %+v", b.Paths)
	}
	s.SendReady = detect.Fact(true)
	if b := w.branch(s, Send, yes); len(b.Paths) != 0 {
		t.Fatalf("already-correct send has no path: %+v", b.Paths)
	}
}

// countingKV counts writes, so a poll that changes nothing is seen to write nothing.
type countingKV struct {
	memoryKV
	puts int
}

func (c *countingKV) Put(ctx context.Context, mod, key string, v any) error {
	c.puts++
	return c.memoryKV.Put(ctx, mod, key, v)
}

// Changing an answer re-decides from the same detection (no new read), drops
// the account and plan, and is the only poll that writes.
func TestDetectAnswersRedecideWithoutReading(t *testing.T) {
	ctx := context.Background()
	runs := make(chan bool, 8)
	w := New(Options{Detector: source{state: healthy(), receive: runs}, Cloudflare: &fakeCloud{}, Verifier: verifier{}})
	kv := &countingKV{}
	env := fakeEnv()
	env.KV = kv
	id, v := ready(t, w, env, Send)
	if len(runs) != 1 || v.Branch.Kind != "configure" || len(v.Branch.Paths) != 1 || v.Branch.Paths[0].Branch != DirectSend {
		t.Fatalf("own-IP route: %+v runs=%d", v.Branch, len(runs))
	}
	if _, e := permissions(w, ctx, env, owner, id, strings.Repeat("a", 32), strings.Repeat("b", 32)); e != nil {
		t.Fatal(e)
	}
	before := kv.puts
	if v, e := w.Detect(ctx, env, owner, id, Send, "example.test", yes, false); e != nil || !v.Done || kv.puts != before {
		t.Fatalf("an unchanged poll wrote: %v puts %d→%d", e, before, kv.puts)
	}
	no := Answers{Route: RouteCloudflare}
	v, e := w.Detect(ctx, env, owner, id, Send, "example.test", no, false)
	if e != nil || !v.Done || len(runs) != 1 || kv.puts != before+1 {
		t.Fatalf("answer change: %+v %v runs=%d puts=%d", v, e, len(runs), kv.puts)
	}
	p := v.Branch.Paths
	if len(p) != 1 || p[0].Branch != RelaySend || !slices.Equal(p[0].Why, []string{"mail.setup.why.routeCloudflare"}) {
		t.Fatalf("paths %+v", p)
	}
	f, _ := w.load(ctx, env, owner, id)
	if f.Answers != no || f.Account != nil || f.Plan != nil {
		t.Fatalf("flow after answer change: %+v", f)
	}
	// "own" is the same source as none, so it changes nothing.
	if _, e := w.Detect(ctx, env, owner, id, Send, "example.test", Answers{Source: SourceOwn, Route: RouteCloudflare}, false); e != nil || kv.puts != before+1 {
		t.Fatalf("the same choice wrote: %v", e)
	}
	if _, e := w.Detect(ctx, env, owner, id, Send, "example.test", Answers{Route: "maybe"}, false); !errors.Is(e, ErrInvalid) {
		t.Fatalf("invalid answer: %v", e)
	}
}

// Every reason, path title and route text the wizard can show is in all nine
// locales, without a trailing full stop (the catalog's style).
func TestAnswerKeysInNineLocales(t *testing.T) {
	keys := []string{"mail.setup.route", "mail.setup.routeBody", "mail.setup.paths", ErrPlanChanged.Error(), "ui.setup.regeneratePreview"}
	for _, k := range RouteKeys {
		keys = append(keys, "mail.setup.route."+k)
	}
	keys = append(keys, "mail.setup.prereq", "mail.setup.prereq.receivePending", "mail.setup.prereq.receivePendingBody", "mail.setup.prereq.continueSend", "mail.setup.prereq.ready", "mail.setup.prereq.readyBody")
	keys = append(keys, "mail.setup.facts.others", "mail.setup.facts.unrelated", "mail.setup.facts.allFine", "mail.setup.facts.state."+FactProblem, "mail.setup.facts.state."+FactUnknown)
	for _, g := range []string{GroupMailPlus, GroupNetwork, GroupDNS, GroupCloudflare} {
		keys = append(keys, "mail.setup.facts.group."+g)
	}
	for _, what := range []string{"noDomain", "noMailbox"} {
		keys = append(keys, "mail.setup.prereq."+what, "mail.setup.prereq."+what+"Body")
	}
	for _, b := range []Branch{DirectSend, RelaySend, DirectReceive, RoutingReceive} {
		keys = append(keys, "mail.setup.path."+string(b))
	}
	for _, code := range WhyCodes {
		keys = append(keys, "mail.setup.why."+code)
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
			text := catalog[key]
			if text == "" || strings.HasSuffix(text, ".") || strings.HasSuffix(text, "。") {
				t.Fatalf("%s: missing or invalid %s", locale, key)
			}
		}
	}
}

// A plan prepared for the old answers is never stored or
// applied. All "yes" → slow preview pending → fixed IP "no" → the poll must
// not store the direct-send plan, and Apply must refuse without writing.
func TestChangedAnswerDiscardsAPendingPreview(t *testing.T) {
	env := fakeEnv()
	cloud := &slowCloud{fakeCloud: &fakeCloud{restorable: true, value: "original"}, delay: 300 * time.Millisecond}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: cloud, Verifier: verifier{result: Verification{Readback: true, Delivery: true}}})
	w.previewWait = 20 * time.Millisecond
	id, v := ready(t, w, env, Send)
	if v.Branch.Paths[0].Branch != DirectSend {
		t.Fatalf("the own-IP route must be direct: %+v", v.Branch.Paths)
	}
	ctx := context.Background()
	if _, e := permissions(w, ctx, env, owner, id, strings.Repeat("a", 32), strings.Repeat("b", 32)); e != nil {
		t.Fatal(e)
	}
	if p, e := w.Preview(ctx, env, owner, id, Configuration{}); e != nil || !p.Pending {
		t.Fatalf("first reply must be pending: %+v %v", p, e)
	}
	no := Answers{Route: RouteCloudflare}
	if v, e := w.Detect(ctx, env, owner, id, Send, "example.test", no, false); e != nil || v.Branch.Paths[0].Branch != RelaySend {
		t.Fatalf("answer change: %+v %v", v, e)
	}
	time.Sleep(400 * time.Millisecond) // the old preparation would have finished by now
	for range 20 {
		p, e := w.PollPreview(ctx, env, owner, id)
		if e == nil && !p.Pending {
			t.Fatalf("the old plan came back: %+v", p)
		}
		if e != nil {
			if !errors.Is(e, ErrStale) {
				t.Fatalf("poll: %v", e)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	f, _ := w.load(ctx, env, owner, id)
	if f.Plan != nil {
		t.Fatalf("the direct-send plan was stored: %+v", f.Plan)
	}
	if _, e := w.Apply(ctx, env, owner, id); e == nil {
		t.Fatal("applied without a plan for the current answers")
	}
	if cloud.writes != 0 {
		t.Fatalf("writes: %d", cloud.writes)
	}
}

// Defense in depth: a stored plan whose basis no longer matches the flow
// (answers changed under it) is refused by Apply with ErrStale, nothing written.
func TestApplyRefusesAPlanForOtherAnswers(t *testing.T) {
	env := fakeEnv()
	cloud := &fakeCloud{restorable: true, value: "original"}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: cloud, Verifier: verifier{result: Verification{Readback: true, Delivery: true}}})
	id, _ := ready(t, w, env, Send)
	preview(t, w, env, id)
	ctx := context.Background()
	f, err := w.load(ctx, env, owner, id)
	if err != nil || f.Plan == nil || f.Plan.Basis == "" {
		t.Fatalf("stored plan: %+v %v", f, err)
	}
	f.Answers.Route = RouteCloudflare // the plan stays, the decision moved
	if err := w.save(ctx, env, f); err != nil {
		t.Fatal(err)
	}
	if _, e := w.Apply(ctx, env, owner, id); !errors.Is(e, ErrPlanChanged) {
		t.Fatalf("apply: %v", e)
	}
	if g, _ := w.load(ctx, env, owner, id); g.Phase != PhaseNew || len(g.Applied) != 0 || cloud.writes != 0 {
		t.Fatalf("apply wrote: %+v writes=%d", g, cloud.writes)
	}
}

// Several checks bad and unclear at once. Every reason is
// named, in the fixed order: bad checks (in check order), then unclear checks.
func TestSeveralReasonsKeepTheirOrder(t *testing.T) {
	cases := []struct {
		name    string
		answers Answers
		mutate  func(*detect.State)
		want    []string
	}{
		{"all-send-checks-bad", yes, func(s *detect.State) {
			s.Network.Addressing = detect.Fact(detect.Changing)
			s.Network.PTR = detect.Fact([]string{})
			s.Network.FCrDNS = detect.Fact(false)
			s.Network.Outbound25 = detect.Fact(false)
			s.Network.DNSBL[0].Status = "listed"
		}, []string{"ipChanging", "ptrNone", "fcrdnsFail", "outboundBlocked", "dnsblListed"}},
		{"bad-then-unclear", yes, func(s *detect.State) {
			s.Network.FCrDNS = detect.Fact(false)
			s.Network.Outbound25 = detect.Unavailable[bool]()
			s.Network.DNSBL[0].Status = "unknown"
		}, []string{"fcrdnsFail", "outboundUnknown", "dnsblUnknown"}},
		{"listed-and-unclear-ptr", yes, func(s *detect.State) {
			s.Network.PTR = detect.Unavailable[[]string]()
			s.Network.FCrDNS = detect.Unavailable[bool]()
			s.Network.DNSBL = append(s.Network.DNSBL, detect.DNSBL{Provider: "other", Status: "listed"})
		}, []string{"dnsblListed", "ptrUnknown", "fcrdnsUnknown"}},
		{"ip-unknown-hides-its-own-checks", yes, func(s *detect.State) {
			s.Network.EgressIPv4 = detect.Unavailable[string]()
			s.Network.PTR = detect.Unavailable[[]string]()
			s.Network.FCrDNS = detect.Unavailable[bool]()
			s.Network.Outbound25 = detect.Unavailable[bool]()
			s.Network.DNSBL = []detect.DNSBL{{Provider: "unconfigured", Status: "unknown"}}
		}, []string{"ipUnknown", "outboundUnknown"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := healthy()
			tc.mutate(&s)
			d := Decide(s, Send, tc.answers)
			if d.Send != RelaySend || !slices.Equal(d.SendWhy, tc.want) {
				t.Fatalf("send %s why=%v, want %v", d.Send, d.SendWhy, tc.want)
			}
		})
	}
	s := healthy()
	s.Network.Addressing = detect.Fact(detect.Changing)
	s.Network.Inbound25 = detect.Fact(false)
	s.Network.EgressIPv4 = detect.Unavailable[string]()
	d := Decide(s, Receive, yes)
	if want := []string{"ipChanging", "inboundBlocked", "ipUnknown"}; d.Receive != RoutingReceive || !slices.Equal(d.ReceiveWhy, want) {
		t.Fatalf("receive why=%v, want %v", d.ReceiveWhy, want)
	}
}

// Both decides each direction on the one route and its own
// checks. Every route × a send-only bad check, a receive-only bad check, a
// shared bad check and good checks.
func TestBothDirectionsCrossed(t *testing.T) {
	checks := []struct {
		name                string
		mutate              func(*detect.State)
		sendBad, receiveBad string
	}{
		{"good", nil, "", ""},
		{"send-only-fcrdns", func(s *detect.State) { s.Network.FCrDNS = detect.Fact(false) }, "fcrdnsFail", ""},
		{"receive-only-inbound", func(s *detect.State) { s.Network.Inbound25 = detect.Fact(false) }, "", "inboundBlocked"},
		{"shared-ip-changing", func(s *detect.State) { s.Network.Addressing = detect.Fact(detect.Changing) }, "ipChanging", "ipChanging"},
	}
	for _, c := range checks {
		for _, route := range routes {
			t.Run(fmt.Sprintf("%s/route=%q", c.name, route), func(t *testing.T) {
				s := healthy()
				if c.mutate != nil {
					c.mutate(&s)
				}
				d := Decide(s, Both, Answers{Route: route})
				wantSend, wantReceive := DirectSend, DirectReceive
				if route != RouteDirect || c.sendBad != "" {
					wantSend = RelaySend
				}
				if route != RouteDirect || c.receiveBad != "" {
					wantReceive = RoutingReceive
				}
				if d.Send != wantSend || d.Receive != wantReceive {
					t.Fatalf("got send=%s receive=%s, want %s %s (%+v)", d.Send, d.Receive, wantSend, wantReceive, d)
				}
				// One direction's check never shows up in the other's reasons.
				if slices.Contains(d.SendWhy, "inboundBlocked") || slices.Contains(d.ReceiveWhy, "fcrdnsFail") {
					t.Fatalf("a direction names the other's reason: send=%v receive=%v", d.SendWhy, d.ReceiveWhy)
				}
				if route == RouteDirect && (c.sendBad != "" && d.SendWhy[0] != c.sendBad || c.receiveBad != "" && d.ReceiveWhy[0] != c.receiveBad) {
					t.Fatalf("a bad check must come first: send=%v receive=%v", d.SendWhy, d.ReceiveWhy)
				}
				if d.Gate != "" {
					t.Fatalf("both must not stop: %+v", d)
				}
			})
		}
	}
}

// hangingPlan blocks every preparation until it is canceled, and reports the
// cancellation.
type hangingPlan struct {
	*fakeCloud
	canceled chan struct{}
}

func (f *hangingPlan) Plan(ctx context.Context, _ core.Env, _ PlanRequest) (Prepared, error) {
	<-ctx.Done()
	close(f.canceled)
	return Prepared{}, ctx.Err()
}

// Layer 1 alone (Detect's dropPreview): changing an answer cancels the
// preparation running for the old answers. Nothing else cancels it.
func TestDetectCancelsThePreviewForOldAnswers(t *testing.T) {
	env := fakeEnv()
	cloud := &hangingPlan{fakeCloud: &fakeCloud{restorable: true}, canceled: make(chan struct{})}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: cloud, Verifier: verifier{}})
	w.previewWait = 10 * time.Millisecond
	id, _ := ready(t, w, env, Send)
	ctx := context.Background()
	if _, e := permissions(w, ctx, env, owner, id, strings.Repeat("a", 32), strings.Repeat("b", 32)); e != nil {
		t.Fatal(e)
	}
	if p, e := w.Preview(ctx, env, owner, id, Configuration{}); e != nil || !p.Pending {
		t.Fatalf("pending: %+v %v", p, e)
	}
	if _, e := w.Detect(ctx, env, owner, id, Send, "example.test", Answers{Route: RouteCloudflare}, false); e != nil {
		t.Fatal(e)
	}
	select {
	case <-cloud.canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("the preparation for the old answers kept running")
	}
	w.mu.Lock()
	left := w.previews[id]
	w.mu.Unlock()
	if left != nil {
		t.Fatal("the old preparation is still the flow's preview")
	}
}

// Layer 2 alone (awaitPreview's Basis check): the flow's answers change
// without Detect (another worker path, an old version's flow), so the job is
// still the flow's preview when it finishes. Its plan must not be stored.
func TestFinishedPreviewForOtherAnswersIsNotStored(t *testing.T) {
	env := fakeEnv()
	cloud := &slowCloud{fakeCloud: &fakeCloud{restorable: true, value: "original"}, delay: 100 * time.Millisecond}
	w := New(Options{Detector: source{state: healthy()}, Cloudflare: cloud, Verifier: verifier{}})
	w.previewWait = 10 * time.Millisecond
	id, _ := ready(t, w, env, Send)
	ctx := context.Background()
	if _, e := permissions(w, ctx, env, owner, id, strings.Repeat("a", 32), strings.Repeat("b", 32)); e != nil {
		t.Fatal(e)
	}
	if p, e := w.Preview(ctx, env, owner, id, Configuration{}); e != nil || !p.Pending {
		t.Fatalf("pending: %+v %v", p, e)
	}
	f, err := w.load(ctx, env, owner, id)
	if err != nil {
		t.Fatal(err)
	}
	f.Answers.Route = RouteCloudflare // bypasses Detect: the job stays current
	if err := w.save(ctx, env, f); err != nil {
		t.Fatal(err)
	}
	var e error
	for range 100 {
		var p PreviewView
		if p, e = w.PollPreview(ctx, env, owner, id); e != nil || !p.Pending {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !errors.Is(e, ErrPlanChanged) {
		t.Fatalf("poll: %v", e)
	}
	if g, _ := w.load(ctx, env, owner, id); g.Plan != nil {
		t.Fatalf("the plan for the old answers was stored: %+v", g.Plan)
	}
}

// a test NAS (build 7): a domain MailPlus Server does not have stops at
// "configure MailPlus first" before any path is decided. The DNS, signing and
// relay facts the path needs are read again after MailPlus is set up, so the
// stop step shows no path on purpose.
func TestMissingDomainDecidesNoPath(t *testing.T) {
	s := healthy()
	s.Domains = detect.Fact([]detect.Domain{})
	d := Decide(s, Both, yes)
	if d.Gate != Minimal || d.Send != "" || d.Receive != "" || d.SendWhy != nil || d.ReceiveWhy != nil {
		t.Fatalf("decision %+v", d)
	}
	if b := New(Options{}).branch(s, Both, yes); b.Kind != "configureMailPlus" || len(b.Paths) != 0 {
		t.Fatalf("branch %+v", b)
	}
}
