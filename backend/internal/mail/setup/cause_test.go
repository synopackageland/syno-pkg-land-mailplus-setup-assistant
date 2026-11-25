package setup

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

func TestUnreadMailPlusBranchSaysExactlyWhy(t *testing.T) {
	for _, tc := range []struct {
		cause, body string
		params      map[string]string
	}{
		{core.CauseTimeout, "mail.setup.unreadable.timeout", nil},
		{core.CauseAuthority, "mail.setup.unreadable.authority", nil},
		{"dsm_117", "mail.setup.unreadable.dsm", map[string]string{"code": "117"}},
		{"dsm_102", "mail.setup.unreadable.mailplusApiMissing", nil},
		{"dsm_105", "mail.setup.unreadable.dsmPermission", nil},
		{"dsm_119", "mail.setup.unreadable.dsmSession", nil},
		{detect.CauseUnsupported, "mail.setup.unreadable.unsupported", nil},
	} {
		s := healthy()
		s.Package = detect.Observation[detect.Package]{Status: detect.Unknown, Detail: tc.cause}
		d := Decide(s, Send, yes)
		if d.Reason != "unknown" || d.Cause != tc.cause {
			t.Fatalf("decision = %+v, want unknown/%s", d, tc.cause)
		}
		b := New(Options{}).branch(s, Send, yes)
		if b.Kind != "blocked" || b.TitleKey != "mail.setup.unreadable" || b.BodyKey != tc.body || b.Params["code"] != tc.params["code"] {
			t.Fatalf("branch = %+v, want %s", b, tc.body)
		}
	}
	// A DSM fact read later in the decision keeps its own cause.
	s := healthy()
	s.SMTP = detect.Observation[detect.SMTP]{Status: detect.Unknown, Detail: core.CauseTimeout}
	if d := Decide(s, Send, yes); d.Cause != core.CauseTimeout {
		t.Fatalf("SMTP cause lost: %+v", d)
	}
	// Missing evidence that is not a DSM read keeps the generic explanation.
	s = healthy()
	s.Network = detect.Network{}
	if b := New(Options{}).branch(s, Send, yes); b.Reason == "unknown" && b.TitleKey != "mail.setup.unknown" {
		t.Fatalf("non-DSM unknown claimed a DSM cause: %+v", b)
	}
}

func TestDetectJobOutlivesEveryDSMReadAtFullBudget(t *testing.T) {
	if DetectBudget <= detect.DSMPassBudget || detectRetention <= DetectBudget {
		t.Fatalf("job %v / retention %v must exceed the DSM pass %v", DetectBudget, detectRetention, detect.DSMPassBudget)
	}
	if DetectBudget < 20*time.Minute {
		t.Fatalf("detect job %v cannot hold many two-minute reads", DetectBudget)
	}
}

// blockedDetector blocks until canceled, then counts a fresh, fast run.
type blockedDetector struct {
	runs  atomic.Int32
	block atomic.Bool
}

func (b *blockedDetector) Detect(ctx context.Context, _ core.Env, r detect.Request) detect.State {
	b.runs.Add(1)
	if b.block.Load() {
		<-ctx.Done()
		return detect.State{Domain: r.Domain}
	}
	return healthy()
}

func TestAbandonedDetectionIsCanceledAndRunsAgain(t *testing.T) {
	bg := &core.Background{Abandon: 100 * time.Millisecond}
	d := &blockedDetector{}
	d.block.Store(true)
	w := New(Options{Detector: d, Background: bg})
	env := fakeEnv()
	ctx := context.Background()
	flow, _ := w.Start(ctx, env, owner)
	if v, e := w.Detect(ctx, env, owner, flow.ID, Send, "example.test", yes, false); e != nil || v.Done {
		t.Fatal(v, e)
	}
	done := make(chan struct{})
	go func() { bg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("unpolled detection kept running")
	}
	d.block.Store(false)
	var v DetectView
	for range 200 {
		var e error
		if v, e = w.Detect(ctx, env, owner, flow.ID, Send, "example.test", yes, false); e != nil || v.Done {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !v.Done || d.runs.Load() != 2 || v.Branch == nil || v.Branch.Reason == "unknown" {
		t.Fatalf("the cut detection was used: %+v runs=%d", v, d.runs.Load())
	}
}

// a test NAS: sample-nas.test exists in MailPlus but not in DNS. The address type
// is not checked by this version, but the administrator's answer stands for
// it; what stops the decision is the domain's DNS, and the branch names it.
func TestBlockedUnknownNamesTheMissingFacts(t *testing.T) {
	s := healthy()
	s.Network.Addressing = detect.Observation[detect.Addressing]{Status: detect.Unknown, Detail: detect.CauseNotChecked}
	s.DNS.Exists = detect.Check{Status: "missing"}
	s.DNS.Cloudflare = detect.Observation[bool]{Status: detect.Unknown, Detail: detect.CauseDNSUnknown}
	d := Decide(s, Send, yes)
	if d.Reason != "unknown" || d.Cause != "" || len(d.Missing) == 0 || d.Send != DirectSend {
		t.Fatalf("decision %+v", d)
	}
	b := New(Options{}).branch(s, Send, yes)
	if b.Kind != "blocked" || b.BodyKey != "mail.setup.unknownFactsBody" {
		t.Fatalf("branch %+v", b)
	}
	got := map[string]string{}
	for _, f := range b.Warnings {
		got[f.LabelKey] = f.Value
	}
	if got["mail.setup.fact.dns"] != "mail.setup.cause.dnsUnknown" || got["mail.setup.fact.domainDNS"] != "mail.setup.cause.noDomain" {
		t.Fatalf("missing facts not named: %v", got)
	}
	// The path the stop is about still says why it was chosen.
	if len(b.Paths) != 1 || b.Paths[0].TitleKey != "mail.setup.path.direct-send" {
		t.Fatalf("paths %+v", b.Paths)
	}
}

// Network facts the send path could not check no longer stop the wizard:
// unclear is not usable, so it recommends the relay and names the fact.
func TestUnclearNetworkFactsRecommendRelay(t *testing.T) {
	s := healthy()
	s.Network.PTR = detect.Observation[[]string]{Status: detect.Known, Value: []string{}}
	if d := Decide(s, Send, yes); d.Send != RelaySend || !reflect.DeepEqual(d.SendWhy, []string{"ptrNone"}) {
		t.Fatalf("empty PTR not named: %+v", d)
	}
	// IP unknown: its PTR, FCrDNS and blocklists were not read; one reason says so.
	s = healthy()
	s.Network.EgressIPv4 = detect.Observation[string]{Status: detect.Unknown, Detail: "probe_unavailable"}
	s.Network.PTR = detect.Observation[[]string]{Status: detect.Unknown, Detail: detect.CauseIPUnknown}
	s.Network.FCrDNS = detect.Observation[bool]{Status: detect.Unknown, Detail: detect.CauseIPUnknown}
	s.Network.DNSBL = []detect.DNSBL{{Provider: "unconfigured", Status: "unknown"}}
	if d := Decide(s, Send, yes); d.Send != RelaySend || !reflect.DeepEqual(d.SendWhy, []string{"ipUnknown"}) {
		t.Fatalf("unknown IP: %+v", d)
	}
}

// More than 1000 accounts stops at unknown with its own explanation.
func TestTooManyAccountsBranchSaysSo(t *testing.T) {
	s := healthy()
	s.Accounts[s.Domain] = detect.Observation[[]detect.Account]{Status: detect.Unknown, Detail: detect.CauseTooManyAccounts}
	d := Decide(s, Send, yes)
	if d.Reason != "unknown" || d.Cause != detect.CauseTooManyAccounts {
		t.Fatalf("decision = %+v", d)
	}
	b := New(Options{}).branch(s, Send, yes)
	if b.Kind != "blocked" || b.BodyKey != "mail.setup.unreadable.accountsTooLarge" {
		t.Fatalf("branch = %+v", b)
	}
}
