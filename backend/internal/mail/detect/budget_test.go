package detect

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

func dsmFactsKnown(s State) bool {
	return s.Package.IsKnown() && s.SMTP.IsKnown() && s.Domains.IsKnown() && s.Accounts[s.Domain].IsKnown() &&
		s.Signing[s.Domain].IsKnown() && s.Delivery.IsKnown() && s.QueueSize.IsKnown()
}

// The sample-nas case: DSM answers in ~10 s per call. Before, every read was cut
// at 5 s, the package stayed unknown and so did every other MailPlus fact.
func TestDetectReadsMailPlusWhenDSMTakesTenSecondsPerCall(t *testing.T) {
	t.Parallel()
	ten := 10 * time.Second
	// The package list gates everything; the delivery reads run beside the
	// domain chain. Real time: ~10 s for the gate, ~10 s for the slow branch.
	dsm := &fakeDSM{slow: map[string]time.Duration{
		"SYNO.Core.Package.list":                     ten,
		"SYNO.MailPlusServer.SMTP.Delivery.get_type": ten,
		"SYNO.MailPlusServer.Queue.list":             ten,
	}}
	d := &Detector{Timeout: 20 * time.Millisecond}
	started := time.Now()
	s := d.Detect(context.Background(), core.Env{DSM: dsm}, Request{Domain: "example.test"})
	if !dsmFactsKnown(s) {
		t.Fatalf("10 s DSM calls lost MailPlus facts: %+v", s)
	}
	// The two slow reads after the gate ran concurrently, not one after another.
	if took := time.Since(started); took > 2*ten+5*time.Second {
		t.Fatalf("independent reads were serialized: %v", took)
	}
	for _, f := range Facts(s)[:8] {
		if f.Value == "unknown" || f.Params != nil && f.Params["code"] != "" {
			t.Fatalf("fact %s not read: %+v", f.LabelKey, f)
		}
	}
}

// fullTimeDSM makes every DSM call take exactly one unit (the per-call budget
// scaled down) and gives the domain 1000 accounts in ten pages of 100.
type fullTimeDSM struct {
	fakeDSM
	unit           time.Duration
	inFlight, most int
	// domains > 0 lists that many domains (d1.example.test …).
	domains int
}

func (f *fullTimeDSM) peak() int { f.mu.Lock(); defer f.mu.Unlock(); return f.most }

func (f *fullTimeDSM) Call(ctx context.Context, api, method string, version int, params map[string]any, out any) error {
	f.mu.Lock()
	f.inFlight++
	f.most = max(f.most, f.inFlight)
	f.mu.Unlock()
	defer func() { f.mu.Lock(); f.inFlight--; f.mu.Unlock() }()
	select {
	case <-time.After(f.unit):
	case <-ctx.Done():
		return core.ErrDSMTimeout
	}
	if api+"."+method == "SYNO.MailPlusServer.Domain.list" && f.domains > 0 {
		ds := []any{}
		for i := 1; i <= f.domains; i++ {
			ds = append(ds, map[string]any{"domain_id": i, "name": fmt.Sprintf("d%d.example.test", i)})
		}
		b, _ := json.Marshal(map[string]any{"domains": ds})
		return json.Unmarshal(b, out)
	}
	if api+"."+method != "SYNO.MailPlusServer.Domain.User.list" {
		return f.fakeDSM.Call(ctx, api, method, version, params, out)
	}
	f.mu.Lock()
	f.calls = append(f.calls, api+"."+method)
	f.mu.Unlock()
	offset := params["offset"].(int)
	users := []any{}
	for i := offset; i < offset+100 && i < 1000; i++ {
		users = append(users, map[string]any{"id": i + 1, "name": fmt.Sprintf("u%d", i), "is_activated": true})
	}
	b, _ := json.Marshal(map[string]any{"users": users, "total": 1000})
	return json.Unmarshal(b, out)
}

// The pass budget holds under slot contention. Every call takes its whole
// per-call budget, the domain has 1000 accounts (ten pages), and the other
// reads (SMTP, four delivery reads, queue, two licence reads, DKIM) compete
// for the executor's two slots at the same time. Before, the account chain
// re-queued behind them for every page and read only part of its pages
// within the fourteen units; now it has a lane of its own.
func TestDSMPassBudgetHoldsUnderSlotContention(t *testing.T) {
	t.Parallel()
	// Large enough that scheduler noise under load stays well inside the
	// one-unit margin (13 of 14 units).
	const unit = 500 * time.Millisecond
	scale := func(d time.Duration) time.Duration { return d / core.DSMReadTimeout * unit }
	dsm := &fullTimeDSM{unit: unit}
	d := &Detector{Timeout: 20 * time.Millisecond, DSMBudget: scale(DSMPassBudget)}
	started := time.Now()
	s := d.Detect(context.Background(), core.Env{DSM: dsm}, Request{Domain: "example.test"})
	took := time.Since(started)
	a := s.Accounts["example.test"]
	if !a.IsKnown() || len(a.Value) != 1000 {
		pages := 0
		for _, c := range dsm.called() {
			if c == "SYNO.MailPlusServer.Domain.User.list" {
				pages++
			}
		}
		t.Fatalf("accounts %s after %v: %d/10 pages read within %v", a.Detail, took, pages, scale(DSMPassBudget))
	}
	if !dsmFactsKnown(s) || !s.License.IsKnown() {
		t.Fatalf("a read beside the chain was cut: %+v", s)
	}
	// Never more than the executor's two slots at once.
	if dsm.peak() > core.DSMSlots {
		t.Fatalf("%d concurrent DSM calls", dsm.peak())
	}
	inner := func(d time.Duration) time.Duration { return d - min(5*time.Second, d/4) }
	// Three hops each keep a reply reserve (core.DSMReadTimeout): client,
	// deadline_ms, and the executor's DSM command layer.
	if inner(inner(inner(core.DSMReadTimeout))) < 2*time.Minute {
		t.Fatal("the executor must get at least two minutes per DSM read")
	}
}

// The diagnosis snapshot reads ten domains' DKIM beside the other reads, every
// call at its full time, within the same pass.
func TestDSMPassBudgetHoldsForTheSnapshotOfTenDomains(t *testing.T) {
	t.Parallel()
	const unit = 500 * time.Millisecond
	dsm := &fullTimeDSM{unit: unit, domains: 10}
	d := &Detector{DSMBudget: DSMPassBudget / core.DSMReadTimeout * unit}
	s := d.ReadMailPlus(context.Background(), core.Env{DSM: dsm})
	for i := 1; i <= 10; i++ {
		if sign := s.Signing[fmt.Sprintf("d%d.example.test", i)]; !sign.IsKnown() {
			t.Fatalf("DKIM of domain %d: %s", i, sign.Detail)
		}
	}
	if !s.SMTP.IsKnown() || !s.Delivery.IsKnown() || !s.QueueSize.IsKnown() || !s.License.IsKnown() || dsm.peak() > core.DSMSlots {
		t.Fatalf("snapshot cut or over the slots (%d): %+v", dsm.peak(), s)
	}
}

func TestUnreadMailPlusKeepsItsCause(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		cause  string
		key    string
		params map[string]string
	}{
		{"timeout", core.ErrDSMTimeout, core.CauseTimeout, "mail.setup.cause.timeout", nil},
		{"authority", core.AuthorityRequired{Profile: "mail-read"}, core.CauseAuthority, "mail.setup.cause.authority", nil},
		{"dsm", core.DSMError{Code: 117}, "dsm_117", "mail.setup.cause.dsm", map[string]string{"code": "117"}},
		{"other", context.Canceled, core.CauseUnavailable, "mail.setup.cause.unavailable", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dsm := &fakeDSM{errs: map[string]error{"SYNO.Core.Package.list": tc.err}}
			s := (&Detector{Timeout: 20 * time.Millisecond}).Detect(context.Background(), core.Env{DSM: dsm}, Request{Domain: "example.test"})
			if s.Package.IsKnown() || s.Package.Detail != tc.cause {
				t.Fatalf("package = %+v, want cause %s", s.Package, tc.cause)
			}
			// Facts not read because the gate failed say the same cause.
			if s.SMTP.Detail != tc.cause || s.Delivery.Detail != tc.cause || s.Accounts[s.Domain].Detail != tc.cause {
				t.Fatalf("dependent facts lost the cause: %+v %+v %+v", s.SMTP, s.Delivery, s.Accounts)
			}
			f := Facts(s)[0]
			if f.Value != tc.key || len(f.Params) != len(tc.params) || f.Params["code"] != tc.params["code"] {
				t.Fatalf("package fact = %+v, want %s %v", f, tc.key, tc.params)
			}
		})
	}
}

func TestDSMPassBudgetEndsAStuckReadAsTimeout(t *testing.T) {
	dsm := &fakeDSM{slow: map[string]time.Duration{"SYNO.MailPlusServer.SMTP.Delivery.get_type": time.Minute}}
	d := &Detector{Timeout: 20 * time.Millisecond, DSMBudget: 200 * time.Millisecond}
	s := d.Detect(context.Background(), core.Env{DSM: dsm}, Request{Domain: "example.test"})
	if !s.Package.IsKnown() || !s.SMTP.IsKnown() || s.Delivery.IsKnown() || s.Delivery.Detail != core.CauseTimeout {
		t.Fatalf("a stuck read must end as probe_timeout and keep the others: %+v %+v", s.SMTP, s.Delivery)
	}
}

func TestReadMailPlusReadsEveryDomainWithoutAccountsOrNetwork(t *testing.T) {
	dsm := &fakeDSM{}
	s := (&Detector{}).ReadMailPlus(context.Background(), core.Env{DSM: dsm})
	if !s.Package.IsKnown() || !s.Signing["example.test"].IsKnown() || !s.Delivery.IsKnown() || !s.QueueSize.IsKnown() {
		t.Fatalf("snapshot read incomplete: %+v", s)
	}
	for _, call := range dsm.called() {
		if call == "SYNO.MailPlusServer.Domain.User.list" {
			t.Fatal("the diagnosis snapshot must not page through accounts")
		}
	}
}
