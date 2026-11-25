package detect

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"SynoMailPlusSetupAssistant/internal/core"
)

// recordDSM answers the package list with packages and every other call with
// reply (or err), and records each call.
type recordDSM struct {
	packages string
	reply    string
	err      error
	calls    []string
}

func (d *recordDSM) Call(_ context.Context, api, method string, _ int, _ map[string]any, out any) error {
	d.calls = append(d.calls, api+" "+method)
	if api == "SYNO.Core.Package" {
		if d.packages == "fail" {
			return core.DSMError{Code: 117}
		}
		return json.Unmarshal([]byte(`{"packages":`+d.packages+`}`), out)
	}
	if d.err != nil {
		return d.err
	}
	return json.Unmarshal([]byte(d.reply), out)
}

type confidentialDSM struct {
	recordDSM
	sent int
}

func (c *confidentialDSM) CallConfidential(ctx context.Context, api, method string, v int, p map[string]any, out any) error {
	c.sent++
	return c.Call(ctx, api, method, v, p, out)
}

const (
	pkgRunning = `[{"id":"MailPlus-Server","version":"4.1.1-31785","additional":{"status":"running","installed_info":{}}}]`
	pkgStopped = `[{"id":"MailPlus-Server","version":"4.1.1-31785","additional":{"status":"stop","installed_info":{}}}]`
	pkgBroken  = `[{"id":"MailPlus-Server","version":"4.1.1-31785","additional":{"status":"running","installed_info":{"is_broken":true}}}]`
	pkgNone    = `[{"id":"MailPlus","version":"4.1.1","additional":{"status":"running","installed_info":{}}}]`
)

func TestStatusOfReadsTheExactPackage(t *testing.T) {
	for name, tc := range map[string]struct {
		packages string
		state    MailPlusState
		broken   bool
	}{
		"running":        {pkgRunning, MailPlusRunning, false},
		"stopped":        {pkgStopped, MailPlusStopped, false},
		"broken":         {pkgBroken, MailPlusStopped, true},
		"other id only":  {pkgNone, MailPlusNotInstalled, false},
		"no status":      {`[{"id":"MailPlus-Server","additional":{}}]`, MailPlusUnknown, false},
		"no list":        {`null`, MailPlusUnknown, false},
		"list refused":   {"fail", MailPlusUnknown, false},
		"empty packages": {`[]`, MailPlusNotInstalled, false},
	} {
		dsm := &recordDSM{packages: tc.packages}
		s, err := New().MailPlusStatus(context.Background(), core.Env{DSM: dsm})
		// Only a running MailPlus Server is asked whether it finished its first-run setup.
		calls := 1
		if tc.state == MailPlusRunning {
			calls = 2
		}
		if err != nil || s.State != tc.state || s.Broken != tc.broken || len(dsm.calls) != calls {
			t.Fatalf("%s: %+v %v %v", name, s, err, dsm.calls)
		}
		if tc.state == MailPlusUnknown && (s.CauseKey == "" || s.Cause == "") {
			t.Fatalf("%s: unknown without a cause: %+v", name, s)
		}
		if (s.State == MailPlusRunning) != (s.Err() == nil) {
			t.Fatalf("%s: Err %v", name, s.Err())
		}
	}
	// A DSM code is never the shown text: dsm_117 maps to the plain cause key.
	s, _ := New().MailPlusStatus(context.Background(), core.Env{DSM: &recordDSM{packages: "fail"}})
	if s.Cause != "dsm_117" || s.CauseKey != "mail.setup.cause.dsm" {
		t.Fatalf("%+v", s)
	}
}

// A running MailPlus Server says whether it finished its first-run setup; a
// failed read leaves that unknown and the precondition running.
func TestMailPlusStatusReadsTheFirstRunSetup(t *testing.T) {
	for name, tc := range map[string]struct {
		reply string
		err   error
		want  *bool
	}{
		"set up":     {reply: `{"plusserver_initialized":true,"mailserver_initialized":true,"is_migrating":false}`, want: ptr(true)},
		"first run":  {reply: `{"plusserver_initialized":false,"mailserver_initialized":false,"is_migrating":false}`, want: ptr(false)},
		"no field":   {reply: `{}`},
		"read fails": {err: core.DSMError{Code: 5604}},
	} {
		dsm := &recordDSM{packages: pkgRunning, reply: tc.reply, err: tc.err}
		s, err := New().MailPlusStatus(context.Background(), core.Env{DSM: dsm})
		if err != nil || s.State != MailPlusRunning || (s.SetUp == nil) != (tc.want == nil) || (s.SetUp != nil && *s.SetUp != *tc.want) {
			t.Fatalf("%s: %+v %v", name, s, err)
		}
		if dsm.calls[1] != "SYNO.MailPlusServer.Util initial_check" {
			t.Fatalf("%s: %v", name, dsm.calls)
		}
	}
	dsm := &recordDSM{packages: pkgStopped}
	if s, _ := New().MailPlusStatus(context.Background(), core.Env{DSM: dsm}); s.SetUp != nil || len(dsm.calls) != 1 {
		t.Fatalf("stopped: %+v %v", s, dsm.calls)
	}
}

func ptr[T any](v T) *T { return &v }

// A missing grant is the approval prompt, not "unknown".
func TestMailPlusStatusReturnsTheAuthorityRefusal(t *testing.T) {
	_, err := New().MailPlusStatus(context.Background(), core.Env{DSM: refusingDSM{core.AuthorityRequired{Profile: "mail-read"}}})
	var authority core.AuthorityRequired
	if !errors.As(err, &authority) || authority.Profile != "mail-read" {
		t.Fatalf("%v", err)
	}
	_, err = New().MailPlusStatus(context.Background(), core.Env{DSM: refusingDSM{core.ErrNoAdmin}})
	if !errors.Is(err, core.ErrNoAdmin) {
		t.Fatalf("%v", err)
	}
}

type refusingDSM struct{ err error }

func (r refusingDSM) Call(context.Context, string, string, int, map[string]any, any) error {
	return r.err
}

// The gate: once a package read through it says MailPlus Server does not
// run, no SYNO.MailPlusServer call is sent (reads and confidential writes).
func TestGateRefusesMailPlusCallsAfterAPackageReadSaysNotRunning(t *testing.T) {
	for name, tc := range map[string]struct {
		packages string
		state    MailPlusState
		cause    string
	}{
		"not installed": {pkgNone, MailPlusNotInstalled, CauseMailPlusNotInstalled},
		"stopped":       {pkgStopped, MailPlusStopped, CauseMailPlusNotRunning},
		"broken":        {pkgBroken, MailPlusStopped, CauseMailPlusNotRunning},
	} {
		inner := &confidentialDSM{recordDSM: recordDSM{packages: tc.packages, reply: `{}`}}
		g := Gate(inner, nil)
		if ReadPackage(context.Background(), g).IsKnown() != true {
			t.Fatalf("%s: package read failed", name)
		}
		err := g.Call(context.Background(), "SYNO.MailPlusServer.Domain", "list", 1, nil, &struct{}{})
		var refused MailPlusUnavailable
		if !errors.As(err, &refused) || refused.State != tc.state || core.Cause(err) != tc.cause || !errors.Is(err, core.ErrUnavailable) {
			t.Fatalf("%s: %v (cause %s)", name, err, core.Cause(err))
		}
		c, ok := g.(confidential)
		if !ok {
			t.Fatalf("%s: the gate hid the confidential transport", name)
		}
		if err := c.CallConfidential(context.Background(), "SYNO.MailPlusServer.SMTP.Delivery", "set_multiple", 3, nil, &struct{}{}); !errors.As(err, &refused) {
			t.Fatalf("%s: confidential call sent: %v", name, err)
		}
		if len(inner.calls) != 1 || inner.sent != 0 {
			t.Fatalf("%s: MailPlus Server called: %v", name, inner.calls)
		}
		// Other DSM APIs are not MailPlus Server's: they pass.
		if err := g.Call(context.Background(), "SYNO.Core.Network", "get", 2, nil, &struct{}{}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// Running (or not read yet): calls pass; DSM's "no such API" (102) on a
// MailPlus Server call is the typed refusal, never the raw code.
func TestGatePassesWhenRunningAndTypesAMissingAPI(t *testing.T) {
	inner := &recordDSM{packages: pkgRunning, reply: `{"domains":[]}`}
	g := Gate(inner, nil)
	if _, ok := g.(confidential); ok {
		t.Fatal("a plain transport became confidential")
	}
	_ = ReadPackage(context.Background(), g)
	if err := g.Call(context.Background(), "SYNO.MailPlusServer.Domain", "list", 1, nil, &struct{}{}); err != nil || len(inner.calls) != 2 {
		t.Fatalf("%v %v", err, inner.calls)
	}
	missing := Gate(&recordDSM{err: core.DSMError{Code: 102}}, nil)
	err := missing.Call(context.Background(), "SYNO.MailPlusServer.Domain", "list", 1, nil, &struct{}{})
	var refused MailPlusUnavailable
	if !errors.As(err, &refused) || refused.State != MailPlusUnknown || core.Cause(err) != CauseMailPlusAPIMissing {
		t.Fatalf("%v (%s)", err, core.Cause(err))
	}
	key, params := CauseKey(core.Cause(err))
	if key != "mail.setup.cause.mailplusApiMissing" || params["code"] != "" {
		t.Fatalf("%s %v", key, params)
	}
	// Another DSM error passes as it was (its code stays for the log).
	other := Gate(&recordDSM{err: core.DSMError{Code: 105}}, nil)
	if err := other.Call(context.Background(), "SYNO.MailPlusServer.Domain", "list", 1, nil, &struct{}{}); core.Cause(err) != "dsm_105" {
		t.Fatalf("%v", err)
	}
	if Gate(nil, nil) != nil || Gate(g, nil) != g {
		t.Fatal("Gate must not wrap nil or itself")
	}
}

// The detection pass through the gate: MailPlus Server not installed means
// the package read is the only DSM call.
func TestDetectionThroughTheGateReadsOnlyThePackage(t *testing.T) {
	inner := &recordDSM{packages: pkgNone, reply: `{}`}
	s := New().ReadMailPlus(context.Background(), core.Env{DSM: Gate(inner, nil)})
	if StatusOf(s.Package).State != MailPlusNotInstalled || len(inner.calls) != 1 {
		t.Fatalf("%+v %v", s.Package, inner.calls)
	}
}
