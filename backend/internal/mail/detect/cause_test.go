package detect

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"

	sdkapi "github.com/synopackageland/syno-pkg-land-sdk/api"
)

// replyDSM replaces the replies of some methods (api.method → data).
type replyDSM struct {
	fakeDSM
	replies map[string]any
}

func (r *replyDSM) Call(ctx context.Context, api, method string, version int, params map[string]any, out any) error {
	if v, ok := r.replies[api+"."+method]; ok {
		b, _ := json.Marshal(v)
		return json.Unmarshal(b, out)
	}
	return r.fakeDSM.Call(ctx, api, method, version, params, out)
}

// a test NAS build 14: sample-nas.test is in MailPlus Server's domain list, yet
// its accounts and DKIM showed a bare "unknown" (probe_unavailable), which
// hid which of several things went wrong. Each now has its own cause; none
// says "not in MailPlus" for a domain the list has.
func TestAccountAndDKIMReadsOfAListedDomainNameTheirCause(t *testing.T) {
	user := "SYNO.MailPlusServer.Domain.User.list"
	dkim := "SYNO.MailPlusServer.Domain.get_security"
	for _, tc := range []struct {
		name   string
		dsm    core.DSM
		key    string
		params map[string]string
	}{
		{"reply-lacks-fields", &replyDSM{replies: map[string]any{
			user: map[string]any{"users": []any{map[string]any{"id": 1, "name": "a"}}, "total": 1},
			dkim: map[string]any{"dkim_selector": ""},
		}}, "mail.setup.cause.incomplete", nil},
		{"reply-without-users", &replyDSM{replies: map[string]any{
			user: map[string]any{"total": 0},
			dkim: map[string]any{},
		}}, "mail.setup.cause.incomplete", nil},
		{"unreadable-reply", &fakeDSM{errs: map[string]error{user: core.ErrDSMBadResponse, dkim: core.ErrDSMBadResponse}}, "mail.setup.cause.badResponse", nil},
		{"failure-without-code", &fakeDSM{errs: map[string]error{user: core.DSMError{}, dkim: core.DSMError{}}}, "mail.setup.cause.badResponse", nil},
		{"executor-refusal", &fakeDSM{errs: map[string]error{user: &sdkapi.Error{Code: "POLICY_DENIED", Message: "secret detail"}, dkim: &sdkapi.Error{Code: "POLICY_DENIED"}}}, "mail.setup.cause.executorApproval", nil},
		{"dsm-code", &fakeDSM{errs: map[string]error{user: core.DSMError{Code: 5566}, dkim: core.DSMError{Code: 5566}}}, "mail.setup.cause.dsm", map[string]string{"code": "5566"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := (&Detector{Timeout: 20 * time.Millisecond}).Detect(context.Background(), core.Env{DSM: tc.dsm}, Request{Domain: "example.test"})
			if !s.Domains.IsKnown() || len(s.Domains.Value) == 0 || s.Domains.Value[0].Name != "example.test" {
				t.Fatalf("domain list: %+v", s.Domains)
			}
			for _, f := range Facts(s) {
				if f.LabelKey != "mail.setup.fact.accounts" && f.LabelKey != "mail.setup.fact.dkim" {
					continue
				}
				if f.Value != tc.key || len(f.Params) != len(tc.params) || f.Params["code"] != tc.params["code"] {
					t.Errorf("%s = %s %v, want %s %v", f.LabelKey, f.Value, f.Params, tc.key, tc.params)
				}
			}
		})
	}
}

// An executor message never becomes a cause; an unexpected code stays
// generic.
func TestDSMCauseKeepsOnlyProtocolCodes(t *testing.T) {
	if c := dsmCause(&sdkapi.Error{Code: "bad code; rm -rf", Message: "x"}); c != core.CauseUnavailable {
		t.Fatal(c)
	}
	if c := dsmCause(context.Canceled); c != core.CauseUnavailable {
		t.Fatal(c)
	}
	if c := dsmCause(core.ErrDSMTimeout); c != core.CauseTimeout {
		t.Fatal(c)
	}
}

// Every cause the detector can produce has text in every locale.
func TestEveryCauseHasTextInEveryLocale(t *testing.T) {
	causes := []string{CauseUnsupported, CauseNotChecked, CauseNoDomain, CauseNotInMailPlus, CauseDNSUnknown, CauseIPUnknown, CausePTRNone,
		CauseIncomplete, CauseBadResponse, causeExecutor + "POLICY_DENIED", core.CauseTimeout, core.CauseAuthority, core.CauseTooLarge, "dsm_105", core.CauseUnavailable}
	for _, loc := range []string{"en", "zh-TW", "zh-CN", "ja", "ko", "de", "fr", "es", "it"} {
		texts := catalog(t, loc)
		for _, c := range causes {
			key, params := CauseKey(c)
			text := texts[key]
			if text == "" {
				t.Fatalf("%s: %s (%s) has no text", loc, key, c)
			}
			for _, m := range placeholder.FindAllStringSubmatch(text, -1) {
				if _, ok := params[m[1]]; !ok {
					t.Fatalf("%s: %s lacks {%s}", loc, key, m[1])
				}
			}
		}
	}
}

// executorCodes are the upper-case refusal codes of SDK protocol v1
// (spec/protocol/v1/errors.json, SDK v0.53.24) a DSM read can return, plus one
// the App does not know.
var executorCodes = []string{"AUTH_DENIED", "INELIGIBLE", "APP_DENIED", "ADMIN_REQUIRED", "DELEGATION_DENIED",
	"SCOPE_DENIED", "POLICY_DENIED", "PEER_DENIED", "PERMISSION_DENIED", "UNKNOWN_OP", "INVALID_REQUEST",
	"REQUEST_TOO_LARGE", "EXECUTOR_PAUSED", "EXECUTOR_STARTING", "STORAGE_ERROR", "INTERNAL", "WRITE_FAILED",
	"READ_FAILED", "DSM_FAILED", "ROOT_FAILED", "ROOT_TIMEOUT", "ROOT_BUSY", "ROOT_STAGING_FULL",
	"ROOT_JOB_NOT_FOUND", "PORTAL_FAILED", "NO_SPACE", "SCOPE_APPROVAL_STALE", "IDENTITY_CHANGED",
	"OPERATION_CANCELED", "CANCEL_REQUESTED", "CLEANUP_PENDING", "EXECUTOR_UNAVAILABLE", "APP_STOPPED",
	"APP_STARTING", "EXECUTOR_TOO_LARGE", "EXECUTOR_PROTOCOL", "WEBAPI_UNCERTAIN", "WEBAPI_REPLY_TOO_LARGE",
	"SOME_FUTURE_CODE"}

// Every executor refusal reads as plain words with what to do, in the short
// cause (facts, evidence) and in the full sentence (wizard, diagnose): no
// code, no placeholder, in every locale.
func TestExecutorRefusalsShowPlainWordsWithoutTheCode(t *testing.T) {
	rawCode := regexp.MustCompile(`\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b`)
	if got := ExecutorCauseKey("POLICY_DENIED"); got != "mail.setup.cause.executorApproval" {
		t.Fatal(got)
	}
	if got := ExecutorCauseKey("SOME_FUTURE_CODE"); got != "mail.setup.cause.executor" {
		t.Fatal(got)
	}
	for _, loc := range []string{"en", "zh-TW", "zh-CN", "ja", "ko", "de", "fr", "es", "it"} {
		texts := catalog(t, loc)
		for _, code := range executorCodes {
			cause := causeExecutor + code
			if !IsExecutorCause(cause) {
				t.Fatalf("%s is not an executor cause", cause)
			}
			key, params := CauseKey(cause)
			if len(params) != 0 || strings.Contains(key, code) {
				t.Fatalf("%s: %s %v carries the code", code, key, params)
			}
			full := "mail.setup.unreadable." + strings.TrimPrefix(key, "mail.setup.cause.")
			for _, k := range []string{key, full} {
				text := texts[k]
				if text == "" || strings.Contains(text, "{") || rawCode.MatchString(text) {
					t.Fatalf("%s: %s for %s is %q", loc, k, code, text)
				}
			}
		}
	}
}

// emittedCauses reads every Cause* string constant the backend declares, so a
// new reason fails this test until it has words in every locale.
func emittedCauses(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	fset := token.NewFileSet()
	err := filepath.WalkDir("../../", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			g, ok := decl.(*ast.GenDecl)
			if !ok || g.Tok != token.CONST {
				continue
			}
			for _, spec := range g.Specs {
				v := spec.(*ast.ValueSpec)
				for i, name := range v.Names {
					if !strings.HasPrefix(name.Name, "Cause") || i >= len(v.Values) {
						continue
					}
					if lit, ok := v.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						s, _ := strconv.Unquote(lit.Value)
						out[name.Name] = s
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEveryReasonHasPlainWordsInEveryLocale(t *testing.T) {
	causes := emittedCauses(t)
	if len(causes) < 18 {
		t.Fatalf("found only %d causes: %v", len(causes), causes)
	}
	// DSM codes: the mapped ones and an unmapped one.
	for _, c := range []string{"dsm_102", "dsm_105", "dsm_106", "dsm_9999", "something_new"} {
		causes[c] = c
	}
	placeholder := regexp.MustCompile(`\{(\w+)\}`)
	for _, loc := range []string{"en", "zh-TW", "zh-CN", "ja", "ko", "de", "fr", "es", "it"} {
		texts := catalog(t, loc)
		for name, cause := range causes {
			key, params := CauseKey(cause)
			full := "mail.setup.unreadable." + strings.TrimPrefix(key, "mail.setup.cause.")
			for _, k := range []string{key, full} {
				text := texts[k]
				if text == "" {
					t.Errorf("%s: %s (%s) has no %s", loc, name, cause, k)
					continue
				}
				for _, m := range placeholder.FindAllStringSubmatch(text, -1) {
					if m[1] == "code" || params[m[1]] == "" {
						t.Errorf("%s: %s shows {%s}", loc, k, m[1])
					}
				}
			}
		}
	}
}
