package cloudflare

import (
	"errors"
	"fmt"
	"testing"
)

func TestAsErrorFollowsWrappedErrors(t *testing.T) {
	typed := &Error{Kind: ErrPermission, Operation: "token policies"}
	if got := asError(fmt.Errorf("read: %w", typed)); got != typed {
		t.Fatalf("wrapped typed error lost: %v", got)
	}
	if got := asError(errors.New("other")); got != nil {
		t.Fatalf("unrelated error became typed: %v", got)
	}
}

func TestPermissionRefusedOnlyForDocumentedCodes(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want bool
	}{
		"10000":          {&Error{Status: 403, Kind: ErrPermission, Codes: []int{10000}}, true},
		"9109":           {&Error{Status: 403, Kind: ErrAuth, Codes: []int{9109}}, true},
		"no code":        {&Error{Status: 403, Kind: ErrPermission}, false},
		"other code":     {&Error{Status: 403, Kind: ErrPermission, Codes: []int{1002}}, false},
		"mixed codes":    {&Error{Status: 403, Kind: ErrPermission, Codes: []int{10000, 1002}}, false},
		"plan limit":     {&Error{Status: 403, Kind: ErrPlanLimit, Codes: []int{10000}}, false},
		"not a 403":      {&Error{Status: 401, Kind: ErrAuth, Codes: []int{10000}}, false},
		"not a CF error": {errors.New("x"), false},
	} {
		if got := PermissionRefused(c.err); got != c.want {
			t.Errorf("%s: got %v", name, got)
		}
	}
}

// Email Sending on Workers Free: a 402, or a refusal naming Workers Paid or
// an entitlement, is a plan answer; a bare 403 or a server error is not.
func TestPlanLimitedNamesPlanRefusals(t *testing.T) {
	for _, c := range []struct {
		status  int
		message string
		want    bool
	}{
		{402, "payment required", true},
		{403, "Email Sending requires the Workers Paid plan", true},
		{403, "This account is missing the required entitlement", true},
		{403, "Authentication error", false},
		{500, "internal error", false},
	} {
		if got := PlanLimited(classify(c.status, []apiIssue{{Code: 10000, Message: c.message}})); got != c.want {
			t.Fatalf("%d %q: %v", c.status, c.message, got)
		}
	}
	if PlanLimited(nil) {
		t.Fatal("nil")
	}
}
