package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"os"
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

// Workers Free sends only to the account's verified destination addresses.
// The REST send refuses any other recipient with HTTP 403, code 10208
// (email.sending.error.email.recipient_plan_restricted). The fixture follows
// Cloudflare's documented error table; it was not captured live (no Free
// account with a zone was available).
func TestSendRecipientPlanRestricted(t *testing.T) {
	raw, err := os.ReadFile("testdata/send-recipient-plan-restricted.json")
	if err != nil {
		t.Fatal(err)
	}
	c := fixture(t, exchange{method: "POST", path: "/accounts/acct/email/sending/send", status: 403, raw: string(raw)})
	_, err = c.SendMessage(context.Background(), "acct", "admin@mail.example.test", "admin@mail.example.test", "check", "body")
	if !PlanLimited(err) || !RecipientPlanRestricted(err) || PermissionRefused(err) {
		t.Fatalf("restricted recipient: %v", err)
	}
	// Another plan answer is not the recipient restriction.
	other := classify(402, []apiIssue{{Code: 1, Message: "payment required"}})
	if !PlanLimited(other) || RecipientPlanRestricted(other) {
		t.Fatalf("other plan answer: %v", other)
	}
	// An account without Email Sending at all is a plan answer too.
	if e := classify(403, []apiIssue{{Code: 10105, Message: "email.sending.error.authentication.not_entitled"}}); !PlanLimited(e) || RecipientPlanRestricted(e) {
		t.Fatalf("not entitled: %v", e)
	}
	// A token without Email Sending: Edit stays a permission answer.
	forbidden := classify(403, []apiIssue{{Code: 10102, Message: "email.sending.error.authentication.forbidden"}})
	if PlanLimited(forbidden) || RecipientPlanRestricted(forbidden) {
		t.Fatalf("forbidden: %v", forbidden)
	}
}
