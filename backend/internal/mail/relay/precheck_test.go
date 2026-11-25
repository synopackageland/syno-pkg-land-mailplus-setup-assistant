package relay

import (
	"errors"
	"fmt"
	"testing"
)

func TestConnectionPrecheckTrigger(t *testing.T) {
	for _, stage := range []string{"connect", "tls", "auth", "greeting", "ehlo", "mail", "rcpt", "data", "stream", "commit", "envelope", "address"} {
		err := fmt.Errorf("wrapped: %w", upstreamError{stage: stage, code: 0})
		if got := NeedsConnectionPrecheck(err); got != (stage == "connect" || stage == "tls") {
			t.Fatalf("wrong precheck trigger: %s", stage)
		}
	}
	if NeedsConnectionPrecheck(nil) || NeedsConnectionPrecheck(errors.New("451 4.4.0 Upstream temporarily unavailable")) {
		t.Fatal("generic SMTP failure ran precheck")
	}
}
