package diagnose

import (
	"fmt"
	"net"
	"testing"
)

// timeoutErr is a net.Error that is not a *net.DNSError.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// Lookup errors reach the classifier wrapped; it must follow the chain.
func TestDNSClassificationFollowsWrappedErrors(t *testing.T) {
	notFound := fmt.Errorf("lookup: %w", &net.DNSError{IsNotFound: true, Name: "secret.dqs.example"})
	if got := dnsResult(nil, notFound); got.Status != "missing" || got.Detail != "DNS name or record not found" {
		t.Fatalf("wrapped NXDOMAIN: %+v", got)
	}
	timeout := fmt.Errorf("lookup: %w", &net.DNSError{IsTimeout: true})
	if got := dnsResult(nil, timeout); got.Detail != "DNS timeout" {
		t.Fatalf("wrapped DNS timeout: %+v", got)
	}
	if got := safeError(fmt.Errorf("dial: %w", timeoutErr{})); got != "network timeout" {
		t.Fatalf("wrapped net timeout: %s", got)
	}
}
