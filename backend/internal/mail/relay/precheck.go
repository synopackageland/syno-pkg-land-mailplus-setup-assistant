package relay

import "errors"

// NeedsConnectionPrecheck is the mail relay integration seam. After a failed upstream
// test or 451, retain the typed cause and call precheck.Runner.Run with
// precheck.MailRelay only if this returns true. A generic 451 is not sufficient
// evidence: AUTH, envelope and message refusals must stay in the mail flow.
// Never run probes in the SMTP delivery goroutine or a scheduled relay check.
func NeedsConnectionPrecheck(err error) bool {
	var failure upstreamError
	if !errors.As(err, &failure) {
		return false
	}
	return failure.stage == "connect" || failure.stage == "tls"
}
