package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Upstream isolates every external SMTP call. Open returns only after the peer
// has accepted AUTH, the entire envelope, and DATA with 354.
type Upstream interface {
	Open(context.Context, string, string, []string) (Transaction, error)
	Test(context.Context, string) error
}

// Transaction writes dot-decoded bytes. Commit sends the terminator and waits
// for exactly 250. Close aborts an unfinished body without a terminator.
type Transaction interface {
	io.Writer
	Commit() error
	Close() error
}

type smtpUpstream struct {
	address string
	roots   *x509.CertPool // private test CA injection; production uses system roots
	timeout time.Duration
}

func cloudflareUpstream() *smtpUpstream {
	return &smtpUpstream{address: "smtp.mx.cloudflare.net:465", timeout: sessionTimeout}
}

// Never include peer text or transport errors: either may echo a credential.
// enhanced is only the RFC 3463 status code of a refusal (digits and dots,
// validated), never the text after it.
type upstreamError struct {
	stage    string
	code     int
	enhanced string
}

// enhancedStatus returns the RFC 3463 enhanced status code that starts an
// SMTP reply text ("5.7.1 ..."), or "" when there is none.
func enhancedStatus(text string) string {
	word, _, _ := strings.Cut(text, " ")
	parts := strings.Split(word, ".")
	if len(parts) != 3 || len(parts[0]) != 1 || parts[0] < "2" || parts[0] > "5" {
		return ""
	}
	for _, part := range parts[1:] {
		if len(part) < 1 || len(part) > 3 {
			return ""
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return ""
			}
		}
	}
	return word
}

// RecipientPlanRefused: the upstream refused a recipient with 550 5.7.1 at
// RCPT TO. Cloudflare documents this as the Workers Free refusal of any
// recipient that is not one of the account's verified destination addresses
// (sending to anyone needs Workers Paid). Not yet observed live.
func RecipientPlanRefused(err error) bool {
	var u upstreamError
	return errors.As(err, &u) && u.stage == "rcpt" && u.code == 550 && u.enhanced == "5.7.1"
}

func (e upstreamError) Error() string {
	return fmt.Sprintf("mail.relay.upstream_%s/%d", e.stage, e.code)
}

func readLine(p *textproto.Conn) (string, error) {
	b, err := p.R.ReadSlice('\n')
	if err != nil || len(b) > 4096 {
		return "", errors.New("mail.relay.protocol_line")
	}
	if len(b) < 2 || b[len(b)-2] != '\r' {
		return "", errors.New("mail.relay.protocol_line")
	}
	return string(b[:len(b)-2]), nil
}

func protocolConn(c net.Conn) *textproto.Conn {
	p := textproto.NewConn(c)
	p.R = bufio.NewReaderSize(c, 4096)
	return p
}

// Limit both single lines and multiline reply totals; textproto.ReadResponse
// alone permits an unbounded multiline reply from a broken/malicious peer.
func response(p *textproto.Conn, stage string, want int) error {
	code := 0
	for total := 0; total < 64<<10; {
		line, err := readLine(p)
		if err != nil || len(line) < 4 {
			return upstreamError{stage: stage, code: 0}
		}
		total += len(line) + 2
		n, err := strconv.Atoi(line[:3])
		if err != nil || n < 100 || n > 599 || (code != 0 && n != code) {
			return upstreamError{stage: stage, code: 0}
		}
		code = n
		switch line[3] {
		case '-':
			continue
		case ' ':
			if (want < 100 && code/10 == want) || code == want {
				return nil
			}
			return upstreamError{stage: stage, code: code, enhanced: enhancedStatus(line[4:])}
		default:
			return upstreamError{stage: stage, code: 0}
		}
	}
	return upstreamError{stage: stage, code: 0}
}

func command(p *textproto.Conn, stage string, want int, format string, args ...any) error {
	if err := p.PrintfLine(format, args...); err != nil {
		return upstreamError{stage: stage, code: 0}
	}
	return response(p, stage, want)
}

type smtpTransaction struct {
	conn   net.Conn
	p      *textproto.Conn
	writer io.WriteCloser
	stop   func() bool
	once   sync.Once
}

func (t *smtpTransaction) Write(b []byte) (int, error) {
	n, err := t.writer.Write(b)
	if err != nil {
		return n, upstreamError{stage: "stream", code: 0}
	}
	return n, nil
}
func (t *smtpTransaction) Commit() error {
	if err := t.writer.Close(); err != nil {
		return upstreamError{stage: "commit", code: 0}
	}
	return response(t.p, "commit", 250)
}
func (t *smtpTransaction) Close() error {
	t.once.Do(func() { t.stop(); t.conn.Close() })
	return nil
}

func (u *smtpUpstream) connect(ctx context.Context, token string) (*smtpTransaction, error) {
	host, _, err := net.SplitHostPort(u.address)
	if err != nil {
		return nil, upstreamError{stage: "address", code: 0}
	}
	timeout := u.timeout
	if timeout <= 0 {
		timeout = sessionTimeout
	}
	// Spend at most half the dial budget on IPv4, leaving room for IPv6.
	dialCtx, cancel := context.WithTimeout(ctx, min(15*time.Second, timeout))
	defer cancel()
	v4ctx, v4cancel := context.WithTimeout(dialCtx, min(7*time.Second, timeout/2))
	raw, err := (&net.Dialer{}).DialContext(v4ctx, "tcp4", u.address)
	v4cancel()
	if err != nil {
		raw, err = (&net.Dialer{}).DialContext(dialCtx, "tcp6", u.address)
	}
	if err != nil {
		return nil, upstreamError{stage: "connect", code: 0}
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	raw.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	conn := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: u.roots, MinVersion: tls.VersionTLS12})
	t := &smtpTransaction{conn: conn, stop: stop}
	fail := func(err error) (*smtpTransaction, error) { t.Close(); return nil, err }
	if conn.HandshakeContext(ctx) != nil {
		return fail(upstreamError{stage: "tls", code: 0})
	}
	t.p = protocolConn(conn)
	if err = response(t.p, "greeting", 220); err != nil {
		return fail(err)
	}
	if err = command(t.p, "ehlo", 250, "EHLO homekeeper.invalid"); err != nil {
		return fail(err)
	}
	auth := base64.StdEncoding.EncodeToString([]byte("\x00api_token\x00" + token))
	if err = command(t.p, "auth", 235, "AUTH PLAIN %s", auth); err != nil {
		return fail(err)
	}
	return t, nil
}

func (u *smtpUpstream) Test(ctx context.Context, token string) error {
	t, err := u.connect(ctx, token)
	if err != nil {
		return err
	}
	// Close after AUTH; do not require a cooperative QUIT response.
	return t.Close()
}

func (u *smtpUpstream) Open(ctx context.Context, token, from string, to []string) (Transaction, error) {
	// Envelope values are parsed locally, but keep the transport boundary safe
	// even for callers other than the local SMTP server.
	if !safePath(from, true) || len(to) == 0 || len(to) > MaxRecipients {
		return nil, upstreamError{stage: "envelope", code: 0}
	}
	for _, rcpt := range to {
		if !safePath(rcpt, false) {
			return nil, upstreamError{stage: "envelope", code: 0}
		}
	}
	t, err := u.connect(ctx, token)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (Transaction, error) { t.Close(); return nil, err }
	if err = command(t.p, "mail", 250, "MAIL FROM:%s", from); err != nil {
		return fail(err)
	}
	for _, rcpt := range to {
		if err = command(t.p, "rcpt", 25, "RCPT TO:%s", rcpt); err != nil {
			return fail(err)
		}
	}
	if err = command(t.p, "data", 354, "DATA"); err != nil {
		return fail(err)
	}
	t.writer = t.p.DotWriter()
	return t, nil
}

func safePath(path string, empty bool) bool {
	if len(path) < 2 || len(path) > 256 || path[0] != '<' || path[len(path)-1] != '>' {
		return false
	}
	body := path[1 : len(path)-1]
	if body == "" {
		return empty
	}
	for _, r := range body {
		if r <= 32 || r >= 127 || strings.ContainsRune("<>", r) {
			return false
		}
	}
	return strings.Contains(body, "@")
}
