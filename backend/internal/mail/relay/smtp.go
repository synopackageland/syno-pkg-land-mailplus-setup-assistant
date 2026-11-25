package relay

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

type server struct {
	cert    tls.Certificate
	auth    AuthCredentials
	service *Service
	env     core.Env
}

// Accept only SIZE on MAIL (no unnegotiated SMTPUTF8/DSN/BINARYMIME).
// BODY=8BITMIME is accepted because the relay forwards those bytes unchanged.
func pathArg(arg, prefix string, sender bool) (string, bool) {
	if !strings.HasPrefix(strings.ToUpper(arg), prefix) {
		return "", false
	}
	value := strings.TrimSpace(arg[len(prefix):])
	end := strings.IndexByte(value, '>')
	if end < 0 {
		return "", false
	}
	path := value[:end+1]
	if !safePath(path, sender) {
		return "", false
	}
	seen := map[string]bool{}
	for _, extension := range strings.Fields(value[end+1:]) {
		name, v, _ := strings.Cut(strings.ToUpper(extension), "=")
		if !sender || seen[name] {
			return "", false
		}
		seen[name] = true
		switch name {
		case "SIZE":
			size, err := strconv.ParseUint(v, 10, 64)
			if err != nil || size > MaxSize {
				return "", false
			}
		case "BODY":
			if v != "8BITMIME" && v != "7BIT" {
				return "", false
			}
		default:
			return "", false
		}
	}
	return path, true
}

func (s *server) serve(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(s.service.timeout))
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	conn := raw
	p := protocolConn(conn)

	say := func(format string, args ...any) bool {
		if strings.HasPrefix(format, "5") || strings.HasPrefix(format, "452") {
			s.service.count("rejected")
		}
		return p.PrintfLine(format, args...) == nil
	}
	say("220 homekeeper ESMTP")
	var secured, authed, greeted bool
	var from string
	var recipients []string
	reset := func() { from = ""; recipients = nil }
	readAuth := func() (string, error) {
		line, e := readLine(p)
		if e != nil {
			return "", e
		}
		if len(line) > 4096 {
			return "", errors.New("auth too long")
		}
		b, e := base64.StdEncoding.DecodeString(line)
		return string(b), e
	}
	for {
		line, e := readLine(p)
		if e != nil {
			return
		}
		if len(line) > 4096 {
			say("500 5.5.2 Line too long")
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		verb = strings.ToUpper(verb)
		arg = strings.TrimSpace(arg)
		switch verb {
		case "EHLO", "HELO":
			greeted = true
			reset()
			if verb == "HELO" {
				say("250 homekeeper")
				continue
			}
			say("250-homekeeper")
			say("250-SIZE %d", MaxSize)
			if !secured {
				say("250-STARTTLS")
			} else {
				say("250-AUTH PLAIN LOGIN")
			}
			say("250 8BITMIME")
		case "STARTTLS":
			if secured || !greeted || arg != "" {
				say("503 5.5.1 Bad STARTTLS sequence")
				continue
			}
			if !say("220 2.0.0 Start TLS") {
				return
			}
			t := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12})
			if t.HandshakeContext(ctx) != nil {
				return
			}
			conn = t
			p = protocolConn(conn)
			secured = true
			authed = false
			greeted = false
			reset()
		case "AUTH":
			if !secured {
				say("538 5.7.11 Encryption required")
				continue
			}
			if !greeted || authed || from != "" {
				say("503 5.5.1 Bad AUTH sequence")
				continue
			}
			parts := strings.Fields(arg)
			if len(parts) == 0 {
				say("501 5.5.2 Missing mechanism")
				continue
			}
			var user, password string
			var err error
			switch strings.ToUpper(parts[0]) {
			case "PLAIN":
				var decoded string
				if len(parts) == 2 {
					var b []byte
					b, err = base64.StdEncoding.DecodeString(parts[1])
					decoded = string(b)
				} else if len(parts) == 1 {
					say("334 ")
					decoded, err = readAuth()
				} else {
					err = errors.New("bad auth")
				}
				v := strings.Split(decoded, "\x00")
				if len(v) == 3 && (v[0] == "" || v[0] == v[1]) {
					user, password = v[1], v[2]
				} else {
					err = errors.New("bad auth")
				}
			case "LOGIN":
				if len(parts) == 2 {
					var b []byte
					b, err = base64.StdEncoding.DecodeString(parts[1])
					user = string(b)
				} else if len(parts) == 1 {
					say("334 VXNlcm5hbWU6")
					user, err = readAuth()
				} else {
					err = errors.New("bad auth")
				}
				if err == nil {
					say("334 UGFzc3dvcmQ6")
					password, err = readAuth()
				}
			default:
				say("504 5.5.4 Unsupported mechanism")
				continue
			}
			if err == nil && equal(user, s.auth.Username) && equal(password, s.auth.Password) {
				authed = true
				say("235 2.7.0 Authenticated")
			} else {
				say("535 5.7.8 Authentication failed")
			}
		case "MAIL":
			if !greeted {
				say("503 5.5.1 EHLO required")
				continue
			}
			if !authed {
				say("530 5.7.0 Authentication required")
				continue
			}
			reset()
			var ok bool
			from, ok = pathArg(arg, "FROM:", true)
			if !ok {
				say("501 5.5.2 Bad sender")
				continue
			}
			say("250 2.1.0 Sender OK")
		case "RCPT":
			if !authed || from == "" {
				say("503 5.5.1 MAIL required")
				continue
			}
			rcpt, ok := pathArg(arg, "TO:", false)
			if !ok {
				say("501 5.5.2 Bad recipient")
				continue
			}
			if len(recipients) >= MaxRecipients {
				say("452 4.5.3 Recipient limit")
				continue
			}
			recipients = append(recipients, rcpt)
			say("250 2.1.5 Recipient OK")
		case "DATA":
			if !authed || len(recipients) == 0 || arg != "" {
				say("503 5.5.1 RCPT required")
				continue
			}
			token, e := upstreamToken(ctx, s.env)
			var up Transaction
			if e == nil {
				up, e = s.service.upstream.Open(ctx, token, from, recipients)
				// Open returns only after AUTH was answered: report whether
				// Cloudflare accepted the token (a refusal says nothing else).
				if e == nil || AuthRefused(e) {
					s.service.tokenResult(ctx, s.env, e != nil)
				}
			}
			if RecipientPlanRefused(e) {
				// Permanent: Workers Free sends only to the account's
				// verified addresses. Retrying cannot help, so MailPlus
				// returns the message to its sender now, with the reason.
				s.service.planRefused(ctx, s.env)
				say("550 5.7.1 Cloudflare Workers Free sends only to verified addresses; sending to anyone needs Workers Paid")
				reset()
				continue
			}
			if e != nil {
				s.service.count("deferred")
				s.service.lastError(e)
				// Otherwise always temporary: MailPlus keeps the message queued and
				// retries, also when Cloudflare refused the token (revoked
				// or rolled), so nothing bounces while a new one is entered.
				if AuthRefused(e) {
					say("451 4.7.0 Upstream login refused, try again later")
				} else {
					say("451 4.4.0 Upstream temporarily unavailable")
				}
				reset()
				continue
			}
			if !say("354 End data with <CRLF>.<CRLF>") {
				up.Close()
				s.service.count("deferred")
				return
			}
			s.service.count("accepted")
			// Decode/encode SMTP dots; the only retained bytes are IO buffers.
			n, copyErr := io.Copy(up, io.LimitReader(p.DotReader(), MaxSize+1))
			if n > MaxSize {
				up.Close() // never send the terminator for an oversized message
				s.service.lastError(errors.New("mail.relay.size_limit"))
				say("552 5.3.4 Message exceeds size limit")
				return // do not parse the remaining DATA as SMTP commands
			}
			if copyErr == nil {
				e = up.Commit()
			} else {
				e = upstreamError{stage: "stream", code: 0}
			}
			up.Close()
			if e != nil {
				s.service.count("deferred")
				s.service.lastError(e)
				say("451 4.4.0 Upstream delivery unconfirmed")
				return
			}
			s.service.sent(ctx, s.env)
			if !say("250 2.0.0 Upstream accepted") {
				return
			}
			reset()
		case "RSET":
			reset()
			say("250 2.0.0 Reset")
		case "NOOP":
			say("250 2.0.0 OK")
		case "QUIT":
			say("221 2.0.0 Bye")
			return
		default:
			say("502 5.5.1 Unsupported command")
		}
	}
}
