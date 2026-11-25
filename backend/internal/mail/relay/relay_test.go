package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"github.com/synopackageland/syno-pkg-land-sdk/ipc"
)

// fixtureTimeout bounds every socket in these local fixtures. A busy build
// host running -race (load average 15 and up) needs about 16 s just to stream
// TestSizeLimit's 25 MiB through both TLS hops, so the old 20 s budget failed
// with "i/o timeout". Production keeps sessionTimeout (also two minutes).
const fixtureTimeout = 2 * time.Minute

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

// retryTiming runs attempt (numbered from 1) until it returns nil, at most
// attempts times. attempt reports assertion failures through t as usual (they
// are never retried) and returns an error only for a failure a slow host can
// cause; the error says which one. It is logged and retried with a fresh
// fixture, and the last one fails the test.
func retryTiming(t *testing.T, attempts int, attempt func(n int) error) {
	t.Helper()
	for n := 1; ; n++ {
		err := attempt(n)
		if err == nil || t.Failed() {
			return
		}
		if n == attempts {
			t.Fatalf("attempt %d of %d: %v", n, attempts, err)
		}
		t.Logf("attempt %d of %d: %v; retrying with a fresh fixture", n, attempts, err)
	}
}

type memoryStore struct {
	mu               sync.Mutex
	secrets          map[string]string
	values           map[string][]byte
	failGet, failPut bool
}
type kvStore struct{ *memoryStore }

func newEnv() core.Env {
	store := &memoryStore{secrets: map[string]string{TokenSecretKey: "fixture"}, values: make(map[string][]byte)}
	return core.Env{Secrets: store, KV: kvStore{store}}
}
func (m *memoryStore) Get(_ context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failGet {
		return "", errors.New("store unavailable")
	}
	return m.secrets[key], nil
}
func (m *memoryStore) Put(_ context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failPut {
		return errors.New("store unavailable")
	}
	m.secrets[key] = value
	return nil
}
func (m *memoryStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.secrets, key)
	return nil
}
func (m kvStore) Get(_ context.Context, module, key string, out any) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.values[module+"/"+key]
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(b, out)
}
func (m kvStore) Put(_ context.Context, module, key string, v any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failPut {
		return errors.New("store unavailable")
	}
	b, err := json.Marshal(v)
	m.values[module+"/"+key] = b
	return err
}

type fixture struct {
	cert tls.Certificate
	pool *x509.CertPool
	env  core.Env
	auth AuthCredentials
	// failureText replaces the fake's refusal text (after the code).
	failureText string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	cert, err := prepareCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "mail-relay", "starttls.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		t.Fatal("test certificate missing")
	}
	env := newEnv()
	auth, err := Credentials(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{cert: cert, pool: pool, env: env, auth: auth}
}

// receivedBody waits for the body the fake read, or for the fake to give up.
func (fake *fakeSMTP) receivedBody() (string, bool) {
	select {
	case b := <-fake.body:
		return b, true
	case <-fake.done:
		select {
		case b := <-fake.body:
			return b, true
		default:
			return "", false
		}
	}
}

// A real, local implicit-TLS SMTP peer. Only fake credentials cross this socket.
type fakeSMTP struct {
	up        *smtpUpstream
	body      chan string
	committed chan struct{}
	release   chan struct{}
	done      chan struct{}
}

func startFake(t *testing.T, f fixture, failureStage string, failureCode int, hold bool) *fakeSMTP {
	t.Helper()
	l, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{f.cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	fake := &fakeSMTP{
		up:   &smtpUpstream{address: l.Addr().String(), roots: f.pool, timeout: fixtureTimeout},
		body: make(chan string, 1), committed: make(chan struct{}),
		release: make(chan struct{}), done: make(chan struct{}),
	}
	go func() {
		defer close(fake.done)
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		stop := context.AfterFunc(ctx, func() { c.Close() })
		defer stop()
		c.SetDeadline(time.Now().Add(fixtureTimeout))
		p := textproto.NewConn(c)
		reply := func(stage string, code int) bool {
			if stage == failureStage {
				if failureCode == 0 {
					return false
				} // lost reply
				text := "peer-private-text"
				if f.failureText != "" {
					text = f.failureText
				}
				p.PrintfLine("%d %s", failureCode, text)
				return false
			}
			p.PrintfLine("%d fixture", code)
			return true
		}
		if !reply("greeting", 220) {
			return
		}
		for _, step := range []struct {
			stage, prefix string
			code          int
		}{
			{"ehlo", "EHLO ", 250}, {"auth", "AUTH PLAIN ", 235},
			{"mail", "MAIL FROM:", 250}, {"rcpt", "RCPT TO:", 250}, {"data", "DATA", 354},
		} {
			line, err := p.ReadLine()
			if err != nil {
				return
			} // AUTH-only test closes here
			if !strings.HasPrefix(line, step.prefix) {
				t.Error("unexpected upstream command")
				return
			}
			if step.stage == "auth" {
				decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
				if err != nil || string(decoded) != "\x00api_token\x00fixture" {
					t.Error("upstream AUTH mismatch")
					return
				}
			}
			if !reply(step.stage, step.code) {
				return
			}
		}
		if failureStage == "size" {
			_, err := io.Copy(io.Discard, p.DotReader())
			if err == nil {
				t.Error("oversized upstream body was committed")
			}
			return
		}
		b, err := io.ReadAll(io.LimitReader(p.DotReader(), 4096))
		if err != nil {
			return
		}
		fake.body <- string(b)
		if hold {
			select {
			case <-fake.release:
			case <-ctx.Done():
				return
			}
		}
		if failureStage == "timeout" {
			<-ctx.Done()
			return
		}
		if !reply("commit", 250) {
			return
		}
		close(fake.committed)
	}()
	t.Cleanup(func() {
		cancel()
		l.Close()
		select {
		case <-fake.done:
		case <-time.After(10 * time.Second):
			t.Error("fake SMTP did not stop")
		}
	})
	return fake
}

func localClient(t *testing.T, f fixture, up Upstream) (*smtp.Client, *Service) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	b, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	a, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	b.SetDeadline(time.Now().Add(fixtureTimeout))
	ctx, cancel := context.WithCancel(context.Background())
	s := New(t.TempDir())
	s.upstream = up
	s.timeout = fixtureTimeout
	done := make(chan struct{})
	go func() { defer close(done); (&server{f.cert, f.auth, s, f.env}).serve(ctx, a) }()
	client, err := smtp.NewClient(b, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); cancel(); <-done })
	if err := client.StartTLS(&tls.Config{RootCAs: f.pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}); err != nil {
		t.Fatal(err)
	}
	if err := client.Auth(smtp.PlainAuth("", f.auth.Username, f.auth.Password, "127.0.0.1")); err != nil {
		t.Fatal("local AUTH failed")
	}
	return client, s
}

func smtpCode(t *testing.T, err error, code int) {
	t.Helper()
	var pe *textproto.Error
	if !errors.As(err, &pe) || pe.Code != code {
		t.Fatalf("wanted SMTP %d, got %v", code, err)
	}
}
func envelope(t *testing.T, c *smtp.Client) {
	t.Helper()
	if err := c.Mail("sender@example.invalid"); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("recipient@example.invalid"); err != nil {
		t.Fatal(err)
	}
}

func TestPassThrough(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name, stage string
		code        int
	}{
		{"success", "", 0}, {"temporary-mail", "mail", 450},
		{"permanent-mail", "mail", 550}, {"auth", "auth", 535},
		{"recipient", "rcpt", 550}, {"data", "data", 554},
		{"commit-temporary", "commit", 451}, {"commit-permanent", "commit", 550},
		{"lost-reply", "commit", 0}, {"timeout", "timeout", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.stage != "timeout" {
				passThrough(t, f, tc.stage, tc.code, 1)
				return
			}
			retryTiming(t, 3, func(n int) error { return passThrough(t, f, tc.stage, tc.code, n) })
		})
	}
}

// passThrough is one attempt of a TestPassThrough case. The "timeout" case
// gives the whole upstream session (dial, TLS, AUTH, envelope, body) a short
// budget that must expire only while the fake withholds the commit reply. A
// loaded host can spend it earlier: the relay then refuses DATA, or the fake
// never receives the body. Only those two return an error, so only the
// "timeout" case retries, each time with a four times larger budget (250 ms,
// 1 s, 4 s). A client socket that times out (fixtureTimeout) is a hang, not a
// slow host, and fails at once: retrying it would take minutes per attempt.
func passThrough(t *testing.T, f fixture, stage string, code, attempt int) error {
	fake := startFake(t, f, stage, code, false)
	if stage == "timeout" {
		fake.up.timeout = (250 * time.Millisecond) << (2 * (attempt - 1))
	}
	client, s := localClient(t, f, fake.up)
	envelope(t, client)
	w, err := client.Data()
	if stage != "" && stage != "commit" && stage != "timeout" {
		smtpCode(t, err, 451)
	} else {
		if stage == "timeout" && err != nil && !isTimeout(err) {
			return fmt.Errorf("relay refused DATA (%v), most likely because the %v upstream budget ran out before DATA", err, fake.up.timeout)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.WriteString(w, "Subject: fixture\r\n\r\n.dot\r\nlast\r\n"); err != nil {
			t.Fatal(err)
		}
		err = w.Close()
		if stage != "" {
			smtpCode(t, err, 451)
		} else if err != nil {
			t.Fatal(err)
		}
		body, ok := fake.receivedBody()
		if !ok && stage == "timeout" {
			return fmt.Errorf("upstream never received the body, most likely because the %v upstream budget ran out before it arrived", fake.up.timeout)
		}
		if !ok || body != "Subject: fixture\n\n.dot\nlast\n" {
			t.Fatal("SMTP dot transparency changed")
		}
	}
	status := s.Status()
	if stage == "" {
		if status.Counters["sent"] != 1 || status.Counters["accepted"] != 1 || status.Info["lastSuccess"] == "" {
			t.Fatal("missing successful delivery metrics")
		}
		var at time.Time
		found, err := f.env.KV.Get(context.Background(), ID, "lastSuccess", &at)
		if err != nil || !found || at.IsZero() {
			t.Fatal("last success not persisted")
		}
	} else if status.Counters["sent"] != 0 || status.Counters["deferred"] != 1 || status.LastErr == "" || strings.Contains(status.LastErr, "peer-private-text") {
		t.Fatal("incorrect or unsanitized failure metrics")
	}
	return nil
}

func TestCommitBarrier(t *testing.T) {
	f := newFixture(t)
	fake := startFake(t, f, "", 0, true)
	client, _ := localClient(t, f, fake.up)
	envelope(t, client)
	w, err := client.Data()
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, "Subject: barrier\r\n\r\nbody\r\n")
	done := make(chan error, 1)
	go func() { done <- w.Close() }()
	select {
	case <-fake.body:
	case <-time.After(2 * time.Second):
		t.Fatal("body not streamed")
	}
	select {
	case <-done:
		t.Fatal("downstream ACK preceded upstream commit")
	case <-time.After(25 * time.Millisecond):
	}
	close(fake.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestSizeLimit streams 25 MiB through both TLS hops: 16-31 s on a loaded
// -race host, inside the client socket's fixtureTimeout. A client socket
// that still times out is retried once (2 attempts): a real hang then fails
// after about 4 minutes rather than 6, inside go test's 10 minute default.
func TestSizeLimit(t *testing.T) {
	f := newFixture(t)
	retryTiming(t, 2, func(int) error {
		slow := func(err error) error {
			return fmt.Errorf("client socket timed out after %v while streaming 25 MiB: %w", fixtureTimeout, err)
		}
		fake := startFake(t, f, "size", 0, false)
		client, s := localClient(t, f, fake.up)
		envelope(t, client)
		w, err := client.Data()
		if isTimeout(err) {
			return slow(err)
		} else if err != nil {
			t.Fatal(err)
		}
		// Exactly MaxSize+1 decoded bytes: bound memory to one small reusable chunk.
		chunk := strings.Repeat("x", 1023) + "\n"
		for n := 0; n < MaxSize/len(chunk); n++ {
			if _, err = io.WriteString(w, chunk); isTimeout(err) {
				return slow(err)
			} else if err != nil {
				t.Fatal(err)
			}
		}
		io.WriteString(w, "x")
		err = w.Close()
		if isTimeout(err) {
			return slow(err)
		}
		smtpCode(t, err, 552)
		if s.Status().Counters["sent"] != 0 || s.Status().Counters["rejected"] != 1 {
			t.Fatal("oversized message counted as sent")
		}
		return nil
	})
}

func TestAuthenticationAndRecipientLimit(t *testing.T) {
	f := newFixture(t)
	a, b := net.Pipe()
	b.SetDeadline(time.Now().Add(5 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	s := New(t.TempDir())
	done := make(chan struct{})
	go func() { defer close(done); (&server{f.cert, f.auth, s, f.env}).serve(ctx, a) }()
	p := textproto.NewConn(b)
	t.Cleanup(func() { p.Close(); cancel(); <-done })
	p.ReadResponse(220)
	send := func(code int, format string, args ...any) {
		t.Helper()
		if p.PrintfLine(format, args...) != nil {
			t.Fatal("SMTP command write failed")
		}
		if _, _, err := p.ReadResponse(code); err != nil {
			t.Fatal(err)
		}
	}
	send(250, "EHLO fixture")
	send(530, "MAIL FROM:<sender@example.invalid>")
	send(538, "AUTH LOGIN")
	send(220, "STARTTLS")
	secure := tls.Client(b, &tls.Config{RootCAs: f.pool, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	if secure.Handshake() != nil {
		t.Fatal("STARTTLS failed")
	}
	p = textproto.NewConn(secure)
	send(503, "AUTH LOGIN") // EHLO must be repeated after STARTTLS
	send(250, "EHLO fixture")
	send(334, "AUTH LOGIN")
	send(334, "%s", base64.StdEncoding.EncodeToString([]byte(f.auth.Username)))
	send(235, "%s", base64.StdEncoding.EncodeToString([]byte(f.auth.Password)))
	send(250, "MAIL FROM:<>")
	for n := 0; n < MaxRecipients; n++ {
		send(250, "RCPT TO:<recipient@example.invalid>")
	}
	send(452, "RCPT TO:<extra@example.invalid>")
	send(250, "RSET")
	send(501, "MAIL FROM:<sender@example.invalid> SMTPUTF8")
	send(250, "MAIL FROM:<sender@example.invalid> SIZE=256 BODY=8BITMIME")
	send(221, "QUIT")
}

func TestUpstreamAuthOnlyAndTLSVerification(t *testing.T) {
	f := newFixture(t)
	t.Run("auth-only", func(t *testing.T) {
		fake := startFake(t, f, "", 0, false)
		if err := fake.up.Test(context.Background(), "fixture"); err != nil {
			t.Fatal(err)
		}
		<-fake.done
		select {
		case <-fake.body:
			t.Fatal("AUTH probe submitted mail")
		default:
		}
	})
	t.Run("untrusted-peer", func(t *testing.T) {
		fake := startFake(t, f, "", 0, false)
		fake.up.roots = x509.NewCertPool()
		err := fake.up.Test(context.Background(), "fixture")
		if err == nil || err.Error() != "mail.relay.upstream_tls/0" {
			t.Fatal("untrusted TLS peer was accepted")
		}
	})
	t.Run("context-cancel", func(t *testing.T) {
		fake := startFake(t, f, "", 0, false)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := fake.up.Test(ctx, "fixture"); err == nil {
			t.Fatal("canceled probe succeeded")
		}
	})
}

func TestPrivateState(t *testing.T) {
	ctx := context.Background()
	env := newEnv()
	a, err := Credentials(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Credentials(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	if a != b || len(a.Password) < 24 || len(a.Username) < 24 {
		t.Fatal("credentials not stable/random")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", a, a), a.Password) {
		t.Fatal("formatted credentials leaked")
	}
	store := env.Secrets.(*memoryStore)
	store.failGet = true
	if _, err := Credentials(ctx, env); err == nil {
		t.Fatal("store error replaced credentials")
	}
	store.failGet = false
	if _, err := probeMissingToken(env); err == nil {
		t.Fatal("missing token was accepted")
	}
	dir := t.TempDir()
	first, err := prepareCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := prepareCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Certificate[0]) != string(second.Certificate[0]) {
		t.Fatal("certificate changed on restart")
	}
	path := filepath.Join(dir, "mail-relay", "starttls.pem")
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareCertificate(dir); err == nil {
		t.Fatal("permissive private key accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "unrelated")
	os.WriteFile(target, []byte("unchanged"), 0600)
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareCertificate(dir); err == nil {
		t.Fatal("symlink private key accepted")
	}
}

func probeMissingToken(env core.Env) (string, error) {
	// Helper deliberately exercises the public probe's failure before networking.
	env.Secrets.Delete(context.Background(), TokenSecretKey)
	err := TestUpstream(context.Background(), env)
	return "", err
}

func TestServiceLifecycle(t *testing.T) {
	// The SDK listener refuses a binary without the package identity and TCP
	// listener policy that `synopkgland build` binds with -ldflags.
	if _, err := ipc.ListenTCP(context.Background(), "unbound_probe", 0); err != nil && strings.Contains(err.Error(), "not bound by the build") {
		t.Skip("relay listener needs the build's -ldflags; run `npm run test:go` (scripts/go-test.sh)")
	}
	env := newEnv()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	l.Close()
	n, _ := strconv.Atoi(port)
	env.KV.Put(context.Background(), ID, PortKey, n)
	last := time.Now().Add(-24 * time.Hour).UTC()
	env.KV.Put(context.Background(), ID, "lastSuccess", last)
	s := New(t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx, env) }()
	t.Cleanup(func() { cancel() })
	deadline := time.Now().Add(2 * time.Second)
	for !s.Status().Running {
		select {
		case err := <-done:
			t.Fatalf("startup failed: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("startup did not bind")
		}
		time.Sleep(time.Millisecond)
	}
	if s.ListenAddr() != net.JoinHostPort("127.0.0.1", port) {
		t.Fatal("listener address changed")
	}
	if s.Status().Info["lastSuccess"] != last.Format(time.RFC3339Nano) {
		t.Fatal("last success not restored")
	}
	if err := s.Start(ctx, env); err == nil {
		t.Fatal("double start succeeded")
	}
	c, err := net.Dial("tcp4", s.ListenAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stop did not close idle peer")
	}
	if s.Status().Running {
		t.Fatal("relay still running")
	}
	copy := s.Status()
	copy.Info["listen"] = "changed"
	copy.Counters["sent"] = 99
	if s.Status().Info["listen"] == "changed" || s.Status().Counters["sent"] != 0 {
		t.Fatal("status maps are shared")
	}
}

// a token deleted or rolled in Cloudflare's dashboard makes the
// upstream refuse AUTH (535). MailPlus must get a temporary reply, so the
// message stays in its queue and is retried, and the refusal is reported;
// a later accepted login reports the token good again. A temporary 454 is
// not a refusal of the token.
func TestUpstreamLoginRefusedIsTemporaryAndReported(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name   string
		code   int
		want   int
		report []bool
	}{
		{"refused", 535, 451, []bool{true}},
		{"temporary", 454, 451, nil},
		{"accepted", 0, 0, []bool{false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stage := "auth"
			if tc.code == 0 {
				stage = ""
			}
			fake := startFake(t, f, stage, tc.code, false)
			client, s := localClient(t, f, fake.up)
			var mu sync.Mutex
			var got []bool
			s.TokenResult = func(_ context.Context, _ core.Env, refused bool) {
				mu.Lock()
				got = append(got, refused)
				mu.Unlock()
			}
			envelope(t, client)
			w, err := client.Data()
			if tc.want != 0 {
				smtpCode(t, err, tc.want)
				var pe *textproto.Error
				if errors.As(err, &pe) && tc.code == 535 && !strings.HasPrefix(pe.Msg, "4.7.0") {
					t.Fatalf("not the login reply: %q", pe.Msg)
				}
				if s.Status().Counters["deferred"] != 1 || strings.Contains(s.Status().LastErr, "peer-private-text") {
					t.Fatal("deferral not counted or peer text kept")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				io.WriteString(w, "Subject: fixture\r\n\r\nbody\r\n")
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if fmt.Sprint(got) != fmt.Sprint(tc.report) && !(len(got) == 0 && len(tc.report) == 0) {
				t.Fatalf("reported %v, want %v", got, tc.report)
			}
		})
	}
	if !AuthRefused(upstreamError{stage: "auth", code: 535}) || AuthRefused(upstreamError{stage: "auth", code: 454}) || AuthRefused(upstreamError{stage: "mail", code: 550}) {
		t.Fatal("AuthRefused")
	}
}

// On Workers Free, Cloudflare SMTP accepts only the account's verified
// destination addresses and refuses any other RCPT TO with 550 5.7.1
// (Cloudflare's SMTP documentation; not captured live). That refusal is
// permanent: the relay passes it on as 550 5.7.1 with a plain reason, so
// MailPlus returns the message to its sender at once instead of retrying for
// days, and records the fixed plan code. Any other RCPT refusal stays 451.
func TestRecipientPlanRefusalIsPermanentAndNamed(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name, text string
		want       int
		lastErr    string
	}{
		{"plan", "5.7.1 peer-private-text", 550, "mail.relay.recipient_plan"},
		{"other enhanced code", "5.1.1 peer-private-text", 451, "mail.relay.upstream_rcpt/550"},
		{"no enhanced code", "peer-private-text", 451, "mail.relay.upstream_rcpt/550"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.failureText = tc.text
			fake := startFake(t, f, "rcpt", 550, false)
			client, s := localClient(t, f, fake.up)
			envelope(t, client)
			_, err := client.Data()
			smtpCode(t, err, tc.want)
			var pe *textproto.Error
			errors.As(err, &pe)
			if strings.Contains(pe.Msg, "peer-private-text") {
				t.Fatal("peer text passed on")
			}
			if tc.want == 550 && (!strings.HasPrefix(pe.Msg, "5.7.1") || !strings.Contains(pe.Msg, "Workers Paid")) {
				t.Fatalf("plan reply %q", pe.Msg)
			}
			status := s.Status()
			if status.LastErr != tc.lastErr || status.Counters["sent"] != 0 {
				t.Fatalf("status %+v", status)
			}
			if at := status.Info["lastPlanRefusal"]; (tc.want == 550) != (at != "") {
				t.Fatalf("plan refusal time %q", at)
			}
		})
	}
	if !RecipientPlanRefused(upstreamError{stage: "rcpt", code: 550, enhanced: "5.7.1"}) ||
		RecipientPlanRefused(upstreamError{stage: "mail", code: 550, enhanced: "5.7.1"}) ||
		RecipientPlanRefused(upstreamError{stage: "rcpt", code: 550}) {
		t.Fatal("RecipientPlanRefused")
	}
}
