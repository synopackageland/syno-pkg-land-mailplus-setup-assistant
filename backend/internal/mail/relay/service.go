// Package relay adapts MailPlus STARTTLS submission to Cloudflare implicit TLS.
// It streams each message without a spool or retries; MailPlus owns the queue.
package relay

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"

	"github.com/synopackageland/syno-pkg-land-sdk/ipc"
)

const (
	ID = "mail.relay"
	// PortKey is an integer in the mail.relay KV namespace. Zero is not allowed.
	PortKey              = "port"
	DefaultPort          = 2525
	TokenSecretKey       = "mail.relay.cloudflare-token"
	CredentialsSecretKey = "mail.relay.credentials"
	MaxSize              = 25 << 20
	MaxRecipients        = 50
	sessionTimeout       = 120 * time.Second
)

// Service implements core.Service. Construct one instance per daemon.
type Service struct {
	dataDir  string
	upstream Upstream
	timeout  time.Duration
	// TokenResult, when set, hears whether Cloudflare accepted the token at
	// each upstream AUTH (refused: a definite 5xx reply to AUTH). It must
	// not block for long and must write only when its state changes
	// (hibernation). It never sees the token.
	TokenResult func(ctx context.Context, env core.Env, refused bool)
	mu          sync.Mutex
	starting    bool
	addr        string
	status      core.ServiceStatus
}

var _ core.Service = (*Service)(nil)

// New uses the package's private DataDir for its certificate, never for mail.
// Env deliberately contains no filesystem path, so the host supplies it here.
func New(dataDir string) *Service {
	return &Service{dataDir: dataDir, upstream: cloudflareUpstream(), timeout: sessionTimeout}
}

func (*Service) ID() string { return ID }

// ListenAddr is empty until the first successful bind, then retains the last
// bound address after stop. Check Status().Running before using it.
func (s *Service) ListenAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

func (s *Service) Status() core.ServiceStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.status
	out.Counters = make(map[string]int64, 4)
	for _, key := range []string{"accepted", "sent", "deferred", "rejected"} {
		out.Counters[key] = s.status.Counters[key]
	}
	out.Info = make(map[string]string)
	for k, v := range s.status.Info {
		out.Info[k] = v
	}
	return out
}

func clock(env core.Env) time.Time {
	if env.Now != nil {
		return env.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) count(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.Counters == nil {
		s.status.Counters = make(map[string]int64)
	}
	s.status.Counters[key]++
}

func (s *Service) lastError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.LastErr = err.Error()
}

// PlanRefusalCode is the last error after Cloudflare refused a recipient
// because the account is on Workers Free (RecipientPlanRefused).
const PlanRefusalCode = "mail.relay.recipient_plan"

// planRefused records a recipient refused by the Workers Free plan: counted
// as rejected, the fixed plan code as the last error and the time in
// Info["lastPlanRefusal"], which a later success to another (verified)
// recipient does not clear.
func (s *Service) planRefused(ctx context.Context, env core.Env) {
	at := clock(env)
	s.count("rejected")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.LastErr = PlanRefusalCode
	if s.status.Info == nil {
		s.status.Info = make(map[string]string)
	}
	s.status.Info["lastPlanRefusal"] = at.Format(time.RFC3339Nano)
}

func (s *Service) sent(ctx context.Context, env core.Env) {
	at := clock(env)
	s.mu.Lock()
	if s.status.Counters == nil {
		s.status.Counters = make(map[string]int64)
	}
	s.status.Counters["sent"]++
	if s.status.Info == nil {
		s.status.Info = make(map[string]string)
	}
	s.status.Info["lastSuccess"] = at.Format(time.RFC3339Nano)
	s.status.LastErr = ""
	s.mu.Unlock()
	// An upstream commit cannot be undone on a state-store failure. Still ACK it;
	// otherwise deliberately deferring here would cause another delivery.
	if err := env.KV.Put(ctx, ID, "lastSuccess", at); err != nil {
		s.lastError(errors.New("mail.relay.state_write"))
	}
}

func (s *Service) Start(ctx context.Context, env core.Env) (err error) {
	s.mu.Lock()
	if s.starting {
		s.mu.Unlock()
		return errors.New("mail.relay.already_running")
	}
	s.starting = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.starting = false
		s.status.Running = false
		s.mu.Unlock()
		if err != nil {
			s.lastError(err)
		}
	}()
	if env.KV == nil || env.Secrets == nil {
		return errors.New("mail.relay.stores_required")
	}
	port := DefaultPort
	if _, e := env.KV.Get(ctx, ID, PortKey, &port); e != nil {
		return errors.New("mail.relay.port_read")
	}
	if port < 1024 || port > 65535 {
		return errors.New("mail.relay.invalid_port")
	}
	if e := env.KV.Put(ctx, ID, PortKey, port); e != nil {
		return errors.New("mail.relay.port_write")
	}
	var last time.Time
	if _, e := env.KV.Get(ctx, ID, "lastSuccess", &last); e != nil {
		return errors.New("mail.relay.state_read")
	}
	auth, e := Credentials(ctx, env)
	if e != nil {
		return e
	}
	cert, e := prepareCertificate(s.dataDir)
	if e != nil {
		return e
	}
	listener, e := ipc.ListenTCP(ctx, "mail_relay", port)
	if e != nil {
		return errors.New("mail.relay.listen_failed")
	}
	defer listener.Close()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var peers sync.WaitGroup
	defer peers.Wait()
	stop := context.AfterFunc(runCtx, func() { listener.Close() })
	defer stop()
	s.mu.Lock()
	s.addr = listener.Addr().String()
	s.status.Running = true
	s.status.Since = clock(env)
	s.status.LastErr = ""
	if s.status.Info == nil {
		s.status.Info = make(map[string]string)
	}
	s.status.Info["listen"] = s.addr
	if !last.IsZero() {
		s.status.Info["lastSuccess"] = last.UTC().Format(time.RFC3339Nano)
	}
	s.mu.Unlock()
	// Bound idle sessions and concurrent upstream submissions together.
	slots := make(chan struct{}, 8)
	for {
		c, e := listener.Accept()
		if e != nil {
			cancel()
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("mail.relay.accept_failed")
		}
		select {
		case slots <- struct{}{}:
			peers.Add(1)
			go func() {
				defer peers.Done()
				defer func() { <-slots }()
				(&server{cert: cert, auth: auth, service: s, env: env}).serve(runCtx, c)
			}()
		default:
			c.SetDeadline(time.Now().Add(time.Second))
			fmt.Fprint(c, "421 4.3.2 Relay busy\r\n")
			c.Close()
			s.count("rejected")
		}
	}
}

// TestUpstream verifies TLS and AUTH only; it never submits MAIL or DATA.
func TestUpstream(ctx context.Context, env core.Env) error {
	token, err := upstreamToken(ctx, env)
	if err != nil {
		return err
	}
	return cloudflareUpstream().Test(ctx, token)
}

// AuthRefused: the upstream answered AUTH with a permanent refusal (5xx, for
// example 535 5.7.8 for a deleted or rolled token). A temporary 4xx (454) or
// a lost reply is not a refusal of the token.
func AuthRefused(err error) bool {
	var u upstreamError
	return errors.As(err, &u) && u.stage == "auth" && u.code >= 500 && u.code <= 599
}

func (s *Service) tokenResult(ctx context.Context, env core.Env, refused bool) {
	if s.TokenResult != nil {
		s.TokenResult(ctx, env, refused)
	}
}

func upstreamToken(ctx context.Context, env core.Env) (string, error) {
	if env.Secrets == nil {
		return "", errors.New("mail.relay.secrets_required")
	}
	token, err := env.Secrets.Get(ctx, TokenSecretKey)
	if err != nil || token == "" {
		return "", errors.New("mail.relay.token_unavailable")
	}
	return token, nil
}
