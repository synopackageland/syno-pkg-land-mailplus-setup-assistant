// Package worker is the operation table of the package's background worker.
// The CGI forwards each admitted request over the private Unix socket with the
// verified caller as owner; the worker owns the store, the grants, the setup
// transactions, the diagnose runs and the relay service.
package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/synopackageland/syno-pkg-land-sdk/delegate"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
	"SynoMailPlusSetupAssistant/internal/mail/diagnose"
	"SynoMailPlusSetupAssistant/internal/mail/relay"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

// Worker answers the private IPC.
type Worker struct {
	Host *core.Host
	Mail *mail.Assistant
	// NextWait is how long one mail.diagnose.next call waits for background
	// work before it returns progress (default and maximum diagnose.NextWait).
	NextWait time.Duration
}

// OwnerHeader and ClientHeader carry the CGI's verified caller and the
// browser address; a browser can never set them (the socket is 0600).
const (
	OwnerHeader  = "X-MailPlusSetupAssistant-Owner"
	ClientHeader = "X-MailPlusSetupAssistant-Client"
)

func decode(raw json.RawMessage, into any) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return core.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(into); err != nil {
		return core.ErrInvalid
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return core.ErrInvalid
	}
	return nil
}

// Methods lists every worker method; the CGI exposes exactly these.
var Methods = []string{
	"dsm.authority.status", "dsm.authority.grant", "dsm.authority.revoke",
	"mail.relay.status", "mail.relay.set", "mail.mailplus.status",
	"mail.setup.start", "mail.setup.cloudflare", "mail.setup.zones", "mail.setup.detect", "mail.setup.permissions", "mail.setup.preview",
	"mail.setup.apply", "mail.setup.status", "mail.setup.decide", "mail.setup.receivemodes",
	"mail.inbound.status", "mail.inbound.sync", "mail.inbound.token", "mail.cloudflare.remove",
	"mail.diagnose.symptoms", "mail.diagnose.start", "mail.diagnose.next",
}

// Invoke runs one method for owner (a DSM administrator; the CGI checks).
func (w *Worker) Invoke(ctx context.Context, owner, method string, params json.RawMessage) (any, error) {
	h := w.Host
	env := h.CallerEnv(ctx, owner)
	// The MailPlus Server precondition: once a package read of this request
	// (or of the background work it starts) says MailPlus Server does not
	// run, no SYNO.MailPlusServer call is sent; DSM's "no such API" on one
	// is the typed refusal, never a raw DSM code.
	env.DSM = detect.Gate(env.DSM, env.Log)
	switch method {
	case "dsm.authority.status":
		if err := decode(params, &struct{}{}); err != nil || h.Authority == nil {
			return nil, core.ErrInvalid
		}
		return h.Authority.Bindings(ctx)
	case "dsm.authority.grant":
		var g delegate.Grant
		if err := decode(params, &g); err != nil || h.Authority == nil {
			return nil, core.ErrInvalid
		}
		return map[string]any{}, h.Authority.Bind(ctx, owner, g)
	case "dsm.authority.revoke":
		var p struct{ Profile, ID string }
		if err := decode(params, &p); err != nil || h.Authority == nil {
			return nil, core.ErrInvalid
		}
		return map[string]any{}, h.Authority.Forget(ctx, p.Profile, p.ID)

	case "mail.relay.status":
		if err := decode(params, &struct{}{}); err != nil {
			return nil, err
		}
		items, err := h.Services(ctx)
		if err != nil {
			return nil, err
		}
		for _, s := range items {
			if s.ID == relay.ID {
				return s, nil
			}
		}
		return nil, core.ErrNotFound
	case "mail.relay.set":
		var p struct {
			Enabled *bool `json:"enabled"`
		}
		if err := decode(params, &p); err != nil || p.Enabled == nil {
			return nil, core.ErrInvalid
		}
		// Enabling needs the relay's configuration from the setup flow; the
		// service itself refuses to start without its credentials.
		return map[string]any{}, h.SetService(ctx, relay.ID, *p.Enabled)

	case "mail.mailplus.status":
		if err := decode(params, &struct{}{}); err != nil {
			return nil, err
		}
		if w.Mail.MailPlus == nil {
			return nil, core.ErrUnavailable
		}
		return w.Mail.MailPlus.Status(ctx, env, owner)

	case "mail.setup.start":
		if err := decode(params, &struct{}{}); err != nil {
			return nil, err
		}
		return w.Mail.Setup.Start(ctx, env, owner)
	case "mail.setup.cloudflare":
		var p struct {
			ID    string `json:"id"`
			Token string `json:"token"`
		}
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		// Connect checks the flow first, then seals the token at once under a
		// fresh reference; it never reaches the flow record, a reply or a log.
		return w.Mail.Setup.Connect(ctx, env, owner, p.ID, p.Token)
	case "mail.setup.zones":
		var p struct {
			ID        string `json:"id"`
			AccountID string `json:"accountId"`
			ZoneID    string `json:"zoneId"`
			// Poll fetches the zone's MailPlus domain read; nothing else is read.
			Poll bool `json:"poll"`
		}
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		if p.Poll {
			// As the preview poll: only the flow; a choice sent with a poll
			// would be silently ignored, so it is refused.
			if p.AccountID != "" || p.ZoneID != "" {
				return nil, core.ErrInvalid
			}
			return w.Mail.Setup.PollZone(ctx, env, owner, p.ID)
		}
		return w.Mail.Setup.Zones(ctx, env, owner, p.ID, p.AccountID, p.ZoneID)
	case "mail.setup.detect":
		var p struct {
			ID      string        `json:"id"`
			Intent  setup.Intent  `json:"intent"`
			Domain  string        `json:"domain"`
			Answers setup.Answers `json:"answers"`
			Refresh bool          `json:"refresh"`
		}
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return w.Mail.Setup.Detect(ctx, env, owner, p.ID, p.Intent, p.Domain, p.Answers, p.Refresh)
	case "mail.setup.permissions":
		var p struct {
			ID        string `json:"id"`
			AccountID string `json:"accountId"`
			ZoneID    string `json:"zoneId"`
		}
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		ps, err := w.Mail.Setup.Permissions(ctx, env, owner, p.ID, strings.TrimSpace(p.AccountID), strings.TrimSpace(p.ZoneID))
		if err != nil {
			return nil, err
		}
		return map[string]any{"permissions": ps}, nil
	case "mail.setup.preview":
		var p struct {
			ID        string `json:"id"`
			Addresses string `json:"addresses"`
			Members   string `json:"members"`
			// Tunnel is the inbound tunnel picked from a preview's options.
			Tunnel string `json:"tunnel"`
			// Receive is the receiving mode through Cloudflare:
			// domain or addresses (default).
			Receive string `json:"receive"`
			// Poll fetches the plan a previous preview started; no answers.
			Poll bool `json:"poll"`
		}
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		if p.Poll {
			if p.Addresses != "" || p.Members != "" || p.Tunnel != "" || p.Receive != "" {
				return nil, core.ErrInvalid
			}
			return w.Mail.Setup.PollPreview(ctx, env, owner, p.ID)
		}
		// The Cloudflare token was sealed at sign-in (mail.setup.cloudflare).
		cfg := setup.Configuration{Addresses: p.Addresses, Members: p.Members, Tunnel: p.Tunnel, Receive: p.Receive}
		return w.Mail.Setup.Preview(ctx, env, owner, p.ID, cfg)
	case "mail.setup.apply", "mail.setup.status":
		var p struct {
			ID string `json:"id"`
		}
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		if method == "mail.setup.apply" {
			return w.Mail.Setup.Apply(ctx, env, owner, p.ID)
		}
		return w.Mail.Setup.Status(ctx, env, owner, p.ID)
	case "mail.setup.decide":
		var p struct {
			ID     string `json:"id"`
			Choice string `json:"choice"`
		}
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return w.Mail.Setup.Decide(ctx, env, owner, p.ID, p.Choice)

	case "mail.setup.receivemodes":
		var p struct {
			ID string `json:"id"`
		}
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return w.Mail.Setup.ReceiveModes(ctx, env, owner, p.ID)

	case "mail.inbound.status":
		if err := decode(params, &struct{}{}); err != nil {
			return nil, err
		}
		if w.Mail.Kept == nil {
			return nil, core.ErrUnavailable
		}
		return w.Mail.Kept.Status(ctx, env)
	case "mail.inbound.sync":
		var p struct {
			ID   string `json:"id"`
			Poll bool   `json:"poll"`
		}
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		if w.Mail.Kept == nil {
			return nil, core.ErrUnavailable
		}
		return w.Mail.Kept.Sync(ctx, env, p.ID, p.Poll)
	case "mail.inbound.token":
		var p struct {
			ID    string `json:"id"`
			Token string `json:"token"`
		}
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		if w.Mail.Kept == nil {
			return nil, core.ErrUnavailable
		}
		return w.Mail.Kept.SetToken(ctx, env, p.ID, p.Token)
	case "mail.cloudflare.remove":
		var p struct {
			ID      string `json:"id"`
			Routing bool   `json:"routing"`
			Poll    bool   `json:"poll"`
		}
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		if w.Mail.Kept == nil {
			return nil, core.ErrUnavailable
		}
		return w.Mail.Kept.Remove(ctx, env, p.ID, p.Routing, p.Poll)

	case "mail.diagnose.symptoms":
		if err := decode(params, &struct{}{}); err != nil {
			return nil, err
		}
		out := []map[string]any{}
		for _, plan := range diagnose.Plans() {
			out = append(out, map[string]any{"symptom": plan.Symptom, "checks": len(plan.Checks)})
		}
		return map[string]any{"symptoms": out}, nil
	case "mail.diagnose.start":
		var p struct {
			Symptom diagnose.Symptom `json:"symptom"`
		}
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return w.Mail.Diagnose.Start(owner, p.Symptom)
	case "mail.diagnose.next":
		var p struct {
			ID string `json:"id"`
		}
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return w.Mail.Diagnose.Next(ctx, env, owner, p.ID, w.NextWait)
	}
	return nil, core.ErrNotFound
}

// publicError keeps fixed codes only. A mail rule's reason (for example
// mail.setup.stalePlan) is a fixed key and is passed as a detail.
func publicError(err error) *core.RPCError {
	reason := func(code string) *core.RPCError {
		return &core.RPCError{Code: code, Message: "MailPlus Setup Assistant refused the request", Details: map[string]string{"reason": err.Error()}}
	}
	var mailplus detect.MailPlusUnavailable
	if errors.As(err, &mailplus) {
		// The precondition: a typed code and its catalog reason, never DSM's.
		code := "mailplus_unknown"
		switch mailplus.State {
		case detect.MailPlusNotInstalled:
			code = "mailplus_not_installed"
		case detect.MailPlusStopped:
			code = "mailplus_not_running"
		}
		return &core.RPCError{Code: code, Message: "MailPlus Server is not available", Details: map[string]string{"reason": setup.MailPlusReason(mailplus.State)}}
	}
	// A Cloudflare refusal for a missing permission keeps its fixed key
	// (mail.setup.permissionRefused.<code>), so the page can ask for a token.
	// A replacement token lacking permissions names all of them (codes of
	// mail.setup.cloudflare.permission.<code>, comma-separated).
	var missing setup.PermissionsMissing
	if errors.As(err, &missing) {
		return &core.RPCError{Code: "permission_refused", Message: "MailPlus Setup Assistant refused the request",
			Details: map[string]string{"reason": missing.Error(), "permissions": strings.Join(missing.Codes, ",")}}
	}
	var refused setup.PermissionRefused
	if errors.As(err, &refused) {
		return reason("permission_refused")
	}
	switch {
	case errors.Is(err, setup.ErrInvalid), errors.Is(err, setup.ErrTokenInvalid), errors.Is(err, diagnose.ErrUnknownSymptom):
		return reason("bad_request")
	case errors.Is(err, setup.ErrNoFlow), errors.Is(err, diagnose.ErrUnknownRun):
		return reason("not_found")
	case errors.Is(err, setup.ErrStale), errors.Is(err, setup.ErrPlanChanged), errors.Is(err, setup.ErrBusy), errors.Is(err, diagnose.ErrRunBusy), errors.Is(err, setup.ErrOtherTransaction):
		return reason("conflict")
	case errors.Is(err, setup.ErrUnsafe):
		return reason("unsafe_plan")
	case errors.Is(err, setup.ErrUnavailable), errors.Is(err, setup.ErrUnconfirmed), errors.Is(err, setup.ErrNotStarted), errors.Is(err, setup.ErrCloudflareUnavailable),
		errors.Is(err, setup.ErrTunnelRequired), errors.Is(err, setup.ErrLANUnknown), errors.Is(err, setup.ErrRulesLimit), errors.Is(err, setup.ErrRoutingConflict),
		errors.Is(err, setup.ErrRoutingLeftover), errors.Is(err, setup.ErrRoutingLeftoverDisabled), errors.Is(err, setup.ErrSendingPlan), errors.Is(err, setup.ErrSendingExisting),
		errors.Is(err, setup.ErrCatchAllInUse), errors.Is(err, setup.ErrSyncTokenRequired):
		return reason("unavailable")
	case errors.Is(err, context.Canceled):
		return &core.RPCError{Code: "request_canceled", Message: "Request canceled"}
	}
	return core.PublicError(err)
}

// RPCReply is the IPC reply envelope.
type RPCReply struct {
	Result any            `json:"result,omitempty"`
	Error  *core.RPCError `json:"error,omitempty"`
}

// ServeHTTP is private IPC, not an alternate public HTTP dispatcher. Only the
// package's protected 0600 Unix socket exposes it. The owner header comes from
// the CGI's verified api.Caller, never from a browser parameter.
func (w *Worker) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	if req.Method != http.MethodPost || req.Header.Get(OwnerHeader) == "" {
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20+1))
	if err != nil || len(body) > 1<<20 {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	ctx := req.Context()
	if ip, err := netip.ParseAddr(req.Header.Get(ClientHeader)); err == nil {
		ctx = core.WithClient(ctx, ip.String())
	}
	value, err := w.Invoke(ctx, req.Header.Get(OwnerHeader), strings.TrimPrefix(req.URL.Path, "/"), body)
	reply := RPCReply{Result: value}
	if err != nil {
		reply = RPCReply{Error: publicError(err)}
	}
	_ = json.NewEncoder(rw).Encode(reply)
}
