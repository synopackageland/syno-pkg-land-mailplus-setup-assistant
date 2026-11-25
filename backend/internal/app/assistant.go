package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/synopackageland/syno-pkg-land-sdk/api"
	"github.com/synopackageland/syno-pkg-land-sdk/ipc"
)

// Fixed constructors make every business route visible to the SDK audit.
// Each forwards to the worker, which owns the store, grants and transactions.
func (cfg Config) assistantRoutes() []api.Route {
	return []api.Route{
		api.HandleRequest("mail.relay.status", cfg.coreCall("mail.relay.status")),
		api.HandleRequest("mail.relay.set", cfg.coreCall("mail.relay.set")),
		api.HandleRequest("mail.mailplus.status", cfg.coreCall("mail.mailplus.status")),
		api.HandleRequest("mail.setup.start", cfg.coreCall("mail.setup.start")),
		api.HandleRequest("mail.setup.cloudflare", cfg.coreCall("mail.setup.cloudflare")),
		api.HandleRequest("mail.setup.zones", cfg.coreCall("mail.setup.zones")),
		api.HandleRequest("mail.setup.detect", cfg.coreCall("mail.setup.detect")),
		api.HandleRequest("mail.setup.permissions", cfg.coreCall("mail.setup.permissions")),
		api.HandleRequest("mail.setup.preview", cfg.coreCall("mail.setup.preview")),
		api.HandleRequest("mail.setup.apply", cfg.coreCall("mail.setup.apply")),
		api.HandleRequest("mail.setup.status", cfg.coreCall("mail.setup.status")),
		api.HandleRequest("mail.setup.decide", cfg.coreCall("mail.setup.decide")),
		api.HandleRequest("mail.setup.receivemodes", cfg.coreCall("mail.setup.receivemodes")),
		api.HandleRequest("mail.inbound.status", cfg.coreCall("mail.inbound.status")),
		api.HandleRequest("mail.inbound.sync", cfg.coreCall("mail.inbound.sync")),
		api.HandleRequest("mail.cloudflare.remove", cfg.coreCall("mail.cloudflare.remove")),
		api.HandleRequest("mail.inbound.token", cfg.coreCall("mail.inbound.token")),
		api.HandleRequest("mail.diagnose.symptoms", cfg.coreCall("mail.diagnose.symptoms")),
		api.HandleRequest("mail.diagnose.start", cfg.coreCall("mail.diagnose.start")),
		api.HandleRequest("mail.diagnose.next", cfg.coreCall("mail.diagnose.next")),
	}
}

func (cfg Config) coreCall(method string) api.RequestHandler {
	return func(ctx context.Context, caller api.Caller, r *http.Request, params json.RawMessage) (any, error) {
		if err := api.RequireAdmin(caller); err != nil {
			return nil, err
		}
		if ip, err := api.ClientAddress(r); err == nil {
			ctx = context.WithValue(ctx, clientKey{}, ip)
		}
		return cfg.callCore(ctx, caller, method, params)
	}
}

// clientKey carries the browser's address (REMOTE_ADDR, from the SDK) to the
// worker, which checks it against DSM's firewall and Auto Block rules. It is
// used for the current request only, never stored.
type clientKey struct{}

// callCore is private package IPC; callers decide which trusted payload to send.
func (cfg Config) callCore(ctx context.Context, caller api.Caller, method string, params json.RawMessage) (any, error) {
	if cfg.coreTransport != nil {
		return cfg.coreTransport(ctx, caller, method, params)
	}
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return ipc.DialUnix(ctx, filepath.Join(cfg.DataDir, "run", "assistant.sock"))
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: api.DefaultRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://assistant/"+method, bytes.NewReader(params))
	if err != nil {
		return nil, &api.Error{Code: "bad_request", Message: "Invalid operation"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MailPlusSetupAssistant-Owner", caller.User())
	if ip, ok := ctx.Value(clientKey{}).(string); ok {
		req.Header.Set("X-MailPlusSetupAssistant-Client", ip)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &api.Error{Code: "app_unavailable", Message: "MailPlus Setup Assistant worker is unavailable"}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20+1))
	if err != nil || len(raw) > 8<<20 || resp.StatusCode != http.StatusOK {
		return nil, &api.Error{Code: "app_unavailable", Message: "MailPlus Setup Assistant worker is unavailable"}
	}
	return decodeCoreReply(raw)
}

func decodeCoreReply(raw []byte) (any, error) {
	var result struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    string            `json:"code"`
			Message string            `json:"message"`
			Details map[string]string `json:"details,omitempty"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &result) != nil {
		return nil, &api.Error{Code: "bad_response", Message: "MailPlus Setup Assistant worker returned an invalid reply"}
	}
	if result.Error != nil {
		return nil, api.WithDetails(&api.Error{Code: result.Error.Code, Message: result.Error.Message}, result.Error.Details)
	}
	return result.Result, nil
}

// WorkerStopBudget bounds the package's own graceful stop; DSM remains the
// supervisor. Modules must honor cancellation in Start, Next and check calls.
const WorkerStopBudget = 10 * time.Second
