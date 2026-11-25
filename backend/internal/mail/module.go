// Package mail composes the mail checks, the setup flow and the relay service.
package mail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/cloudflare"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
	"SynoMailPlusSetupAssistant/internal/mail/diagnose"
	"SynoMailPlusSetupAssistant/internal/mail/relay"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

// Assistant is the mail feature: the setup flow, the diagnostics and the
// relay service. Home Keeper registered the same parts as a core.Module; here
// the worker's operation table calls them directly.
type Assistant struct {
	Setup       *setup.Wizard
	Diagnostics *diagnose.Diagnostics
	Diagnose    *diagnose.Runner
	Relay       *relay.Service
	// MailPlus is the MailPlus Server precondition (mail.mailplus.status).
	MailPlus *Precondition
	// Kept records the kept Cloudflare setups: the receiving mode, the
	// Overview's mailbox sync and the sealed token.
	Kept *InboundSync
	// Background holds the read-only jobs (detection, plan preparation,
	// diagnosis). The worker sets Base to its own context and Waits for it
	// before it closes the store.
	Background *core.Background
}

// Services returns the long-running services the worker hosts.
func (a *Assistant) Services() []core.Service { return []core.Service{relayService{a.Relay}} }

// Dependencies keeps all external I/O replaceable. Construction never makes
// DSM, DNS, SMTP or Cloudflare calls and never enables a service.
type Dependencies struct {
	Detector   detect.Source
	DNS        diagnose.Resolver
	Network    diagnose.NetworkProber
	Cloudflare func(cloudflare.Config) (*cloudflare.Client, error)
	// Delivery is deliberately absent in production until an independently
	// verified round-trip provider exists. TLS/AUTH is not delivery evidence.
	Delivery setup.Verifier
	// InboundPoll bounds how long verification waits for the check mail it
	// sent itself to show up in MailPlus's transaction log (default 90 s).
	InboundPoll time.Duration
}

func SystemDependencies() Dependencies {
	dns := &net.Resolver{PreferGo: true}
	return Dependencies{Detector: detect.New(), DNS: dns,
		Network: diagnose.SystemNetwork{Resolver: dns}, Cloudflare: cloudflare.New}
}

func Production(dataDir string, deps Dependencies) *Assistant {
	bg := &core.Background{}
	service := relay.New(dataDir)
	cf := &cloudflareAdapter{newClient: deps.Cloudflare}
	inboundPoll := deps.InboundPoll
	if inboundPoll == 0 {
		inboundPoll = 90 * time.Second
	}
	reader, _ := deps.Detector.(MailboxReader)
	kept := &InboundSync{cloud: cf, reader: reader, background: bg}
	// The relay reports each upstream login; a refused one marks the kept
	// setups that send through it (token_state.go).
	service.TokenResult = kept.RelayToken
	source := detectorState{detector: deps.Detector, cloud: cf, kept: kept}
	diagnostics := diagnose.New(diagnose.Dependencies{
		State: diagnose.WithRelay(source, service), DNS: deps.DNS, Network: deps.Network,
		RelayStatus: service,
	})
	relayPlan := &relayAdapter{service: service, routeChanged: diagnostics.ForgetRelayRoute}
	wizard := setup.New(setup.Options{
		Detector: deps.Detector, Cloudflare: cf, Directory: cf, Relay: relayPlan,
		MailPlus: mailPlusAdapter{setup.NewMailPlus()}, Verifier: verifier{deps.Detector, deps.Delivery, cf, inboundPoll},
		Background: bg, Inbound: kept,
	})
	kept.undo, kept.relayOff = wizard.RollbackChange, relayPlan.relayOff
	return &Assistant{Setup: wizard, Kept: kept, Diagnostics: diagnostics, Diagnose: &diagnose.Runner{D: diagnostics, Background: bg}, Relay: service,
		MailPlus: &Precondition{Reader: deps.Detector, Background: bg}, Background: bg}
}

// Only fixed relay codes are safe to publish; SMTP replies remain private.
type relayService struct{ *relay.Service }

func (relayService) PublicErrorCode(code string) string {
	if relayErrors[code] {
		return code
	}
	if strings.HasPrefix(code, "mail.relay.upstream_") {
		stage, status, ok := strings.Cut(strings.TrimPrefix(code, "mail.relay.upstream_"), "/")
		if relayUpstreamStages[stage] && (!ok || validSMTPCode(status)) {
			return "mail.relay.upstream_" + stage
		}
	}
	return "service_failed"
}
func validSMTPCode(s string) bool {
	return s == "0" || len(s) == 3 && s[0] >= '1' && s[0] <= '5' && s[1] >= '0' && s[1] <= '9' && s[2] >= '0' && s[2] <= '9'
}

var relayUpstreamStages = map[string]bool{
	"address": true, "connect": true, "tls": true, "greeting": true, "ehlo": true, "auth": true,
	"envelope": true, "mail": true, "rcpt": true, "data": true, "stream": true, "commit": true,
}
var relayErrors = map[string]bool{
	"mail.relay.secrets_required": true, "mail.relay.credentials_read": true,
	"mail.relay.credentials_invalid": true, "mail.relay.credentials_write": true,
	"mail.relay.random_failed": true, "mail.relay.certificate_unavailable": true,
	"mail.relay.state_write": true, "mail.relay.already_running": true,
	"mail.relay.stores_required": true, "mail.relay.port_read": true,
	"mail.relay.invalid_port": true, "mail.relay.port_write": true,
	"mail.relay.state_read": true, "mail.relay.listen_failed": true,
	"mail.relay.accept_failed": true, "mail.relay.token_unavailable": true,
	"mail.relay.protocol_line": true, "mail.relay.size_limit": true,
	relay.PlanRefusalCode: true,
}

// The detector requires an actual domain. Discover it through the authorized
// DSM boundary; do not issue DNS queries for an invented placeholder domain.
type detectorState struct {
	detector detect.Source
	cloud    *cloudflareAdapter
	// kept: the kept setups, whose refused Cloudflare tokens the diagnosis
	// reports (from the records; a refused selector read is verified).
	kept *InboundSync
}

// mailPlusReader is the DSM-only read pass of the production detector.
type mailPlusReader interface {
	ReadMailPlus(context.Context, core.Env) detect.State
}

// Snapshot reads MailPlus Server once (package, SMTP, every domain's DKIM,
// delivery, queue, licence counts) without accounts or network probes; a diagnosis run shares
// it across its checks. A package that cannot be read is Unreadable with the
// fixed cause, so each check can say why it is unavailable.
func (d detectorState) Snapshot(ctx context.Context, env core.Env) (diagnose.State, error) {
	out, err := d.snapshot(ctx, env)
	if err == nil && d.kept != nil && env.KV != nil {
		out.TokenInvalid = d.kept.InvalidDomains(ctx, env)
	}
	return out, err
}

func (d detectorState) snapshot(ctx context.Context, env core.Env) (diagnose.State, error) {
	var out diagnose.State
	reader, ok := d.detector.(mailPlusReader)
	if env.DSM == nil || !ok {
		return out, diagnose.Unreadable{Cause: core.CauseUnavailable}
	}
	state := reader.ReadMailPlus(ctx, env)
	if err := ctx.Err(); err != nil {
		return diagnose.State{}, err
	}
	if !state.Package.IsKnown() {
		return out, diagnose.Unreadable{Cause: state.Package.Detail}
	}
	installed := state.Package.Value.Installed
	out.Installed = &installed
	if installed {
		// A broken installation cannot run until repaired: not running.
		running := state.Package.Value.Running && !state.Package.Value.Broken
		out.Running = &running
	}
	// MailPlus Server's own licence counts (License API v1); nil stays unknown.
	if state.License.IsKnown() {
		licensed, active := state.License.Value.Licensed, state.License.Value.Active
		out.Access.Licensed, out.Access.Activated = &licensed, &active
	}
	if !installed || !*out.Running || !state.Domains.IsKnown() || len(state.Domains.Value) > 10 {
		return out, nil // preserve visible package facts, remaining fields unknown
	}
	if state.SMTP.IsKnown() {
		enabled := state.SMTP.Value.Enabled
		out.SMTPEnabled = &enabled
	}
	if state.QueueSize.IsKnown() {
		total := state.QueueSize.Value
		out.Queue.Total = &total
	}
	if state.Delivery.IsKnown() && env.KV != nil {
		delivery := state.Delivery.Value
		enabled := false
		ownedPort := 0
		port := relay.DefaultPort
		if _, err := env.KV.Get(ctx, relay.ID, relay.PortKey, &port); err != nil {
			return out, core.ErrUnavailable
		}
		if _, err := env.KV.Get(ctx, "mail.wiring", "relay.port", &ownedPort); err != nil {
			return out, core.ErrUnavailable
		}
		unknownOwner := false
		for _, host := range delivery.Default {
			if host.Server == "127.0.0.1" && host.Port == port && host.STARTTLS && host.Auth && delivery.Type == "list" && !delivery.Fallback {
				enabled = ownedPort == port
				unknownOwner = !enabled
			}
		}
		if !unknownOwner {
			out.Relay.Enabled = &enabled
		}
	}
	for _, domain := range state.Domains.Value {
		name := domain.Name
		mailDomain := diagnose.MailDomain{Name: name}
		if signing := state.Signing[name]; signing.IsKnown() && signing.Value.Enabled && signing.Value.Selector != "" {
			mailDomain.Selectors = append(mailDomain.Selectors, signing.Value.Selector)
		}
		// Cloudflare owns its selector. Discover the configured sender using
		// the saved credential reference, never guess "cf-bounce".
		if d.cloud != nil {
			selectors, err := d.cloud.selectors(ctx, env, name)
			if err == nil {
				mailDomain.Selectors = append(mailDomain.Selectors, selectors...)
			} else if d.kept != nil && tokenRefusal(err) {
				d.kept.DomainRefused(ctx, env, name)
			}
		}
		out.Domains = append(out.Domains, mailDomain)
	}
	// Queue age/reasons, assigned certificates, IMAP and external-client
	// reachability have no verified detector mapping yet. Nil means unknown.
	return out, nil
}

type verifier struct {
	detector    detect.Source
	delivery    setup.Verifier
	inbound     *cloudflareAdapter
	inboundPoll time.Duration
}

func (v verifier) Verify(ctx context.Context, env core.Env, request setup.PlanRequest, changes []core.Change) (setup.Verification, error) {
	if request.Decision.Gate != setup.Minimal {
		d := request.Decision
		if d.Receive != setup.RoutingReceive || v.inbound == nil {
			if v.delivery == nil {
				return setup.Verification{}, setup.ErrUnavailable
			}
			return v.delivery.Verify(ctx, env, request, changes)
		}
		// Inbound has its own evidence: read-back plus a completed delivery
		// in MailPlus's transaction log. Any other part of the plan still
		// needs the delivery verifier; without one the result is unverified.
		readback, delivery, findings := v.inbound.verifyInbound(ctx, env, request, changes, v.inboundPoll)
		other := d.Send == setup.RelaySend || d.Send == setup.DirectSend
		for _, n := range d.Needs {
			other = other || strings.HasPrefix(n, "dns.")
		}
		if other {
			if v.delivery == nil {
				delivery = false
			} else {
				rest, err := v.delivery.Verify(ctx, env, request, changes)
				if err != nil {
					delivery = false
				} else {
					readback, delivery = readback && rest.Readback, delivery && rest.Delivery
					findings = append(findings, rest.Findings...)
				}
			}
		}
		return setup.Verification{Readback: readback, Delivery: delivery, Findings: findings}, nil
	}
	if v.detector == nil {
		return setup.Verification{}, setup.ErrUnavailable
	}
	state := v.detector.Detect(ctx, env, detect.Request{Domain: request.Domain})
	return setup.Verification{Readback: ctx.Err() == nil && state.SMTP.IsKnown() && state.SMTP.Value.Enabled}, ctx.Err()
}

// MailPlus expects two secret references; the public relay plan carries a
// single credentialRef so it also passes setup's strict credential-field filter.
type mailPlusAdapter struct{ *setup.MailPlusAdapter }

func (m mailPlusAdapter) Plan(ctx context.Context, env core.Env, request setup.PlanRequest, changes []core.Change) (setup.Prepared, error) {
	prior := make([]core.Change, len(changes))
	for i, c := range changes {
		prior[i] = c
		if c.Target != "homekeeper.relay" {
			continue
		}
		ref := c.Params["credentialRef"]
		if ref == "" {
			return setup.Prepared{}, setup.ErrUnsafePlanCheck
		}
		var auth relay.AuthCredentials
		raw, err := env.Secrets.Get(ctx, ref)
		if err != nil || json.Unmarshal([]byte(raw), &auth) != nil || auth.Username == "" || auth.Password == "" {
			return setup.Prepared{}, setup.ErrUnavailable
		}
		params := map[string]string{}
		for k, value := range c.Params {
			params[k] = value
		}
		params["usernameRef"], params["passwordRef"] = ref+".user", ref+".pass"
		if err := env.Secrets.Put(ctx, params["usernameRef"], auth.Username); err != nil {
			return setup.Prepared{}, setup.ErrUnavailable
		}
		if err := env.Secrets.Put(ctx, params["passwordRef"], auth.Password); err != nil {
			return setup.Prepared{}, setup.ErrUnavailable
		}
		prior[i].Params = params
	}
	return m.MailPlusAdapter.Plan(ctx, env, request, prior)
}

func fingerprint(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

type relayAdapter struct {
	service *relay.Service
	// routeChanged tells diagnostics that the MailPlus route through the relay
	// may have changed, so its memory judgement (H2) must not reuse it.
	routeChanged func()
}

func (r *relayAdapter) forgetRoute() {
	if r.routeChanged != nil {
		r.routeChanged()
	}
}

type relayOperation struct {
	Port         int    `json:"port"`
	SMTPTokenRef string `json:"smtpTokenRef"`
}

func (r *relayAdapter) Plan(ctx context.Context, env core.Env, request setup.PlanRequest) (setup.Prepared, error) {
	if env.Secrets == nil || env.KV == nil || request.SMTPTokenRef == "" {
		return setup.Prepared{}, setup.ErrUnavailable
	}
	var enabled bool
	if _, err := env.KV.Get(ctx, "core.services", relay.ID, &enabled); err != nil {
		return setup.Prepared{}, setup.ErrUnavailable
	}
	// Never silently replace a working relay's credential or active route.
	if enabled || r.service.Status().Running {
		return setup.Prepared{}, setup.ErrUnsafeRelayInUse
	}
	previous, err := env.Secrets.Get(ctx, relay.TokenSecretKey)
	if err != nil || previous != "" {
		return setup.Prepared{}, setup.ErrUnsafeRelayInUse
	}
	port := relay.DefaultPort
	if _, err := env.KV.Get(ctx, relay.ID, relay.PortKey, &port); err != nil || port < 1024 || port > 65535 {
		return setup.Prepared{}, setup.ErrUnavailable
	}
	auth, err := relay.Credentials(ctx, env)
	if err != nil {
		return setup.Prepared{}, setup.ErrUnavailable
	}
	credentialRef := "secret:mail.wiring.credentials." + fingerprint(request.SessionID)
	raw, _ := json.Marshal(auth)
	if err := env.Secrets.Put(ctx, credentialRef, string(raw)); err != nil {
		return setup.Prepared{}, setup.ErrUnavailable
	}
	operationRef := "secret:mail.wiring.relay." + fingerprint(request.SessionID)
	raw, _ = json.Marshal(relayOperation{port, request.SMTPTokenRef})
	if err := env.Secrets.Put(ctx, operationRef, string(raw)); err != nil {
		return setup.Prepared{}, setup.ErrUnavailable
	}
	listen := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	return setup.Prepared{Restorable: true, Changes: []core.Change{{
		ID: "relay.configure", Target: "homekeeper.relay", ActionKey: "mail.setup.change.relay.configure",
		Params: map[string]string{"domain": request.Domain, "listen": listen, "starttls": "required", "credentialRef": credentialRef, "operationRef": operationRef},
		Before: "disabled", After: listen + " STARTTLS AUTH enabled",
	}}}, nil
}

func relayOp(ctx context.Context, env core.Env, change core.Change) (relayOperation, error) {
	var op relayOperation
	raw, err := env.Secrets.Get(ctx, change.Params["operationRef"])
	if err != nil || json.Unmarshal([]byte(raw), &op) != nil || op.Port < 1024 || op.Port > 65535 {
		return op, setup.ErrUnavailable
	}
	return op, nil
}

func (r *relayAdapter) Snapshot(ctx context.Context, env core.Env, c core.Change) (json.RawMessage, error) {
	if _, err := relayOp(ctx, env, c); err != nil {
		return nil, err
	}
	var enabled bool
	if _, err := env.KV.Get(ctx, "core.services", relay.ID, &enabled); err != nil || enabled || r.service.Status().Running {
		return nil, setup.ErrStale
	}
	token, err := env.Secrets.Get(ctx, relay.TokenSecretKey)
	if err != nil || token != "" {
		return nil, setup.ErrStale
	}
	return json.RawMessage(`{"enabled":false}`), nil
}

func (r *relayAdapter) Apply(ctx context.Context, env core.Env, c core.Change) error {
	op, err := relayOp(ctx, env, c)
	if err != nil {
		return err
	}
	token, err := env.Secrets.Get(ctx, op.SMTPTokenRef)
	if err != nil || token == "" {
		return setup.ErrUnavailable
	}
	current, err := env.Secrets.Get(ctx, relay.TokenSecretKey)
	if err != nil || current != "" && current != token {
		return setup.ErrStale
	}
	if err := env.Secrets.Put(ctx, relay.TokenSecretKey, token); err != nil {
		return setup.ErrUnavailable
	}
	if err := env.KV.Put(ctx, relay.ID, relay.PortKey, op.Port); err != nil {
		return setup.ErrUnavailable
	}
	r.forgetRoute()
	if err := env.KV.Put(ctx, "core.services", relay.ID, true); err != nil {
		return setup.ErrUnavailable
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for !r.service.Status().Running {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	return env.KV.Put(ctx, "mail.wiring", "relay.port", op.Port)
}

func (r *relayAdapter) Rollback(ctx context.Context, env core.Env, c core.Change, snapshot json.RawMessage) error {
	if string(snapshot) != `{"enabled":false}` {
		return setup.ErrUnsafeRecord
	}
	op, err := relayOp(ctx, env, c)
	if err != nil {
		return err
	}
	expected, err := env.Secrets.Get(ctx, op.SMTPTokenRef)
	if err != nil || expected == "" {
		return setup.ErrUnavailable
	}
	current, err := env.Secrets.Get(ctx, relay.TokenSecretKey)
	if err != nil || current != "" && current != expected {
		return setup.ErrStale
	}
	r.forgetRoute()
	if err := env.KV.Put(ctx, "core.services", relay.ID, false); err != nil {
		return setup.ErrUnavailable
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for r.service.Status().Running {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	if err := env.Secrets.Delete(ctx, relay.TokenSecretKey); err != nil {
		return err
	}
	return env.KV.Put(ctx, "mail.wiring", "relay.port", 0)
}

// ReplaceToken gives the relay a replacement of the setup's sign-in token
// (setup.TokenReplacer), only while the relay still holds the old one.
func (r *relayAdapter) ReplaceToken(ctx context.Context, env core.Env, old, token string) error {
	current, err := env.Secrets.Get(ctx, relay.TokenSecretKey)
	if err != nil {
		return setup.ErrUnavailable
	}
	if current == "" || current != old {
		return nil
	}
	if err := env.Secrets.Put(ctx, relay.TokenSecretKey, token); err != nil {
		return setup.ErrUnavailable
	}
	return nil
}

// Cloudflare plans use a separate ownership namespace for each wizard change.
// Provider plans/receipts live in Secrets; public changes contain references.
type cloudflareAdapter struct {
	newClient func(cloudflare.Config) (*cloudflare.Client, error)
}

type cloudOperation struct {
	Request setup.PlanRequest    `json:"request"`
	Owner   string               `json:"owner"`
	Fields  cloudflare.DNSFields `json:"fields"`
	Inbound *inboundOp           `json:"inbound,omitempty"`
}

func (c *cloudflareAdapter) client(ctx context.Context, env core.Env, op cloudOperation) (*cloudflare.Client, error) {
	if env.Secrets == nil || c.newClient == nil {
		return nil, setup.ErrUnavailable
	}
	token, err := env.Secrets.Get(ctx, op.Request.TokenRef)
	if err != nil || token == "" {
		return nil, setup.ErrUnavailable
	}
	return c.newClient(cloudflare.Config{Token: token, OwnerID: op.Owner})
}

func (c *cloudflareAdapter) RequiredPermissions(r setup.PlanRequest) ([]setup.Permission, error) {
	out := []setup.Permission{
		{Scope: "zone", Resource: r.ZoneID, Name: cloudflare.PermissionZoneRead},
		{Scope: "zone", Resource: r.ZoneID, Name: cloudflare.PermissionDNSWrite},
	}
	if r.Decision.Send == setup.RelaySend {
		out = append(out, setup.Permission{Scope: "account", Resource: r.AccountID, Name: cloudflare.PermissionSendingWrite})
	}
	if r.Decision.Receive == setup.RoutingReceive {
		out = append(out, inboundPermissions(r)...)
	}
	return out, nil
}

func (c *cloudflareAdapter) Plan(ctx context.Context, env core.Env, r setup.PlanRequest) (setup.Prepared, error) {
	permissions, err := c.RequiredPermissions(r)
	if err != nil {
		return setup.Prepared{}, err
	}
	plan := setup.Prepared{Restorable: true, Permissions: permissions}
	for _, need := range r.Decision.Needs {
		if need == "cloudflare.inbound" {
			if err := c.planInbound(ctx, env, r, &plan); err != nil {
				return setup.Prepared{}, err
			}
			continue
		}
		if need != "cloudflare.sending" && !strings.HasPrefix(need, "dns.") {
			continue
		}
		op := cloudOperation{Request: r, Owner: "hk-" + fingerprint([]string{r.SessionID, need})[:32]}
		client, err := c.client(ctx, env, op)
		if err != nil {
			return setup.Prepared{}, err
		}
		zone, err := client.GetZone(ctx, r.ZoneID)
		if err != nil || zone.Account.ID != r.AccountID || !(r.Domain == zone.Name || strings.HasSuffix(r.Domain, "."+zone.Name)) {
			return setup.Prepared{}, setup.ErrUnsafeZone
		}
		target, before, after := "cloudflare.dns", "missing", ""
		if need == "cloudflare.sending" {
			target = "cloudflare.sending"
			existing, err := client.ListSendingDomains(ctx, r.ZoneID)
			if err != nil {
				return setup.Prepared{}, sendingError(err)
			}
			var found *cloudflare.SendingDomain
			for i := range existing {
				if existing[i].Name == r.Domain {
					found = &existing[i]
				}
			}
			preview, err := client.PreviewSendingDomain(ctx, r.ZoneID, r.Domain)
			if err != nil {
				return setup.Prepared{}, sendingError(err)
			}
			if found != nil {
				// Already in Email Sending (set up by hand or by another
				// tool). Reused only when it works: enabled and Cloudflare's
				// DNS check finds nothing to fix. It is not ours, so rollback
				// and removal leave it.
				if !found.Enabled || len(preview.Errors) > 0 {
					return setup.Prepared{}, setup.ErrSendingExisting
				}
				before, after = sendingExisting, sendingExisting
			} else {
				if len(preview.Records) == 0 {
					return setup.Prepared{}, setup.ErrUnavailable
				}
				for _, issue := range preview.Errors {
					if !strings.HasSuffix(issue.Code, ".missing") {
						return setup.Prepared{}, setup.ErrUnsafeSendingDNS
					}
				}
				raw, _ := json.Marshal(preview.Records)
				after = string(raw)
			}
		} else {
			field := cloudflare.DNSFields{Type: "TXT", Name: r.Domain, TTL: 1}
			switch need {
			case "dns.spf":
				if !r.State.Network.EgressIPv4.IsKnown() {
					return setup.Prepared{}, setup.ErrUnsafeEgress
				}
				field.Content = "v=spf1 ip4:" + r.State.Network.EgressIPv4.Value + " ~all"
			case "dns.dmarc":
				field.Name, field.Content = "_dmarc."+r.Domain, "v=DMARC1; p=none"
			case "dns.dkim":
				signing := r.State.Signing[r.Domain]
				if !signing.IsKnown() || signing.Value.Selector == "" || signing.Value.PublicKey == "" {
					return setup.Prepared{}, setup.ErrUnsafeDKIM
				}
				field.Name, field.Content = signing.Value.Selector+"._domainkey."+r.Domain, "v=DKIM1; k=rsa; p="+signing.Value.PublicKey
			case "dns.a":
				ip := net.ParseIP(r.State.Network.EgressIPv4.Value)
				if !r.State.Network.EgressIPv4.IsKnown() || ip == nil || ip.To4() == nil {
					return setup.Prepared{}, setup.ErrUnsafeEgress
				}
				proxied := false
				field.Type, field.Name, field.Content, field.Proxied = "A", "mail."+r.Domain, ip.String(), &proxied
			case "dns.mx":
				priority := 10
				field.Type, field.Content, field.Priority = "MX", "mail."+r.Domain, &priority
			default:
				return setup.Prepared{}, setup.ErrUnavailable
			}
			records, err := client.ListDNSRecords(ctx, r.ZoneID)
			if err != nil {
				return setup.Prepared{}, setup.ErrUnavailable
			}
			for _, old := range records {
				if strings.EqualFold(strings.TrimSuffix(old.Name, "."), field.Name) && (old.Type == field.Type || old.Type == "CNAME") {
					return setup.Prepared{}, setup.ErrUnsafeDNSExists
				}
			}
			op.Fields = field
			raw, _ := json.Marshal(field)
			after = string(raw)
		}
		ref := "secret:mail.wiring.cloudflare." + fingerprint([]string{r.SessionID, need})
		raw, _ := json.Marshal(op)
		if err := env.Secrets.Put(ctx, ref, string(raw)); err != nil {
			return setup.Prepared{}, setup.ErrUnavailable
		}
		plan.Changes = append(plan.Changes, core.Change{ID: need, Target: target, ActionKey: "mail.setup.change." + need,
			Params: map[string]string{"domain": r.Domain, "operationRef": ref}, Before: before, After: after})
	}
	return plan, nil
}

// sendingExisting is the Before and After of an Email Sending domain the setup
// found working and reused instead of creating one.
const sendingExisting = "existing"

func cloudOp(ctx context.Context, env core.Env, change core.Change) (cloudOperation, error) {
	var op cloudOperation
	raw, err := env.Secrets.Get(ctx, change.Params["operationRef"])
	if err != nil || json.Unmarshal([]byte(raw), &op) != nil || op.Request.Domain != change.Params["domain"] {
		return op, setup.ErrUnavailable
	}
	return op, nil
}

func (c *cloudflareAdapter) Snapshot(ctx context.Context, env core.Env, change core.Change) (json.RawMessage, error) {
	op, err := cloudOp(ctx, env, change)
	if err != nil {
		return nil, err
	}
	client, err := c.client(ctx, env, op)
	if err != nil {
		return nil, err
	}
	if op.Inbound != nil {
		return c.inboundSnapshot(ctx, client, op, change)
	}
	if change.Target == "cloudflare.sending" {
		domains, err := client.ListSendingDomains(ctx, op.Request.ZoneID)
		if err != nil {
			return nil, setup.ErrUnavailable
		}
		reused := change.Before == sendingExisting
		present := false
		for _, domain := range domains {
			if domain.Name == op.Request.Domain {
				present = true
				if !reused || !domain.Enabled {
					return nil, setup.ErrStale
				}
			}
		}
		if reused {
			if !present {
				return nil, setup.ErrStale
			}
			return json.Marshal(map[string]string{"operationRef": change.Params["operationRef"], "before": sendingExisting})
		}
	} else {
		records, err := client.ListDNSRecords(ctx, op.Request.ZoneID)
		if err != nil {
			return nil, setup.ErrUnavailable
		}
		for _, old := range records {
			if old.Name == op.Fields.Name && (old.Type == op.Fields.Type || old.Type == "CNAME") {
				return nil, setup.ErrStale
			}
		}
	}
	return json.Marshal(map[string]string{"operationRef": change.Params["operationRef"], "before": "missing"})
}

func (c *cloudflareAdapter) Apply(ctx context.Context, env core.Env, change core.Change) error {
	op, err := cloudOp(ctx, env, change)
	if err != nil {
		return err
	}
	client, err := c.client(ctx, env, op)
	if err != nil {
		return err
	}
	if op.Inbound != nil {
		return c.inboundApply(ctx, env, client, op)
	}
	ref := change.Params["operationRef"]
	if change.Target == "cloudflare.sending" && change.Before == sendingExisting {
		// Reused, not created: check it still works; nothing is written.
		domains, err := client.ListSendingDomains(ctx, op.Request.ZoneID)
		if err != nil {
			return setup.ErrUnavailable
		}
		ok := false
		for _, domain := range domains {
			ok = ok || (domain.Name == op.Request.Domain && domain.Enabled)
		}
		if !ok {
			return setup.ErrStale
		}
		return env.KV.Put(ctx, "mail.wiring", "cloudflare."+op.Request.Domain, op)
	}
	if change.Target == "cloudflare.sending" {
		// A sender cannot carry our ownership marker. Only a durably saved
		// creation receipt authorizes adoption or deletion after a lost reply.
		saved, err := env.Secrets.Get(ctx, ref+".receipt")
		if err != nil {
			return setup.ErrUnavailable
		}
		if saved != "" {
			var receipt cloudflare.SendingReceipt
			if json.Unmarshal([]byte(saved), &receipt) != nil {
				return setup.ErrUnsafeRecord
			}
			current, err := client.GetSendingDomain(ctx, receipt.ZoneID, receipt.Domain.ID)
			if err != nil || current.Name != receipt.Domain.Name || !current.Enabled {
				return setup.ErrStale
			}
			return nil
		}
		preview, err := client.PreviewSendingDomain(ctx, op.Request.ZoneID, op.Request.Domain)
		if err != nil {
			return setup.ErrUnavailable
		}
		rawPreview, _ := json.Marshal(preview.Records)
		if string(rawPreview) != change.After {
			return setup.ErrStale
		}
		attempt, err := env.Secrets.Get(ctx, ref+".attempt")
		if err != nil || attempt != "" {
			return setup.ErrUnavailable // never repeat possibly delivered create
		}
		if err := env.Secrets.Put(ctx, ref+".attempt", "sent"); err != nil {
			return setup.ErrUnavailable
		}
		receipt, err := client.OnboardSendingDomain(ctx, op.Request.ZoneID, op.Request.Domain)
		if err != nil {
			return sendingError(err)
		}
		raw, _ := json.Marshal(receipt)
		if err := env.Secrets.Put(ctx, ref+".receipt", string(raw)); err != nil {
			return setup.ErrUnavailable
		}
	} else {
		records, err := client.ListDNSRecords(ctx, op.Request.ZoneID)
		if err != nil {
			return setup.ErrUnavailable
		}
		matches := 0
		for _, record := range records {
			if record.Comment != "syno-home-keeper:"+op.Owner {
				if strings.EqualFold(strings.TrimSuffix(record.Name, "."), op.Fields.Name) && (record.Type == op.Fields.Type || record.Type == "CNAME") {
					return setup.ErrStale
				}
				continue
			}
			if dnsMatches(record.DNSFields, op.Fields) {
				matches++
			} else {
				return setup.ErrStale
			}
		}
		if matches > 1 {
			return setup.ErrStale
		}
		if matches == 0 {
			attempt, err := env.Secrets.Get(ctx, ref+".attempt")
			if err != nil || attempt != "" {
				return setup.ErrUnavailable
			}
			if err := env.Secrets.Put(ctx, ref+".attempt", "sent"); err != nil {
				return setup.ErrUnavailable
			}
			if _, err := client.CreateDNSRecord(ctx, op.Request.ZoneID, op.Fields); err != nil {
				return setup.ErrUnavailable
			}
		}
	}
	return env.KV.Put(ctx, "mail.wiring", "cloudflare."+op.Request.Domain, op)
}

func dnsMatches(a, b cloudflare.DNSFields) bool {
	a.Comment, b.Comment = "", ""
	if len(a.Tags) == 0 {
		a.Tags = nil
	}
	if len(b.Tags) == 0 {
		b.Tags = nil
	}
	return reflect.DeepEqual(a, b)
}

func (c *cloudflareAdapter) Rollback(ctx context.Context, env core.Env, change core.Change, snapshot json.RawMessage) error {
	var saved map[string]string
	if json.Unmarshal(snapshot, &saved) != nil || saved["operationRef"] != change.Params["operationRef"] || saved["before"] != change.Before {
		return setup.ErrUnsafeRecord
	}
	op, err := cloudOp(ctx, env, change)
	if err != nil {
		return err
	}
	client, err := c.client(ctx, env, op)
	if err != nil {
		return err
	}
	if op.Inbound != nil {
		return c.inboundRollback(ctx, env, client, op)
	}
	if change.Target == "cloudflare.sending" && saved["before"] == sendingExisting {
		return nil // reused, not created: never deleted
	}
	if saved["before"] != "missing" {
		return setup.ErrUnsafeRecord
	}
	ref := change.Params["operationRef"]
	if change.Target == "cloudflare.sending" {
		raw, err := env.Secrets.Get(ctx, ref+".receipt")
		if err != nil {
			return setup.ErrUnavailable
		}
		if raw == "" {
			attempt, err := env.Secrets.Get(ctx, ref+".attempt")
			if err != nil || attempt != "" {
				return setup.ErrUnavailable
			}
			return nil
		}
		var receipt cloudflare.SendingReceipt
		if json.Unmarshal([]byte(raw), &receipt) != nil {
			return setup.ErrUnsafeRecord
		}
		return undoError(client.RollbackSendingDomain(ctx, receipt), setup.PermSendingEdit)
	}
	records, err := client.ListOwnedDNSRecords(ctx, op.Request.ZoneID)
	if err != nil {
		return undoError(err, setup.PermDNSEdit)
	}
	for _, record := range records {
		if !dnsMatches(record.DNSFields, op.Fields) {
			return setup.ErrStale
		}
	}
	for _, record := range records {
		if err := client.DeleteDNSRecord(ctx, op.Request.ZoneID, record.ID); err != nil {
			return undoError(err, setup.PermDNSEdit)
		}
	}
	return nil
}

func (c *cloudflareAdapter) selectors(ctx context.Context, env core.Env, domain string) ([]string, error) {
	if env.KV == nil {
		return nil, core.ErrUnavailable
	}
	var op cloudOperation
	found, err := env.KV.Get(ctx, "mail.wiring", "cloudflare."+domain, &op)
	if err != nil || !found {
		return nil, core.ErrUnavailable
	}
	if token, err := env.Secrets.Get(ctx, op.Request.TokenRef); err == nil && token == "" {
		// The setup token is deleted once the flow is kept; the relay keeps
		// its own copy of the same token (one token, pasted once).
		op.Request.TokenRef = relay.TokenSecretKey
	}
	client, err := c.client(ctx, env, op)
	if err != nil {
		return nil, err
	}
	senders, err := client.ListSendingDomains(ctx, op.Request.ZoneID)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, sender := range senders {
		if sender.Name == domain && sender.Enabled && sender.DKIMSelector != "" {
			out = append(out, sender.DKIMSelector)
		}
	}
	return out, nil
}

// signInClient opens a client on the sealed sign-in token. Reads only: the
// owner namespace is never used for a write. accountID selects the
// account-owned token's verify endpoint (/accounts/{id}/tokens/verify);
// every other call is the same for both kinds of token.
func (c *cloudflareAdapter) signInClient(ctx context.Context, env core.Env, tokenRef, accountID string) (*cloudflare.Client, string, error) {
	if env.Secrets == nil || c.newClient == nil {
		return nil, "", setup.ErrUnavailable
	}
	token, err := env.Secrets.Get(ctx, tokenRef)
	if err != nil || token == "" {
		return nil, "", setup.ErrUnavailable
	}
	client, err := c.clientFor(token, accountID)
	return client, token, err
}

// clientFor opens a sign-in client on a token held in memory (the verify
// step runs before anything is sealed).
func (c *cloudflareAdapter) clientFor(token, accountID string) (*cloudflare.Client, error) {
	if c.newClient == nil {
		return nil, setup.ErrUnavailable
	}
	client, err := c.newClient(cloudflare.Config{Token: token, OwnerID: "hk-signin", TokenAccountID: accountID})
	if err != nil {
		// A malformed token (the operation layer already refused spaces).
		return nil, setup.ErrTokenInvalid
	}
	return client, nil
}

// refused is a clear refusal of the token by a verify endpoint: HTTP 401 or
// 403, Cloudflare's token codes (cloudflare.classify), or a token that is not
// active. Only a verify endpoint decides that a token is invalid; text is
// never read.
func refused(err error) bool {
	return cloudflare.IsKind(err, cloudflare.ErrAuth) || cloudflare.IsKind(err, cloudflare.ErrPermission)
}

// readRefused classifies one sign-in read made with a token Cloudflare
// accepted: HTTP 403 (whatever its code, 9109 included) means that read's
// permission is missing; any other failure, 401 included, is unavailable.
// sendingError names a plan refusal of Email Sending in plain words; any
// other failure stays unavailable. Workers Free now onboards a sending domain
// and refuses only recipients that are not verified destination addresses
// (code 10208): verifyInbound names that from the check mail.
func sendingError(err error) error {
	if cloudflare.PlanLimited(err) {
		return setup.ErrSendingPlan
	}
	return setup.ErrUnavailable
}

func readRefused(err error) (bool, error) {
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, context.Canceled):
		return false, err
	case cloudflare.PermissionRefused(err):
		// Only a documented authorization refusal names a permission; a 403
		// with another code (a product not enabled, a plan limit) is unknown.
		return true, nil
	}
	return false, setup.ErrCloudflareUnavailable
}

// maxAccountVerifies bounds the account-owned verify attempts of one sign-in.
const maxAccountVerifies = 20

// Accounts verifies the token and lists its accounts. Both kinds of token
// are accepted, deterministically, and only a verify endpoint decides that a
// token is invalid:
//
//   - A user token passes GET /user/tokens/verify. Its accounts come from
//     GET /accounts or, when that is refused (403), from the zones it can
//     read. 403 on /zones means Zone Read is missing; any other failure of
//     these reads is unavailable. Accepted, /accounts refused and no zone
//     yet: the account is unknown until its first zone (AccountUnknown).
//   - An account-owned token (the account token URL creates one) is refused
//     by the user endpoint; Cloudflare documents no specific error for that,
//     so any clear refusal there leads to the account path. Its account is
//     discovered the same way (/accounts, else the zones' accounts; 401 or
//     403 there only mean "nothing found this way") and the token is
//     verified with GET /accounts/{id}/tokens/verify of each candidate: it
//     belongs to the one that accepts it. No candidate account, or every
//     candidate refused it clearly: invalid. A 403 on the discovery reads
//     proves nothing (Cloudflare answers an unknown token there with 403,
//     code 9109), so no permission is reported missing before a verify
//     endpoint answered that the token is active.
//
// A malformed credential (HTTP 400 with an Authorization-format code) at a
// verify endpoint is invalid at once. Anything unclear on the way (5xx,
// transport, an unexpected reply) is ErrCloudflareUnavailable, never a guess.
func (c *cloudflareAdapter) Accounts(ctx context.Context, _ core.Env, token string) (setup.CloudAccess, error) {
	if token == "" {
		return setup.CloudAccess{}, setup.ErrTokenInvalid
	}
	client, err := c.clientFor(token, "")
	if err != nil {
		return setup.CloudAccess{}, err
	}
	_, err = client.VerifyToken(ctx)
	switch {
	case err == nil:
		return c.userAccounts(ctx, client)
	case cloudflare.IsKind(err, cloudflare.ErrInvalid), cloudflare.MalformedCredential(err):
		// Malformed: refused locally, or Cloudflare's HTTP 400 with an
		// Authorization-format code. Neither kind of token: no account probe.
		return setup.CloudAccess{}, setup.ErrTokenInvalid
	case errors.Is(err, context.Canceled):
		return setup.CloudAccess{}, err
	case !refused(err):
		return setup.CloudAccess{}, setup.ErrCloudflareUnavailable
	}
	return c.accountTokenAccounts(ctx, client, token)
}

func (c *cloudflareAdapter) userAccounts(ctx context.Context, client *cloudflare.Client) (setup.CloudAccess, error) {
	out := setup.CloudAccess{Accounts: []setup.CloudAccount{}}
	accounts, err := client.ListAccounts(ctx)
	accountsRefused, err := readRefused(err)
	if err != nil {
		return setup.CloudAccess{}, err
	}
	for _, a := range accounts {
		out.Accounts = append(out.Accounts, setup.CloudAccount{ID: a.ID, Name: a.Name})
	}
	zones, err := client.ListZones(ctx)
	zonesRefused, err := readRefused(err)
	if err != nil {
		return setup.CloudAccess{}, err
	}
	if zonesRefused {
		out.Missing = []string{setup.PermZoneRead}
	}
	if accountsRefused {
		out.Accounts = zoneAccounts(zones)
		out.AccountUnknown = !zonesRefused && len(zones) == 0
	}
	return out, nil
}

// zoneAccounts names the accounts that own zones, each once.
func zoneAccounts(zones []cloudflare.Zone) []setup.CloudAccount {
	out, seen := []setup.CloudAccount{}, map[string]bool{}
	for _, z := range zones {
		if z.Account.ID != "" && !seen[z.Account.ID] {
			seen[z.Account.ID] = true
			out = append(out, setup.CloudAccount{ID: z.Account.ID, Name: z.Account.Name})
		}
	}
	return out
}

// discovered classifies a discovery read for a token the user endpoint
// refused: found (nil), nothing found this way (401 or 403; the second result
// is only whether the answer was not 401, and proves nothing about the
// token), or unavailable.
func discovered(err error) (found, accepted bool, out error) {
	switch {
	case err == nil:
		return true, true, nil
	case errors.Is(err, context.Canceled):
		return false, false, err
	case cloudflare.HTTPStatus(err) == 401:
		return false, false, nil
	case cloudflare.HTTPStatus(err) == 403:
		return false, true, nil
	}
	return false, false, setup.ErrCloudflareUnavailable
}

func (c *cloudflareAdapter) accountTokenAccounts(ctx context.Context, client *cloudflare.Client, token string) (setup.CloudAccess, error) {
	accounts, err := client.ListAccounts(ctx)
	accountsFound, _, err := discovered(err)
	if err != nil {
		return setup.CloudAccess{}, err
	}
	zones, zerr := client.ListZones(ctx)
	zonesFound, _, err := discovered(zerr)
	if err != nil {
		return setup.CloudAccess{}, err
	}
	candidates := []setup.CloudAccount{}
	if accountsFound {
		for _, a := range accounts {
			candidates = append(candidates, setup.CloudAccount{ID: a.ID, Name: a.Name})
		}
	}
	if len(candidates) == 0 && zonesFound {
		candidates = zoneAccounts(zones)
	}
	if len(candidates) == 0 {
		// The user endpoint refused it and no account is there to verify it
		// against: no verify endpoint accepted it, so it is not a usable
		// token (a 403 on these reads proves nothing: Cloudflare answers an
		// unknown token with 403 code 9109 there).
		return setup.CloudAccess{}, setup.ErrTokenInvalid
	}
	owner, err := c.verifyAccountToken(ctx, token, candidates)
	if err != nil {
		return setup.CloudAccess{}, err
	}
	out := setup.CloudAccess{Accounts: []setup.CloudAccount{owner}}
	// Verified now: the zone read follows the accepted-token rule.
	zonesRefused, err := readRefused(zerr)
	if err != nil {
		return setup.CloudAccess{}, err
	}
	if zonesRefused {
		out.Missing = []string{setup.PermZoneRead}
	}
	return out, nil
}

// verifyAccountToken verifies an account-owned token against each candidate
// account, at most maxAccountVerifies. The account that verifies it owns it.
func (c *cloudflareAdapter) verifyAccountToken(ctx context.Context, token string, candidates []setup.CloudAccount) (setup.CloudAccount, error) {
	if len(candidates) > maxAccountVerifies {
		return setup.CloudAccount{}, setup.ErrCloudflareUnavailable
	}
	unclear := false
	for _, a := range candidates {
		client, err := c.clientFor(token, a.ID)
		if err != nil {
			if errors.Is(err, setup.ErrTokenInvalid) {
				unclear = true // an account ID the client refuses: not an answer
				continue
			}
			return setup.CloudAccount{}, err
		}
		_, err = client.VerifyToken(ctx)
		switch {
		case err == nil:
			return a, nil
		case cloudflare.MalformedCredential(err):
			return setup.CloudAccount{}, setup.ErrTokenInvalid
		case errors.Is(err, context.Canceled):
			return setup.CloudAccount{}, err
		case refused(err), cloudflare.IsKind(err, cloudflare.ErrNotFound):
			// This account does not own the token.
		default:
			unclear = true
		}
	}
	if unclear {
		return setup.CloudAccount{}, setup.ErrCloudflareUnavailable
	}
	return setup.CloudAccount{}, setup.ErrTokenInvalid
}

// Zones lists one account's zones. 403 means Zone Read is missing; any
// other failure (401 included) is unavailable.
func (c *cloudflareAdapter) Zones(ctx context.Context, env core.Env, tokenRef, accountID string) ([]setup.CloudZone, []string, error) {
	client, _, err := c.signInClient(ctx, env, tokenRef, "")
	if err != nil {
		return nil, nil, err
	}
	zones, err := client.ListAccountZones(ctx, accountID)
	missing, err := readRefused(err)
	if err != nil {
		return nil, nil, err
	}
	if missing {
		return nil, []string{setup.PermZoneRead}, nil
	}
	out := []setup.CloudZone{}
	for _, z := range zones {
		out = append(out, setup.CloudZone{ID: z.ID, Name: z.Name, Status: z.Status, Type: z.Type})
	}
	return out, nil, nil
}

// NSNames lists the names of the zone's NS records (the zone fact's
// delegation check). Any failure, a refusal included, is an error: unknown.
func (c *cloudflareAdapter) NSNames(ctx context.Context, env core.Env, tokenRef, zoneID string) ([]string, error) {
	client, _, err := c.signInClient(ctx, env, tokenRef, "")
	if err != nil {
		return nil, err
	}
	records, err := client.ListNSRecords(ctx, zoneID)
	if err != nil {
		return nil, setup.ErrCloudflareUnavailable
	}
	out := []string{}
	for _, r := range records {
		if !strings.EqualFold(r.Type, "NS") {
			continue
		}
		out = append(out, detect.NormalizeDomain(r.Name))
	}
	return out, nil
}

// Probe reads the zone's DNS records and, for the relay, its Email Sending
// domains: the reads the plan makes first. 403 names the permission the token
// link asks for (DNS: Edit, Email Sending: Edit); any other failure is
// unavailable. Success proves only the read, so a write refusal can still
// come at apply.
func (c *cloudflareAdapter) Probe(ctx context.Context, env core.Env, tokenRef, accountID, zoneID string, relay, inbound bool) ([]string, error) {
	client, _, err := c.signInClient(ctx, env, tokenRef, "")
	if err != nil {
		return nil, err
	}
	missing := []string{}
	_, err = client.ListDNSRecords(ctx, zoneID)
	if refused, err := readRefused(err); err != nil {
		return nil, err
	} else if refused {
		missing = append(missing, setup.PermDNSEdit)
	}
	if relay {
		_, err = client.ListSendingDomains(ctx, zoneID)
		if cloudflare.PlanLimited(err) {
			return nil, setup.ErrSendingPlan
		}
		if refused, err := readRefused(err); err != nil {
			return nil, err
		} else if refused {
			missing = append(missing, setup.PermSendingEdit)
		}
	}
	if inbound {
		// Reads of each inbound permission group; Write covers Read for all.
		for _, read := range []struct {
			code string
			call func() error
		}{
			{setup.PermZoneSettingsEdit, func() error { _, e := client.RoutingStatus(ctx, zoneID); return e }},
			{setup.PermRoutingRulesEdit, func() error { _, e := client.ListRoutingRules(ctx, zoneID); return e }},
			{setup.PermWorkersEdit, func() error { _, e := client.ListWorkers(ctx, accountID); return e }},
			{setup.PermVPCAdmin, func() error { _, e := client.ListVPCServices(ctx, accountID); return e }},
			{setup.PermTunnelRead, func() error { _, e := client.ListTunnels(ctx, accountID); return e }},
		} {
			if refused, err := readRefused(read.call()); err != nil {
				return nil, err
			} else if refused {
				missing = append(missing, read.code)
			}
		}
	}
	return missing, nil
}

var _ setup.CloudDirectory = (*cloudflareAdapter)(nil)
var _ setup.ZoneDelegations = (*cloudflareAdapter)(nil)
var _ setup.CloudflareClient = (*cloudflareAdapter)(nil)
var _ setup.Relay = (*relayAdapter)(nil)
var _ setup.TokenReplacer = (*relayAdapter)(nil)
var _ setup.MailPlus = mailPlusAdapter{}
var _ diagnose.StateSource = detectorState{}
var _ setup.MailDomainSource = (*detect.Detector)(nil)
