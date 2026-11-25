package mail

import (
	"context"
	"errors"
	"sort"
	"strings"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/cloudflare"
	"SynoMailPlusSetupAssistant/internal/mail/relay"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

// A revoked or rolled Cloudflare token (owner request 2026-11-13:
// the administrator may delete the token in Cloudflare's dashboard).
//
// One kept setup has one token, used in four places: the relay's SMTP login
// to smtp.mx.cloudflare.net (the relay keeps its own sealed copy,
// relay.TokenSecretKey), the mailbox sync, the removal (the journal's sign-in
// token reference is answered with the current token, tokenAlias) and the
// diagnosis's Email Sending selector read. Each notices a refused token where
// it already calls Cloudflare; nothing polls (hibernation):
//
//   - the relay: a permanent refusal of AUTH (535 and the like) marks every
//     kept setup that sends through the relay; MailPlus gets a temporary
//     451, so its mail stays queued and is retried. The next accepted AUTH
//     clears it.
//   - Cloudflare API calls of the sync, the removal and the diagnosis: a
//     401/403 (or Cloudflare's token codes) is confirmed with the token's
//     verify endpoint; only a verify that refuses the token marks it (a 403
//     with an active token is a missing permission, not a dead token). A
//     sync that succeeds clears it.
//
// The state is one boolean on the kept record (tokenInvalid), written only
// when it changes. It holds no secret.
//
// mail.inbound.token replaces the token for everything at once: it is
// verified active and checked against every permission the kept setup needs
// (missing ones are named together), sealed, copied to the relay when this
// setup's relay holds a token, and the state is cleared. The relay reads its
// token for every message, so the next MailPlus retry logs in with the new
// one; no restart is needed.

// TokenMissing: a replacement token is active but lacks permissions the kept
// setup needs (catalog mail.setup.cloudflare.permission.<code>).
type TokenMissing = setup.PermissionsMissing

// usesRelay: the kept setup turned the relay on (its journal says so), so
// the relay's SMTP login is this setup's token.
func usesRelay(rec keptRecord) bool {
	for _, a := range rec.Applied {
		if a.Change.Target == "homekeeper.relay" {
			return true
		}
	}
	return false
}

func hasTarget(rec keptRecord, target string) bool {
	for _, a := range rec.Applied {
		if a.Change.Target == target {
			return true
		}
	}
	return false
}

// markToken sets tokenInvalid on every kept setup match selects, writing
// only the records whose state changes. A legacy setup is recorded on the
// way (as SetToken does), so its state has a home.
func (s *InboundSync) markToken(ctx context.Context, env core.Env, match func(keptRecord) bool, invalid bool) error {
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()
	all, err := s.records(ctx, env)
	if err != nil {
		return err
	}
	for _, rec := range all {
		if !match(rec) || rec.TokenInvalid == invalid {
			continue
		}
		rec.TokenInvalid = invalid
		if err := env.KV.Put(ctx, keptModule, keptKey(rec.ID), rec); err != nil {
			return core.ErrUnavailable
		}
		if env.Log != nil {
			env.Log.Info("cloudflare token state", "domain", rec.Domain, "invalid", invalid)
		}
	}
	return nil
}

// RelayToken is the relay's report after each upstream AUTH (relay.Service
// TokenResult). The last reported state is kept in memory, so a steady
// state costs no store access; a change marks or clears the setups that
// send through the relay.
func (s *InboundSync) RelayToken(ctx context.Context, env core.Env, refused bool) {
	s.mu.Lock()
	same := s.relayRefused != nil && *s.relayRefused == refused
	s.mu.Unlock()
	if same {
		return
	}
	match := func(rec keptRecord) bool { return usesRelay(rec) && rec.TokenRef != "" }
	if err := s.markToken(context.WithoutCancel(ctx), env, match, refused); err != nil {
		return // unknown: try again on the next message
	}
	s.mu.Lock()
	s.relayRefused = &refused
	s.mu.Unlock()
}

// tokenActive asks Cloudflare's verify endpoints whether the token is
// active: a user token, or one owned by the setup's account. It returns the
// client to read with (ErrTokenInvalid for a refused token,
// ErrCloudflareUnavailable when the answer is unclear).
func (s *InboundSync) tokenActive(ctx context.Context, token, accountID string) (*cloudflare.Client, error) {
	if token == "" {
		return nil, setup.ErrTokenInvalid
	}
	client, err := s.cloud.clientFor(token, "")
	if err != nil {
		return nil, err
	}
	_, err = client.VerifyToken(ctx)
	switch {
	case err == nil:
		return client, nil
	case cloudflare.IsKind(err, cloudflare.ErrInvalid), cloudflare.MalformedCredential(err):
		return nil, setup.ErrTokenInvalid
	case errors.Is(err, context.Canceled):
		return nil, err
	case !refused(err):
		return nil, setup.ErrCloudflareUnavailable
	}
	// Maybe owned by the setup's account.
	client, err = s.cloud.clientFor(token, accountID)
	if err != nil {
		return nil, err
	}
	if _, err := client.VerifyToken(ctx); err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			return nil, err
		case refused(err), cloudflare.IsKind(err, cloudflare.ErrNotFound), cloudflare.MalformedCredential(err):
			return nil, setup.ErrTokenInvalid
		}
		return nil, setup.ErrCloudflareUnavailable
	}
	return client, nil
}

// cloudRefused handles a Cloudflare call of a kept setup that was refused
// (401/403 or a token code): the verify endpoint decides whether the token
// itself is dead. Only a definite refusal marks the setup.
func (s *InboundSync) cloudRefused(ctx context.Context, env core.Env, rec keptRecord, token string) {
	if _, err := s.tokenActive(ctx, token, rec.AccountID); errors.Is(err, setup.ErrTokenInvalid) {
		_ = s.markToken(ctx, env, func(r keptRecord) bool { return r.ID == rec.ID }, true)
	}
}

// tokenRefusal: a Cloudflare error that may mean a dead token (401, 403 or
// Cloudflare's token codes), worth one verify call.
func tokenRefusal(err error) bool {
	status := cloudflare.HTTPStatus(err)
	return refused(err) || cloudflare.PermissionRefused(err) || status == 401 || status == 403
}

// DomainRefused is the diagnosis's report of a refused Cloudflare read for
// a mail domain (the Email Sending selector read): each kept setup of that
// domain with a token has it verified.
func (s *InboundSync) DomainRefused(ctx context.Context, env core.Env, domain string) {
	all, err := s.records(ctx, env)
	if err != nil {
		return
	}
	for _, rec := range all {
		if !strings.EqualFold(rec.Domain, domain) || rec.TokenRef == "" || rec.TokenInvalid {
			continue
		}
		token, err := env.Secrets.Get(ctx, rec.TokenRef)
		if err != nil || token == "" {
			continue
		}
		s.cloudRefused(ctx, env, rec, token)
	}
}

// InvalidDomains lists the domains of kept setups whose token is marked
// invalid (sorted, unique). Reads the package's records only.
func (s *InboundSync) InvalidDomains(ctx context.Context, env core.Env) []string {
	all, err := s.records(ctx, env)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, rec := range all {
		if rec.TokenInvalid && !seen[rec.Domain] {
			seen[rec.Domain] = true
			out = append(out, rec.Domain)
		}
	}
	sort.Strings(out)
	return out
}

// neededPermissions are the permissions the kept setup's sync and removal
// need, as catalog codes (docs/mail-rules.md, "Minimal permissions for one
// kept token"), with the read that checks each one. A read cannot prove a
// write; a refused write is named when the sync or removal runs.
func neededPermissions(rec keptRecord) []string {
	out := []string{setup.PermZoneRead}
	if hasTarget(rec, "cloudflare.dns") {
		out = append(out, setup.PermDNSEdit)
	}
	if hasTarget(rec, "cloudflare.sending") || usesRelay(rec) {
		out = append(out, setup.PermSendingEdit)
	}
	if rec.Inbound != nil {
		out = append(out, setup.PermRoutingRulesEdit, setup.PermWorkersEdit, setup.PermVPCAdmin)
	}
	return out
}

// VerifyToken checks a pasted replacement token (held in memory until
// accepted): active (a user token, or one owned by the setup's account), and
// able to make the reads of every permission the kept setup needs. All
// missing permissions are named together (TokenMissing).
func (s *InboundSync) VerifyToken(ctx context.Context, rec keptRecord, token string) error {
	client, err := s.tokenActive(ctx, token, rec.AccountID)
	if err != nil {
		return err
	}
	missing := []string{}
	for _, code := range neededPermissions(rec) {
		var err error
		switch code {
		case setup.PermZoneRead:
			_, err = client.GetZone(ctx, rec.ZoneID)
		case setup.PermDNSEdit:
			_, err = client.ListDNSRecords(ctx, rec.ZoneID)
		case setup.PermSendingEdit:
			_, err = client.ListSendingDomains(ctx, rec.ZoneID)
		case setup.PermRoutingRulesEdit:
			_, err = client.ListRoutingRules(ctx, rec.ZoneID)
		case setup.PermWorkersEdit:
			_, err = client.ListWorkers(ctx, rec.AccountID)
		case setup.PermVPCAdmin:
			_, err = client.ListVPCServices(ctx, rec.AccountID)
		}
		switch {
		case err == nil:
		case errors.Is(err, context.Canceled):
			return err
		case cloudflare.PermissionRefused(err) || cloudflare.HTTPStatus(err) == 403:
			missing = append(missing, code)
		default:
			return setup.ErrCloudflareUnavailable
		}
	}
	if len(missing) > 0 {
		return TokenMissing{Codes: missing}
	}
	return nil
}

// replaceRelayToken gives the relay the new token when this setup's relay
// holds one (a relay turned off holds none and stays off).
func replaceRelayToken(ctx context.Context, env core.Env, rec keptRecord, token string) error {
	if !usesRelay(rec) {
		return nil
	}
	current, err := env.Secrets.Get(ctx, relay.TokenSecretKey)
	if err != nil {
		return setup.ErrUnavailable
	}
	if current == "" || current == token {
		return nil
	}
	if err := env.Secrets.Put(ctx, relay.TokenSecretKey, token); err != nil {
		return setup.ErrUnavailable
	}
	return nil
}
