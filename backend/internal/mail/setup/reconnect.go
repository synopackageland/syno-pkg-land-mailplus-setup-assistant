package setup

import (
	"context"
	"slices"

	"SynoMailPlusSetupAssistant/internal/core"
)

// A setup whose sign-in token was deleted or rolled in Cloudflare's
// dashboard while its changes are still applied: the rollback (and
// the decision's check again) would be refused by Cloudflare. The
// administrator enters a new token on the decision step; it replaces the
// sealed sign-in token in place, under the same reference, so every journal
// entry that names that reference (the Cloudflare changes and the relay's
// SMTP login) uses the new token, and the relay's own copy follows when it
// still holds the old one. Nothing else of the flow changes; the rollback is
// pressed again.

// PermissionsMissing: a new token is active but cannot make the reads of
// these permissions (catalog mail.setup.cloudflare.permission.<code>).
type PermissionsMissing struct{ Codes []string }

func (e PermissionsMissing) Error() string { return "mail.inbound.tokenMissing" }

// TokenReplacer is implemented by a Relay whose copy of the token must
// follow a replacement (old → new, only while it holds old).
type TokenReplacer interface {
	ReplaceToken(ctx context.Context, env core.Env, old, token string) error
}

// reconnectable: the flow's changes are applied and wait for the decision,
// a rollback that failed, or an interrupted run, with a sealed sign-in.
func reconnectable(f *Flow) bool {
	return outstanding(f) && (f.Phase == PhaseDecision || f.Phase == PhaseFailed || f.Phase == PhaseInterrupted) &&
		f.Cloud != nil && f.Cloud.TokenRef != "" && f.Account != nil
}

// reconnect replaces the sealed sign-in token of a flow with applied
// changes. The token must be active, belong to the bound account and make
// the reads the applied path needs; it is held in a scratch reference until
// then and never echoed.
func (w *Wizard) reconnect(ctx context.Context, env core.Env, owner, id, token string) (CloudView, error) {
	if w.options.Directory == nil || env.Secrets == nil {
		return CloudView{}, ErrUnavailable
	}
	w.flowMu.Lock()
	f, err := w.load(ctx, env, owner, id)
	if err == nil && (w.running[f.ID] || !reconnectable(f)) {
		err = ErrStale
	}
	var accountID, zoneID, ref string
	relay, inbound := false, false
	if err == nil {
		accountID, zoneID, ref = f.Account.AccountID, f.Account.ZoneID, f.Cloud.TokenRef
		if _, d, e := detected(f); e == nil {
			relay, inbound = d.Send == RelaySend, d.Receive == RoutingReceive
		}
	}
	w.flowMu.Unlock()
	if err != nil {
		return CloudView{}, err
	}
	access, accounts, err := w.verified(ctx, env, token)
	if err != nil {
		return CloudView{}, err
	}
	if !slices.ContainsFunc(accounts, func(a CloudAccount) bool { return a.ID == accountID }) && !access.AccountUnknown {
		// Another account's token cannot undo this account's changes.
		return CloudView{}, PermissionsMissing{Codes: []string{PermZoneRead}}
	}
	gen, err := newFlowID()
	if err != nil {
		return CloudView{}, err
	}
	scratch := tokenRef(id, gen)
	if err := env.Secrets.Put(ctx, scratch, token); err != nil {
		return CloudView{}, ErrUnavailable
	}
	defer func() { _ = env.Secrets.Delete(context.WithoutCancel(ctx), scratch) }()
	missing, err := w.options.Directory.Probe(ctx, env, scratch, accountID, zoneID, relay, inbound)
	if err != nil {
		return CloudView{}, directoryError(err)
	}
	if len(missing) > 0 {
		return CloudView{}, PermissionsMissing{Codes: cleanMissing(missing)}
	}

	w.flowMu.Lock()
	defer w.flowMu.Unlock()
	f, err = w.load(ctx, env, owner, id)
	if err != nil {
		return CloudView{}, err
	}
	if w.running[f.ID] || !reconnectable(f) || f.Cloud.TokenRef != ref {
		return CloudView{}, ErrStale
	}
	old, err := env.Secrets.Get(ctx, ref)
	if err != nil {
		return CloudView{}, ErrUnavailable
	}
	if err := env.Secrets.Put(ctx, ref, token); err != nil {
		return CloudView{}, ErrUnavailable
	}
	if r, ok := w.options.Relay.(TokenReplacer); ok && old != "" {
		if err := r.ReplaceToken(ctx, env, old, token); err != nil {
			return CloudView{}, err
		}
	}
	if tokenError(f.Error) {
		f.Error = ""
		if err := w.save(ctx, env, f); err != nil {
			return CloudView{}, err
		}
	}
	if env.Log != nil {
		env.Log.Info("setup token replaced", "phase", string(f.Phase))
	}
	return cloudView(f), nil
}

// tokenError: the flow stopped because Cloudflare refused its token or a
// permission (a new token is the way on).
func tokenError(code string) bool {
	if code == ErrTokenInvalid.Error() {
		return true
	}
	for _, p := range PermissionCodes {
		if code == (PermissionRefused{Code: p}).Error() {
			return true
		}
	}
	return false
}
