package setup

import (
	"context"

	"SynoMailPlusSetupAssistant/internal/core"
)

// Receiving through Cloudflare offers two modes (owner decision
// 2026-11-13): the whole domain (the zone's unused catch-all points at the
// Worker; adding or removing MailPlus users needs nothing) or one exact rule
// per mailbox, kept in line by the administrator's "Sync mailboxes" on the
// Overview with the setup's sealed token (kept by the setup's record).
// Nothing syncs on its own.

// inboundBound returns the flow's bound account and zone when it receives
// through Cloudflare and nothing was applied yet.
func (w *Wizard) inboundBound(f *Flow) (accountID, zoneID string, err error) {
	if outstanding(f) || w.running[f.ID] || f.Phase != PhaseNew {
		return "", "", ErrStale
	}
	_, d, err := detected(f)
	if err != nil {
		return "", "", err
	}
	if d.Receive != RoutingReceive || d.Gate == Minimal {
		return "", "", ErrInvalid
	}
	zone, ready := f.Cloud.ready()
	if f.Account == nil || !ready || f.Account.AccountID != f.Cloud.AccountID || f.Account.ZoneID != zone.ID {
		return "", "", ErrStale
	}
	return f.Account.AccountID, f.Account.ZoneID, nil
}

// ReceiveModes says whether the whole-domain mode can be offered for the
// flow's domain (reads the zone and its catch-all; no write).
func (w *Wizard) ReceiveModes(ctx context.Context, env core.Env, owner, id string) (ReceiveModes, error) {
	w.flowMu.Lock()
	f, err := w.load(ctx, env, owner, id)
	if err != nil {
		w.flowMu.Unlock()
		return ReceiveModes{}, err
	}
	_, zoneID, err := w.inboundBound(f)
	domain, ref := f.Domain, ""
	if f.Cloud != nil {
		ref = f.Cloud.TokenRef
	}
	w.flowMu.Unlock()
	if err != nil {
		return ReceiveModes{}, err
	}
	if w.options.Inbound == nil {
		return ReceiveModes{DomainReason: "mail.setup.receive.domainUnsupported"}, nil
	}
	modes, err := w.options.Inbound.ReceiveModes(ctx, env, ref, zoneID, domain)
	return modes, publicError(err)
}
