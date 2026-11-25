package mail

import (
	"context"
	"errors"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/cloudflare"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

// The receiving DNS of a subdomain (owner decision A, 2026-11-13).
// Enabling Email Routing on a subdomain makes Cloudflare add its MX
// route1–3 and SPF records (cloudflare/routing_dns.go). The routing step
// records in a ledger, by ID, the MX and SPF records at the name before it
// enabled routing and after: what appeared is what this App created, what
// changed is restored from its snapshot. Removing the setup deletes exactly
// the created records (only while unchanged) and restores the changed ones;
// every other record stays. The ledger is per mail domain, so a setup kept
// after an earlier rolled-back one (a rollback keeps routing and its records)
// still removes what the earlier one created. The zone apex is never
// recorded: its routing records go only with turning routing off on the
// zone (the removal's ticked option).

type routingLedger struct {
	Domain string `json:"domain"`
	ZoneID string `json:"zoneId"`
	// Owner: the inbound owner whose routing step took Before.
	Owner   string                 `json:"owner"`
	Before  []cloudflare.DNSRecord `json:"before"`
	Created []cloudflare.DNSRecord `json:"created"`
	Changed []ledgerChange         `json:"changed,omitempty"`
}

type ledgerChange struct {
	Before cloudflare.DNSRecord `json:"before"`
	After  cloudflare.DNSRecord `json:"after"`
}

func ledgerKey(domain string) string { return "routingdns." + domain }

// lockedLeft is what a removal of the receiving DNS had to leave: records
// Cloudflare refuses to delete or change because Email Routing manages them
// (code 1046) even after the run unlocked the subdomain, and the zone's
// name for the dashboard link (empty when it could not be read).
type lockedLeft struct {
	Records []cloudflare.DNSRecord
	Zone    string
}

func loadLedger(ctx context.Context, env core.Env, domain string) (routingLedger, bool, error) {
	var led routingLedger
	found, err := env.KV.Get(ctx, "mail.wiring", ledgerKey(domain), &led)
	if err != nil {
		return routingLedger{}, false, setup.ErrUnavailable
	}
	return led, found && led.Domain == domain && (len(led.Created) > 0 || len(led.Changed) > 0 || led.Owner != ""), nil
}

// enableSubdomainRouting is the routing step on a subdomain: snapshot the
// name's MX/SPF once (a resumed apply keeps the first snapshot), enable,
// then record what appeared and what changed.
func enableSubdomainRouting(ctx context.Context, env core.Env, client *cloudflare.Client, op cloudOperation) error {
	r, sub := op.Request, op.Inbound.Subdomain
	led, found, err := loadLedger(ctx, env, sub)
	if err != nil {
		return err
	}
	if !found || led.Owner != op.Owner || led.ZoneID != r.ZoneID {
		before, err := client.MailRecordsAt(ctx, r.ZoneID, sub)
		if err != nil {
			return applyError("routing", err)
		}
		next := routingLedger{Domain: sub, ZoneID: r.ZoneID, Owner: op.Owner, Before: before, Created: []cloudflare.DNSRecord{}}
		if found && led.ZoneID == r.ZoneID {
			// An earlier setup's records (kept by its rollback) stay ours.
			next.Created, next.Changed = led.Created, led.Changed
		}
		led = next
		if err := env.KV.Put(ctx, "mail.wiring", ledgerKey(sub), led); err != nil {
			return setup.ErrUnavailable
		}
	}
	if _, err := client.EnableRouting(ctx, r.ZoneID, sub); err != nil {
		if cloudflare.IsKind(err, cloudflare.ErrConflict) {
			return setup.ErrStale
		}
		return applyError("routing", err)
	}
	after, err := client.MailRecordsAt(ctx, r.ZoneID, sub)
	if err != nil {
		return applyError("routing", err)
	}
	before := map[string]cloudflare.DNSRecord{}
	for _, b := range led.Before {
		before[b.ID] = b
	}
	known := map[string]bool{}
	for _, c := range led.Created {
		known[c.ID] = true
	}
	for _, c := range led.Changed {
		known[c.Before.ID] = true
	}
	for _, a := range after {
		if known[a.ID] {
			continue
		}
		if b, ok := before[a.ID]; !ok {
			led.Created = append(led.Created, a)
		} else if !cloudflare.SameRecord(a, b) {
			led.Changed = append(led.Changed, ledgerChange{Before: b, After: a})
		}
	}
	if err := env.KV.Put(ctx, "mail.wiring", ledgerKey(sub), led); err != nil {
		return setup.ErrUnavailable
	}
	return nil
}

// removeRoutingDNS undoes the ledger of rec's domain: created MX first, then
// created SPF, then the changed records restored. Each done record leaves
// the ledger at once, so a stopped removal goes on where it stopped. When
// Cloudflare refuses a record because Email Routing manages it (1046), the
// run unlocks that subdomain's records once (UnlockSubdomainRouting, scoped
// to the subdomain's name) and tries the record again. A record still
// refused, or every locked record when Cloudflare refuses the unlock itself
// (403 or another API refusal), is left in place and returned, not a stop
// (owner decision, build 48): turning routing off in the dashboard is the
// administrator's call. An unlock whose reply names anything other than the
// subdomain stops the run before any locked record is deleted.
func (s *InboundSync) removeRoutingDNS(ctx context.Context, env core.Env, rec keptRecord, token string) (lockedLeft, error) {
	var left lockedLeft
	led, found, err := loadLedger(ctx, env, rec.Domain)
	if err != nil {
		return left, err
	}
	if !found {
		return left, nil
	}
	if led.ZoneID != rec.ZoneID || s.cloud.newClient == nil {
		return left, setup.ErrUnsafeRecord
	}
	client, err := s.cloud.newClient(cloudflare.Config{Token: token, OwnerID: led.Owner})
	if err != nil {
		return left, setup.ErrUnavailable
	}
	save := func() error {
		if err := env.KV.Put(ctx, "mail.wiring", ledgerKey(rec.Domain), led); err != nil {
			return setup.ErrUnavailable
		}
		return nil
	}
	locked := func(err error) bool { return cloudflare.IsKind(err, cloudflare.ErrManagedDNS) }
	// unlock lifts the subdomain's lock at most once per run; unlocked
	// reports whether a locked record is worth trying again.
	tried, unlocked := false, false
	unlock := func() error {
		if tried {
			return nil
		}
		tried = true
		err := client.UnlockSubdomainRouting(ctx, rec.ZoneID, rec.Domain)
		switch {
		case err == nil:
			unlocked = true
			return nil
		case cloudflare.UnlockOutOfScope(err):
			return setup.ErrUnsafeRecord
		case cloudflare.HTTPStatus(err) == 401:
			return setup.ErrTokenInvalid
		case cloudflare.HTTPStatus(err) >= 400 && cloudflare.HTTPStatus(err) < 500 && cloudflare.HTTPStatus(err) != 429:
			// Refused: the locked records stay, as they did before the unlock.
			return nil
		}
		return undoError(err, setup.PermZoneSettingsEdit)
	}
	// retry runs one record's call, unlocking and trying once more when
	// Email Routing's lock refuses it.
	retry := func(call func() error) error {
		err := call()
		if !locked(err) {
			return err
		}
		if uerr := unlock(); uerr != nil {
			return uerr
		}
		if !unlocked {
			return err
		}
		return call()
	}
	for _, kind := range []string{"MX", "TXT"} {
		kept := []cloudflare.DNSRecord{}
		for i, c := range led.Created {
			if c.Type != kind {
				kept = append(kept, c)
				continue
			}
			if err := retry(func() error { _, err := client.DeleteRecordedDNS(ctx, rec.ZoneID, c); return err }); err != nil {
				if locked(err) {
					left.Records = append(left.Records, c)
					continue
				}
				led.Created = append(kept, led.Created[i:]...)
				_ = save()
				return left, removeDNSError(err)
			}
		}
		led.Created = kept
		if err := save(); err != nil {
			return left, err
		}
	}
	for len(led.Changed) > 0 {
		c := led.Changed[0]
		if err := retry(func() error { _, err := client.RestoreRecordedDNS(ctx, rec.ZoneID, c.Before, c.After); return err }); err != nil {
			if !locked(err) {
				return left, removeDNSError(err)
			}
			left.Records = append(left.Records, c.After)
		}
		led.Changed = led.Changed[1:]
		if err := save(); err != nil {
			return left, err
		}
	}
	if err := env.KV.Put(ctx, "mail.wiring", ledgerKey(rec.Domain), routingLedger{}); err != nil {
		return left, setup.ErrUnavailable
	}
	if len(left.Records) > 0 {
		// Only for the dashboard link: a failed read leaves the name out.
		if zone, err := client.GetZone(ctx, rec.ZoneID); err == nil && zone.ID == rec.ZoneID {
			left.Zone = zone.Name
		}
	}
	return left, nil
}

// removeDNSError maps a stopped record call; the unlock's own outcomes
// (already setup errors) pass through.
func removeDNSError(err error) error {
	var refused setup.PermissionRefused
	if errors.Is(err, setup.ErrUnsafeRecord) || errors.Is(err, setup.ErrTokenInvalid) || errors.Is(err, setup.ErrUnavailable) || errors.As(err, &refused) {
		return err
	}
	return undoError(err, setup.PermDNSEdit)
}
