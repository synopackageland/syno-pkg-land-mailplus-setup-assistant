package mail

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/cloudflare"
	"SynoMailPlusSetupAssistant/internal/mail/relay"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

// Removing a kept Cloudflare setup (owner request 2026-11-13): the
// Overview's "Remove Cloudflare setup" undoes exactly what the setup applied
// and nothing else. It walks the kept record's journal newest first through
// the setup's own rollback (setup.Wizard.RollbackChange, the same code as the
// decision step's rollback), so only resources the journal proves this App
// created are touched (recorded IDs, the owner marker, the catch-all
// snapshot); a resource already gone counts as done.
//
//   - Cloudflare changes use the setup's current token (the kept record's;
//     it may have been replaced on the Overview), not the sign-in token the
//     journal names.
//   - The relay is turned off directly: its own rollback compares the relay's
//     token with the journal's, which no longer matches after a replacement.
//   - Email Routing on the zone, its locked MX/SPF and DNS stay as they are,
//     unless this setup enabled routing on the zone itself and the
//     administrator ticks the option to turn it off.
//   - Each undone step is dropped from the record at once: a removal that
//     stops (a refused permission, a changed resource, an interruption) is
//     pressed again and goes on where it stopped. At the end the sealed token
//     is deleted and the record cleared.
//
// One background job per setup; mail.cloudflare.remove waits at most
// SyncWait for it, and its poll asks for the same run again.

// RemoveRun is the outcome of the last removal of a setup (worker memory).
type RemoveRun struct {
	// State: running, done, failed.
	State string `json:"state"`
	Done  int    `json:"done"`
	Total int    `json:"total"`
	// CauseKey (failed): why it stopped, a catalog key.
	CauseKey string `json:"causeKey,omitempty"`
	// Profile (failed, cause mail.remove.cause.authority): the DSM access
	// profile the refused step needs (mail-write), so the Overview offers
	// "Allow access" for it, as the setup does.
	Profile string `json:"profile,omitempty"`
	At      int64  `json:"at,omitempty"`
	// Locked (done): receiving records Cloudflare would not delete because
	// Email Routing manages them (1046); they were left in place. AccountID
	// and Zone (the zone's name, when read) build the dashboard link where
	// the administrator can deal with them.
	Locked    []LockedRecord `json:"locked,omitempty"`
	AccountID string         `json:"accountId,omitempty"`
	Zone      string         `json:"zone,omitempty"`
	// KeptDomain (done): the MailPlus mail domain this setup created, left
	// because MailPlus users use it now.
	KeptDomain string `json:"keptDomain,omitempty"`
}

// LockedRecord is one record a removal left because Cloudflare locks it.
type LockedRecord struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

type removeJob struct {
	done chan struct{}
	run  RemoveRun
	rec  keptRecord
}

// removeStepBudget bounds one undone step (Cloudflare or DSM). A MailPlus
// restore makes up to four delegated calls (the delivery rollback: two reads,
// two writes), and the executor refuses, unsent, any call whose deadline is
// nearer than core.DSMReadTimeout; so a step holds four full call walls.
const removeStepBudget = 4*core.DSMCallWall + time.Minute

// RemoveBudget bounds one removal of n journal steps (plus routing and the
// token).
func RemoveBudget(n int) time.Duration { return time.Duration(n+3) * removeStepBudget }

// removes names, as catalog keys, what removing the setup takes away.
func removes(rec keptRecord) []string {
	has := map[string]bool{"ui.remove.item.token": true}
	if rec.RoutingDNS {
		has["ui.remove.item.receiveDNS"] = true
	}
	if rec.Inbound != nil {
		if rec.Inbound.Mode == setup.ReceiveDomain {
			has["ui.remove.item.receiveDomain"] = true
		} else {
			has["ui.remove.item.receiveAddresses"] = true
		}
	}
	for _, a := range rec.Applied {
		switch t := a.Change.Target; {
		case t == "cloudflare.sending" && a.Change.Before != sendingExisting:
			has["ui.remove.item.sending"] = true
		case t == "cloudflare.dns":
			has["ui.remove.item.dns"] = true
		case t == "mailplus.domain":
			has["ui.remove.item.mailplusDomain"] = true
		case strings.HasPrefix(t, "mailplus."):
			has["ui.remove.item.mailplus"] = true
		case t == "homekeeper.relay":
			has["ui.remove.item.relay"] = true
		}
	}
	out := []string{}
	for _, key := range []string{"ui.remove.item.receiveDomain", "ui.remove.item.receiveAddresses", "ui.remove.item.receiveDNS", "ui.remove.item.sending",
		"ui.remove.item.dns", "ui.remove.item.mailplus", "ui.remove.item.mailplusDomain", "ui.remove.item.relay", "ui.remove.item.token"} {
		if has[key] {
			out = append(out, key)
		}
	}
	return out
}

// Remove starts the removal of a kept setup (unless one runs) and waits at
// most SyncWait for it; poll only waits for the current run. routing also
// turns Email Routing off on the zone, offered only when this setup enabled
// it there.
func (s *InboundSync) Remove(ctx context.Context, env core.Env, id string, routing, poll bool) (KeptView, error) {
	s.mu.Lock()
	job := s.removals[id]
	s.mu.Unlock()
	if job != nil && (poll || job.run.State == "running") {
		return s.waitRemoval(ctx, job)
	}
	if poll {
		return KeptView{}, setup.ErrNoFlow
	}
	rec, err := s.record(ctx, env, id)
	if err != nil {
		return KeptView{}, err
	}
	if routing && !rec.RoutingOwned {
		return KeptView{}, setup.ErrInvalid
	}
	if rec.TokenRef == "" {
		return KeptView{}, setup.ErrSyncTokenRequired
	}
	if s.undo == nil || s.background == nil {
		return KeptView{}, setup.ErrUnavailable
	}
	s.mu.Lock()
	if s.removals == nil {
		s.removals = map[string]*removeJob{}
	}
	if running := s.removals[id]; running != nil && running.run.State == "running" {
		s.mu.Unlock()
		return s.waitRemoval(ctx, running)
	}
	job = &removeJob{done: make(chan struct{}), rec: rec, run: RemoveRun{State: "running", Total: removeTotal(rec, routing)}}
	s.removals[id] = job
	if _, err := s.background.Go(RemoveBudget(len(rec.Applied)), func(run context.Context) {
		// Never beside a sync of this setup: an automatic run must not add a
		// rule back while the removal deletes them.
		l := s.lock(rec.ID)
		l.Lock()
		defer l.Unlock()
		result := s.remove(run, env, rec, routing, func(done int) {
			s.mu.Lock()
			job.run.Done = done
			s.mu.Unlock()
		})
		s.mu.Lock()
		job.run = result
		s.mu.Unlock()
		close(job.done)
	}); err != nil {
		delete(s.removals, id)
		s.mu.Unlock()
		return KeptView{}, setup.ErrUnavailable
	}
	s.mu.Unlock()
	return s.waitRemoval(ctx, job)
}

func removeTotal(rec keptRecord, routing bool) int {
	n := len(rec.Applied) + 1 // the journal, then the token
	if rec.Legacy {
		n += 3 // rules, Worker, VPC Service
	}
	if routing {
		n++
	}
	if rec.RoutingDNS {
		n++
	}
	return n
}

func (s *InboundSync) waitRemoval(ctx context.Context, job *removeJob) (KeptView, error) {
	wait := s.wait
	if wait == 0 {
		wait = SyncWait
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-job.done:
	case <-timer.C:
	case <-ctx.Done():
		return KeptView{}, ctx.Err()
	}
	return s.view(job.rec), nil
}

// tokenAlias answers the journal's token references with the setup's
// current token; every other secret is read as it is.
type tokenAlias struct {
	core.Secrets
	refs  map[string]bool
	token string
}

func (a tokenAlias) Get(ctx context.Context, key string) (string, error) {
	if a.refs[key] {
		return a.token, nil
	}
	return a.Secrets.Get(ctx, key)
}

// remove is one removal run. Progress is saved after each step.
func (s *InboundSync) remove(ctx context.Context, env core.Env, rec keptRecord, routing bool, progress func(int)) RemoveRun {
	now := time.Now
	if env.Now != nil {
		now = env.Now
	}
	out := RemoveRun{State: "failed", Total: removeTotal(rec, routing), At: now().Unix()}
	done := 0
	// stepErr is the refused step's error (fixed codes only): the cause key
	// alone does not tell which check refused.
	var stepErr error
	logRun := func(r RemoveRun) RemoveRun {
		if env.Log != nil {
			detail := ""
			if stepErr != nil {
				detail = stepErr.Error()
			}
			env.Log.Info("cloudflare setup removal", "domain", rec.Domain, "state", r.State, "done", r.Done, "total", r.Total, "cause", r.CauseKey, "error", detail, "locked", len(r.Locked))
		}
		return r
	}
	token, err := env.Secrets.Get(ctx, rec.TokenRef)
	fail := func(cause string) RemoveRun {
		out.Done, out.CauseKey = done, cause
		if cause == "mail.inbound.cause.token" && token != "" {
			// Refused by Cloudflare: is the token itself dead?
			s.cloudRefused(context.WithoutCancel(ctx), env, rec, token)
		}
		return logRun(out)
	}
	if err != nil || token == "" {
		return fail("mail.inbound.cause.token")
	}
	// The journal names the sign-in token; the setup's current token answers.
	refs := map[string]bool{}
	for _, a := range rec.Applied {
		if strings.HasPrefix(a.Change.Target, "cloudflare.") {
			op, err := cloudOp(ctx, env, a.Change)
			if err != nil {
				return fail("mail.remove.cause.record")
			}
			refs[op.Request.TokenRef] = true
		}
	}
	cloudEnv := env
	cloudEnv.Secrets = tokenAlias{Secrets: env.Secrets, refs: refs, token: token}
	save := func() error { return env.KV.Put(ctx, keptModule, keptKey(rec.ID), rec) }

	if rec.Legacy {
		if err := s.removeLegacy(ctx, env, rec, token); err != nil {
			return fail(removeCause(err, "cloudflare."))
		}
		done += 3
		progress(done)
	}
	for len(rec.Applied) > 0 {
		if ctx.Err() != nil {
			return fail("mail.inbound.cause.interrupted")
		}
		last := rec.Applied[len(rec.Applied)-1]
		c := last.Change
		var err error
		step, cancel := context.WithTimeout(ctx, removeStepBudget)
		switch {
		case c.Target == "homekeeper.relay":
			if s.relayOff == nil {
				err = setup.ErrUnavailable
			} else {
				err = s.relayOff(step, env)
			}
		case strings.HasPrefix(c.Target, "cloudflare."):
			if routing && c.Params["inbound"] == "routing" {
				if err = s.routingOff(step, cloudEnv, c, token); err == nil {
					done++
					progress(done)
				}
			}
			if err == nil {
				err = s.undo(step, cloudEnv, c, last.Snapshot)
			}
		case strings.HasPrefix(c.Target, "mailplus."):
			err = s.undo(step, env, c, last.Snapshot)
			if c.Target == "mailplus.domain" && errors.Is(err, setup.ErrDomainInUse) {
				// The mail domain this setup created now has MailPlus users:
				// deleting it would delete their mail. It is left, and said.
				out.KeptDomain, err = c.Params["domain"], nil
			}
		default:
			// Nothing this App wrote (a DNS record the administrator adds
			// elsewhere, for example).
		}
		cancel()
		if err != nil {
			stepErr = fmt.Errorf("%s: %w", c.Target, err)
			var authority core.AuthorityRequired
			if errors.As(err, &authority) {
				// The executor refused the step for want of a grant (never
				// sent): name the profile so the administrator can allow it.
				out.Profile = authority.Profile
			}
			return fail(removeCause(err, c.Target))
		}
		rec.Applied = rec.Applied[:len(rec.Applied)-1]
		if err := save(); err != nil {
			return fail("mail.remove.cause.record")
		}
		// The step is undone and no longer in the record: its sealed
		// operation can never be read again. Deleted only after the
		// save, so a retry never meets a step without its operation.
		_ = setup.DropOperationSecrets(ctx, env, []core.Change{c})
		done++
		progress(done)
	}
	// The subdomain's receiving DNS this App created (its ledger).
	if rec.RoutingDNS {
		step, cancel := context.WithTimeout(ctx, removeStepBudget)
		left, err := s.removeRoutingDNS(step, env, rec, token)
		cancel()
		if err != nil {
			stepErr = fmt.Errorf("cloudflare.dns: %w", err)
			return fail(removeCause(err, "cloudflare.dns"))
		}
		for _, r := range left.Records {
			out.Locked = append(out.Locked, LockedRecord{Type: r.Type, Name: r.Name, Content: r.Content})
		}
		if len(out.Locked) > 0 {
			out.AccountID, out.Zone = rec.AccountID, left.Zone
		}
		done++
		progress(done)
	}
	// Last: forget the token, then the record.
	if err := env.Secrets.Delete(ctx, rec.TokenRef); err != nil {
		return fail("mail.remove.cause.record")
	}
	if err := env.KV.Put(ctx, keptModule, keptKey(rec.ID), keptRecord{}); err != nil {
		return fail("mail.remove.cause.record")
	}
	out.State, out.Done, out.CauseKey = "done", out.Total, ""
	return logRun(out)
}

// routingOff turns Email Routing off on the zone apex, only when the
// journal's routing step was this setup enabling it there.
func (s *InboundSync) routingOff(ctx context.Context, env core.Env, c core.Change, token string) error {
	op, err := cloudOp(ctx, env, c)
	if err != nil || op.Inbound == nil || op.Inbound.Step != "routing" || op.Inbound.Subdomain != "" || s.cloud.newClient == nil {
		return setup.ErrUnsafeRecord
	}
	client, err := s.cloud.newClient(cloudflare.Config{Token: token, OwnerID: op.Owner})
	if err != nil {
		return setup.ErrUnavailable
	}
	if err := client.DisableRouting(ctx, op.Request.ZoneID); err != nil {
		return undoError(err, setup.PermZoneSettingsEdit)
	}
	return nil
}

// removeLegacy removes a build ≤40 receiving setup, which has no journal:
// only the resources carrying its owner marker (its rules, its Worker, its
// VPC Service); its inbound record is cleared so it is not adopted again.
func (s *InboundSync) removeLegacy(ctx context.Context, env core.Env, rec keptRecord, token string) error {
	if rec.Inbound == nil || s.cloud.newClient == nil {
		return setup.ErrUnsafeRecord
	}
	client, err := s.cloud.newClient(cloudflare.Config{Token: token, OwnerID: rec.Inbound.Owner})
	if err != nil {
		return setup.ErrUnavailable
	}
	owned, err := client.OwnedRoutingRules(ctx, rec.ZoneID)
	if err != nil {
		return undoError(err, setup.PermRoutingRulesEdit)
	}
	for _, rule := range owned {
		if err := client.DeleteRoutingRule(ctx, rec.ZoneID, rule.ID); err != nil {
			return undoError(err, setup.PermRoutingRulesEdit)
		}
	}
	if err := client.DeleteWorker(ctx, rec.AccountID); err != nil {
		return undoError(err, setup.PermWorkersEdit)
	}
	service, found, err := client.FindVPCService(ctx, rec.AccountID)
	if err != nil {
		return undoError(err, setup.PermVPCAdmin)
	}
	if found {
		if err := client.DeleteVPCService(ctx, rec.AccountID, service.ServiceID); err != nil {
			return undoError(err, setup.PermVPCAdmin)
		}
	}
	return env.KV.Put(ctx, "mail.wiring", "inbound."+rec.Domain, cloudOperation{})
}

// undoError names a refused Cloudflare write (a missing permission, or a
// revoked token: HTTP 401) so the removal and the setup's rollback ask for a
// token; anything else is unavailable.
func undoError(err error, code string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if cloudflare.HTTPStatus(err) == 401 {
		// The token itself was refused (deleted or rolled in the dashboard).
		return setup.ErrTokenInvalid
	}
	if refused(err) || cloudflare.PermissionRefused(err) || cloudflare.HTTPStatus(err) == 403 {
		return setup.PermissionRefused{Code: code}
	}
	return setup.ErrUnavailable
}

// removeCause names why a step stopped, as a catalog key. A DSM step the
// executor refused for want of a grant (core.AuthorityRequired: a mail-write
// grant DSM no longer honours, or one never given) is its own cause, so the
// Overview offers "Allow access" rather than a bare "try again"; other NAS
// steps say whether MailPlus Server or the forwarding service stopped them.
func removeCause(err error, target string) string {
	var refusedErr setup.PermissionRefused
	switch {
	case errors.Is(err, core.ErrAuthorityRequired):
		return "mail.remove.cause.authority"
	case errors.Is(err, core.ErrNoAdmin):
		return "mail.remove.cause.admin"
	case errors.As(err, &refusedErr), errors.Is(err, setup.ErrTokenInvalid):
		return "mail.inbound.cause.token"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, setup.ErrUnconfirmed):
		return "mail.inbound.cause.interrupted"
	case errors.Is(err, setup.ErrStale):
		return "mail.remove.cause.changed"
	case strings.HasPrefix(target, "cloudflare."):
		return "mail.inbound.cause.cloudflare"
	case strings.HasPrefix(target, "mailplus."):
		return "mail.remove.cause.mailplus"
	case target == "homekeeper.relay":
		return "mail.remove.cause.relay"
	}
	return "mail.remove.cause.nas"
}

// relayOff turns the relay service off and forgets its token (idempotent).
// Removal calls it for the relay change the journal proves this App made.
func (r *relayAdapter) relayOff(ctx context.Context, env core.Env) error {
	if env.KV == nil || env.Secrets == nil {
		return setup.ErrUnavailable
	}
	r.forgetRoute()
	if err := env.KV.Put(ctx, "core.services", relay.ID, false); err != nil {
		return setup.ErrUnavailable
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for r.service != nil && r.service.Status().Running {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	if err := env.Secrets.Delete(ctx, relay.TokenSecretKey); err != nil {
		return setup.ErrUnavailable
	}
	return env.KV.Put(ctx, "mail.wiring", "relay.port", 0)
}
