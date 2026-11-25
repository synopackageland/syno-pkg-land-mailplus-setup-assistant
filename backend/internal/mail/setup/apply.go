package setup

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

const planParam = "mail.setup.plan"
const sessionParam = "mail.setup.session"

type changeRecord struct {
	Change     core.Change     `json:"change"`
	Snapshot   json.RawMessage `json:"snapshot,omitempty"`
	SecretRefs []string        `json:"secretRefs,omitempty"`
	Status     string          `json:"status"`
}
type verifyResult struct {
	OK       bool           `json:"ok"`
	Findings []core.Finding `json:"findings"`
}

// Budgets of the write wizard's steps. Every MailPlus read and write is a
// delegated call that may take its full two minutes after waiting for an
// executor slot (core.DSMCallWall); Cloudflare and local steps are far shorter.
const (
	// PrepareBudget: the plan reads SMTP, DKIM and both delivery settings
	// for each MailPlus change (at most six calls), plus Cloudflare reads.
	PrepareBudget = 6*core.DSMCallWall + 2*time.Minute
	// snapshotBudget: one change's current setting (at most two reads).
	snapshotBudget = 2*core.DSMCallWall + time.Minute
	// changeBudget: one apply or rollback re-reads the setting (two reads)
	// and writes it (at most two writes).
	changeBudget = 4*core.DSMCallWall + time.Minute
	// VerifyBudget: reading back runs a whole detection.
	VerifyBudget = DetectBudget
)

// applyBudget bounds one background apply of n changes, verification included.
func applyBudget(n int) time.Duration {
	return time.Duration(n)*(snapshotBudget+changeBudget) + VerifyBudget
}

// rollbackBudget bounds restoring n applied changes. A rollback always gets
// its own budget, so a timed-out apply can still be undone.
func rollbackBudget(n int) time.Duration { return time.Duration(max(n, 1)) * changeBudget }

func (w *Wizard) prepare(ctx context.Context, env core.Env, r PlanRequest) (storedPlan, error) {
	plan := storedPlan{Request: r, Changes: []core.Change{}, Permissions: []Permission{}}
	if env.KV == nil || env.Secrets == nil || w.options.Verifier == nil {
		return plan, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, PrepareBudget)
	defer cancel()
	// Reject missing secrets without returning their values or underlying errors.
	secrets := []string{}
	for _, ref := range []string{r.TokenRef, r.SMTPTokenRef} {
		if ref != "" {
			v, e := env.Secrets.Get(ctx, ref)
			if e != nil || v == "" {
				return plan, ErrUnavailable
			}
			secrets = append(secrets, v)
		}
	}
	appendPrepared := func(p Prepared, allowed map[string]bool) error {
		if !p.Restorable || len(p.Changes) == 0 {
			return ErrUnsafePlanCheck
		}
		for _, c := range p.Changes {
			if c.Params["domain"] != r.Domain || !allowed[c.Target] || c.ID == "" || len(c.ID) > 128 || !strings.HasPrefix(c.ActionKey, "mail.setup.change.") || c.Before == "" || c.After == "" || c.Before == c.After || c.Params[planParam] != "" || c.Params[sessionParam] != "" {
				return ErrUnsafePlanCheck
			}
			if !safeJSON(c, secrets) {
				return ErrUnsafeSecret
			}
			for _, old := range plan.Changes {
				if old.ID == c.ID {
					return ErrUnsafePlanCheck
				}
			}
			plan.Changes = append(plan.Changes, c)
		}
		for _, w := range p.Warnings {
			if !strings.HasPrefix(w.LabelKey, "mail.setup.") || !safeJSON(w, secrets) {
				return ErrUnsafeSecret
			}
			plan.Warnings = append(plan.Warnings, w)
		}
		for _, p := range p.Permissions {
			if p.Name == "" || p.Scope == "zone" && p.Resource != r.ZoneID || p.Scope == "account" && p.Resource != r.AccountID || p.Scope != "zone" && p.Scope != "account" {
				return ErrUnsafePlanCheck
			}
			plan.Permissions = append(plan.Permissions, p)
		}
		return nil
	}
	if r.Decision.Cloud() || hasPrefixNeed(r.Decision, "dns.") {
		if w.options.Cloudflare == nil {
			return plan, ErrUnavailable
		}
		p, e := w.options.Cloudflare.Plan(ctx, env, r)
		if e != nil {
			return plan, publicError(e)
		}
		allowed := map[string]bool{"cloudflare.dns": true}
		if r.Decision.Send == RelaySend {
			allowed["cloudflare.sending"] = true
		}
		if r.Decision.Receive == RoutingReceive {
			for _, v := range []string{"cloudflare.routing", "cloudflare.worker", "cloudflare.vpc"} {
				allowed[v] = true
			}
		}
		if e = appendPrepared(p, allowed); e != nil {
			return plan, e
		}
		required, e := w.options.Cloudflare.RequiredPermissions(r)
		if e != nil || !validPermissions(required, r.AccountID, r.ZoneID, r.Decision) || digest(required) != digest(p.Permissions) {
			return plan, ErrUnsafePlanCheck
		}
		for _, need := range r.Decision.Needs {
			if strings.HasPrefix(need, "dns.") {
				covered := false
				for _, c := range p.Changes {
					covered = covered || c.Target == "cloudflare.dns" && c.ActionKey == "mail.setup.change."+need
				}
				if !covered {
					return plan, ErrUnsafePlanCheck
				}
			}
		}
		if r.Decision.Send == RelaySend && !targetPresent(p.Changes, "cloudflare.sending") {
			return plan, ErrUnsafePlanCheck
		}
		if !permission(plan.Permissions, "zone", r.ZoneID, "Zone Read") || !permission(plan.Permissions, "zone", r.ZoneID, "DNS Write") {
			return plan, ErrUnsafePlanCheck
		}
		if r.Decision.Send == RelaySend && !permission(plan.Permissions, "account", r.AccountID, "Email Sending Write") {
			return plan, ErrUnsafePlanCheck
		}
		if r.Decision.Receive == RoutingReceive {
			// Inbound must name every permission it uses and carry every
			// path segment: rules, Worker and the VPC Service.
			for _, p := range InboundPermissions {
				resource := r.AccountID
				if p.Scope == "zone" {
					resource = r.ZoneID
				}
				if !permission(plan.Permissions, p.Scope, resource, p.Name) {
					return plan, ErrUnsafePlanCheck
				}
			}
			for _, target := range []string{"cloudflare.routing", "cloudflare.worker", "cloudflare.vpc"} {
				if !targetPresent(plan.Changes, target) {
					return plan, ErrUnsafePlanCheck
				}
			}
		}
	}
	if hasPrefixNeed(r.Decision, "relay.") {
		if w.options.Relay == nil {
			return plan, ErrUnavailable
		}
		p, e := w.options.Relay.Plan(ctx, env, r)
		if e != nil {
			return plan, publicError(e)
		}
		if e = appendPrepared(p, map[string]bool{"homekeeper.relay": true}); e != nil {
			return plan, e
		}
	}
	if hasPrefixNeed(r.Decision, "mailplus.") {
		if w.options.MailPlus == nil {
			return plan, ErrUnavailable
		}
		p, e := w.options.MailPlus.Plan(ctx, env, r, append([]core.Change{}, plan.Changes...))
		if e != nil {
			return plan, publicError(e)
		}
		allowed := map[string]bool{}
		for _, n := range r.Decision.Needs {
			switch n {
			case "mailplus.dkim.disable":
				allowed["mailplus.dkim"] = true
			case "mailplus.delivery":
				allowed["mailplus.delivery"] = true
			case "mailplus.smtp":
				allowed["mailplus.smtp"] = true
			case "mailplus.domain":
				allowed["mailplus.domain"] = true
			case "mailplus.members":
				allowed["mailplus.members"] = true
			}
		}
		if e = appendPrepared(p, allowed); e != nil {
			return plan, e
		}
		for target := range allowed {
			if !targetPresent(p.Changes, target) {
				return plan, ErrUnsafePlanCheck
			}
		}
	}
	if len(plan.Changes) == 0 || len(plan.Changes) > 100 {
		return plan, ErrUnsafePlanCheck
	}
	domainFirst(plan.Changes)
	planID := digest(plan)
	for index := range plan.Changes {
		c := &plan.Changes[index]
		if c.Params == nil {
			c.Params = map[string]string{}
		}
		c.Params[planParam] = planID
		c.Params[sessionParam] = r.SessionID
		if e := env.KV.Put(ctx, "mail.setup", "change."+digest(*c), changeRecord{Change: *c, Status: "planned", SecretRefs: []string{r.TokenRef, r.SMTPTokenRef}}); e != nil {
			return storedPlan{}, ErrUnavailable
		}
	}
	return plan, nil
}

// domainFirst moves the MailPlus Server mail domain step (mailplus.domain)
// ahead of every other change, keeping the others in order. The
// apply runs the plan in order and the rollback newest first: a refused or
// failed domain creation then leaves Cloudflare untouched, and the domain is
// deleted last, after everything that uses it.
func domainFirst(cs []core.Change) {
	slices.SortStableFunc(cs, func(a, b core.Change) int {
		ad, bd := a.Target == "mailplus.domain", b.Target == "mailplus.domain"
		switch {
		case ad && !bd:
			return -1
		case bd && !ad:
			return 1
		}
		return 0
	})
}

func permission(ps []Permission, scope, resource, name string) bool {
	for _, p := range ps {
		if p.Scope == scope && p.Resource == resource && p.Name == name {
			return true
		}
	}
	return false
}
func targetPresent(cs []core.Change, target string) bool {
	for _, c := range cs {
		if c.Target == target {
			return true
		}
	}
	return false
}
func safeJSON(v any, secrets []string) bool {
	b, e := json.Marshal(v)
	if e != nil {
		return false
	}
	for _, s := range secrets {
		if len(s) > 0 && strings.Contains(string(b), s) {
			return false
		}
	}
	var parsed any
	if json.Unmarshal(b, &parsed) != nil {
		return false
	}
	var safe func(any) bool
	safe = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			for k, v := range x {
				key := strings.ToLower(k)
				if strings.Contains(key, "password") || strings.Contains(key, "privatekey") || strings.Contains(key, "cookie") || strings.Contains(key, "synotoken") || strings.Contains(key, "token") && !strings.HasSuffix(key, "ref") {
					return false
				}
				if !safe(v) {
					return false
				}
			}
		case []any:
			for _, v := range x {
				if !safe(v) {
					return false
				}
			}
		}
		return true
	}
	return safe(parsed)
}
func (w *Wizard) writer(c core.Change) (Writer, error) {
	switch c.Target {
	case "cloudflare.dns", "cloudflare.sending", "cloudflare.routing", "cloudflare.worker", "cloudflare.vpc":
		if w.options.Cloudflare != nil {
			return w.options.Cloudflare, nil
		}
	case "homekeeper.relay":
		if w.options.Relay != nil {
			return w.options.Relay, nil
		}
	case "mailplus.delivery", "mailplus.dkim", "mailplus.smtp", "mailplus.domain", "mailplus.members":
		if w.options.MailPlus != nil {
			return w.options.MailPlus, nil
		}
	}
	return nil, ErrUnavailable
}
func loadChange(ctx context.Context, env core.Env, c core.Change) (changeRecord, error) {
	if env.KV == nil || c.Params[planParam] == "" || c.Params[sessionParam] == "" {
		return changeRecord{}, ErrUnsafeRecord
	}
	var r changeRecord
	ok, e := env.KV.Get(ctx, "mail.setup", "change."+digest(c), &r)
	if e != nil || !ok || digest(r.Change) != digest(c) {
		return changeRecord{}, ErrStale
	}
	return r, nil
}
func saveChange(ctx context.Context, env core.Env, r changeRecord) error {
	if e := env.KV.Put(ctx, "mail.setup", "change."+digest(r.Change), r); e != nil {
		return ErrUnavailable
	}
	return nil
}
func (w *Wizard) Snapshot(ctx context.Context, env core.Env, c core.Change) (json.RawMessage, error) {
	r, e := loadChange(ctx, env, c)
	if e != nil {
		return nil, e
	}
	if len(r.Snapshot) > 0 {
		return append(json.RawMessage{}, r.Snapshot...), nil
	}
	writer, e := w.writer(c)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, snapshotBudget)
	defer cancel()
	b, e := writer.Snapshot(ctx, env, c)
	if e != nil {
		return nil, publicError(e)
	}
	secretValues := []string{}
	if env.Secrets != nil {
		for _, ref := range r.SecretRefs {
			if ref != "" {
				v, e := env.Secrets.Get(ctx, ref)
				if e != nil || v == "" {
					return nil, ErrUnavailable
				}
				secretValues = append(secretValues, v)
			}
		}
	}
	// Snapshot adapters must use references for credentials; reject obvious leaks.
	if len(b) == 0 || len(b) > 256*1024 || !json.Valid(b) || !safeJSON(b, secretValues) {
		return nil, ErrUnsafeSecret
	}
	r.Snapshot = append(json.RawMessage{}, b...)
	r.Status = "snapshotted"
	if e = saveChange(ctx, env, r); e != nil {
		return nil, e
	}
	return append(json.RawMessage{}, b...), nil
}

// ApplyChange applies one snapshotted change of a plan.
func (w *Wizard) ApplyChange(ctx context.Context, env core.Env, c core.Change) error {
	r, e := loadChange(ctx, env, c)
	if e != nil {
		return e
	}
	if r.Status == "applied" {
		return nil
	}
	if r.Status != "snapshotted" && r.Status != "uncertain" {
		return ErrUnsafeRecord
	}
	writer, e := w.writer(c)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, changeBudget)
	defer cancel()
	// Persist possibly-delivered state before dispatch. An adapter must reconcile
	// this change ID before retry; the wizard never invents a replacement ID.
	r.Status = "uncertain"
	if e = saveChange(ctx, env, r); e != nil {
		return e
	}
	if e = writer.Apply(ctx, env, c); e != nil {
		return publicError(e)
	}
	r.Status = "applied"
	return saveChange(ctx, env, r)
}

// RollbackChange restores one applied change from its journaled snapshot.
func (w *Wizard) RollbackChange(ctx context.Context, env core.Env, c core.Change, snapshot json.RawMessage) error {
	r, e := loadChange(ctx, env, c)
	if e != nil {
		return e
	}
	if r.Status == "rolledback" {
		return nil
	}
	if len(r.Snapshot) == 0 || digest(r.Snapshot) != digest(snapshot) {
		return ErrUnsafeRecord
	}
	writer, e := w.writer(c)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, changeBudget)
	defer cancel()
	if e = writer.Rollback(ctx, env, c, snapshot); e != nil {
		return publicError(e)
	}
	r.Status = "rolledback"
	return saveChange(ctx, env, r)
}

// verify reads back the applied plan and asks the injected verifier for
// delivery evidence. A failed or unavailable verification is a result, never
// success; the keep/rollback choice is always offered.
func (w *Wizard) verify(ctx context.Context, env core.Env, f *Flow) (verifyResult, error) {
	if f == nil || f.Plan == nil || f.Plan.Request.SessionID != f.ID {
		return verifyResult{}, ErrStale
	}
	plan := f.Plan
	if w.options.Verifier == nil {
		return verifyResult{}, ErrUnavailable
	}
	for _, c := range plan.Changes {
		r, e := loadChange(ctx, env, c)
		if e != nil || r.Status != "applied" {
			return verifyResult{}, ErrStale
		}
	}
	ctx, cancel := context.WithTimeout(ctx, VerifyBudget)
	defer cancel()
	result, e := w.options.Verifier.Verify(ctx, env, plan.Request, append([]core.Change{}, plan.Changes...))
	// Public verifier findings must also be free of credential fields and values.
	secrets := []string{}
	if env.Secrets != nil {
		for _, ref := range []string{plan.Request.TokenRef, plan.Request.SMTPTokenRef} {
			if ref != "" {
				v, err := env.Secrets.Get(ctx, ref)
				if err != nil {
					e = ErrUnavailable
				}
				if v != "" {
					secrets = append(secrets, v)
				}
			}
		}
	}
	if !safeJSON(result.Findings, secrets) {
		e = ErrUnsafeSecret
		result.Findings = nil
	}
	success := e == nil && result.Readback && (result.Delivery || plan.Request.Decision.Gate == Minimal)
	for _, f := range result.Findings {
		if f.Severity != core.SeverityOK {
			success = false
		}
	}
	if result.Findings == nil {
		result.Findings = []core.Finding{}
	}
	if !success {
		result.Findings = append(result.Findings, core.Finding{ID: "mail.setup.verification", Module: "mail", Check: "mail.setup", Severity: core.SeverityWarning, TitleKey: "mail.setup.verificationFailed", WhyKey: "mail.setup.verificationFailedBody", FixWizard: "mail.diagnose"})
	}
	return verifyResult{OK: success, Findings: result.Findings}, nil
}

// Names are the provider inventory's exact API permission names; never infer a
// missing inbound name or ask for account-wide administrator access
func validPermissions(ps []Permission, account, zone string, d Decision) bool {
	if len(ps) == 0 {
		return false
	}
	for _, p := range ps {
		if p.Name == "" || p.Scope == "zone" && p.Resource != zone || p.Scope == "account" && p.Resource != account || p.Scope != "zone" && p.Scope != "account" {
			return false
		}
	}
	if !permission(ps, "zone", zone, "Zone Read") || !permission(ps, "zone", zone, "DNS Write") {
		return false
	}
	if d.Send == RelaySend && !permission(ps, "account", account, "Email Sending Write") {
		return false
	}
	if d.Receive == RoutingReceive {
		for _, p := range InboundPermissions {
			resource := account
			if p.Scope == "zone" {
				resource = zone
			}
			if !permission(ps, p.Scope, resource, p.Name) {
				return false
			}
		}
	}
	return true
}

// InboundPermissions are the exact Cloudflare API permission groups the
// inbound path uses, besides Zone Read and DNS Write:
// enabling and reading Email Routing (Zone Settings), the exact-address
// rules, the Worker, the VPC Service, and reading tunnels and their
// connections. Resource is filled with the plan's zone or account.
var InboundPermissions = []Permission{
	{Scope: "zone", Name: "Zone Settings Write"},
	{Scope: "zone", Name: "Email Routing Rules Write"},
	{Scope: "account", Name: "Workers Scripts Write"},
	{Scope: "account", Name: "Connectivity Directory Admin"},
	{Scope: "account", Name: "Cloudflare Tunnel Read"},
}
