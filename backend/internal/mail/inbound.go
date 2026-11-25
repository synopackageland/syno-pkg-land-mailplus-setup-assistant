package mail

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/cloudflare"
	"SynoMailPlusSetupAssistant/internal/mail/setup"
)

// Inbound mail through Cloudflare: Email Routing exact-address rules
// → this package's Email Worker → one Workers VPC Service (SMTP TCP 25 on the
// NAS LAN IPv4) over a healthy Cloudflare Tunnel (Syno Connect's or one the
// administrator runs) → MailPlus. Every resource carries one owner per flow;
// rollback removes only what that owner created. Enabling Email Routing and
// its Cloudflare-locked MX/SPF are kept on rollback (the API can only disable
// a whole zone); the preview says so.

// inboundOp is the public plan of one inbound change, sealed in Secrets.
type inboundOp struct {
	Step       string   `json:"step"` // routing | vpc | worker | rules
	Subdomain  string   `json:"subdomain,omitempty"`
	TunnelID   string   `json:"tunnelId"`
	TunnelName string   `json:"tunnelName"`
	Host       string   `json:"host"`
	Addresses  []string `json:"addresses"`
	// Takeover: rules an earlier setup of this package left for requested
	// addresses (another owner). The rules step points them at this
	// owner's Worker; rollback gives them back.
	Takeover []takenRule `json:"takeover,omitempty"`
	// Mode is the receiving mode (setup.ReceiveDomain or ReceiveAddresses).
	Mode string `json:"mode,omitempty"`
	// CatchAllBefore (catchall step): the zone's catch-all as the plan read
	// it. Apply writes only over exactly this; rollback puts it back only
	// while the catch-all is still ours.
	CatchAllBefore *cloudflare.RoutingRule `json:"catchAllBefore,omitempty"`
}

type takenRule struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Owner   string `json:"owner"`
}

// inboundMaxBytes is Cloudflare's inbound limit. MailPlus enforces its own
// SIZE and refuses larger mail with a 5xx, which the Worker passes on.
const inboundMaxBytes = 25 << 20

// maxRoutingRules is Cloudflare's documented Email Routing rule limit per
// domain; every non-catch-all rule in the zone is counted, to be safe.
const maxRoutingRules = 200

// maxMatchedTunnels bounds the connection reads made to match tunnels.
const maxMatchedTunnels = 20

func inboundOwner(session string) string {
	return "hk-" + fingerprint([]string{session, "cloudflare.inbound"})[:32]
}

func inboundPermissions(r setup.PlanRequest) []setup.Permission {
	out := []setup.Permission{}
	for _, p := range setup.InboundPermissions {
		p.Resource = r.AccountID
		if p.Scope == "zone" {
			p.Resource = r.ZoneID
		}
		out = append(out, p)
	}
	return out
}

// lanIPv4 reads the NAS's default-gateway interface from DSM
// (SYNO.Core.Network get v2, mail-read). It must be connected and carry one
// private, non-loopback, non-link-local IPv4; anything else is unknown.
func lanIPv4(ctx context.Context, env core.Env) (string, error) {
	if env.DSM == nil {
		return "", setup.ErrUnavailable
	}
	var out struct {
		Gateway struct {
			IP     string `json:"ip"`
			Status string `json:"status"`
		} `json:"gateway_info"`
	}
	if err := env.DSM.Call(ctx, "SYNO.Core.Network", "get", 2, nil, &out); err != nil {
		var authority core.AuthorityRequired
		if errors.As(err, &authority) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, core.ErrDSMSlotTimeout) {
			return "", err
		}
		return "", setup.ErrLANUnknown
	}
	ip, ok := cloudflare.PrivateIPv4(out.Gateway.IP)
	if !ok || out.Gateway.Status != "connected" {
		return "", setup.ErrLANUnknown
	}
	return ip, nil
}

// chooseTunnel picks the inbound tunnel. A pick must be a healthy tunnel of
// the account. Without one, a single healthy tunnel whose every connection
// comes from the NAS's public IPv4 is used; anything else asks.
func chooseTunnel(ctx context.Context, client *cloudflare.Client, r setup.PlanRequest) (cloudflare.Tunnel, error) {
	tunnels, err := client.ListTunnels(ctx, r.AccountID)
	if err != nil {
		return cloudflare.Tunnel{}, setup.ErrUnavailable
	}
	healthy := []cloudflare.Tunnel{}
	for _, t := range tunnels {
		if t.Status == "healthy" {
			healthy = append(healthy, t)
		}
	}
	if len(healthy) == 0 {
		return cloudflare.Tunnel{}, setup.ErrTunnelRequired
	}
	options := make([]setup.TunnelOption, 0, len(healthy))
	egress := ""
	if r.State.Network.EgressIPv4.IsKnown() {
		egress = r.State.Network.EgressIPv4.Value
	}
	var matched []cloudflare.Tunnel
	unread := false // a connection read failed: nothing is certain
	for i, t := range healthy {
		option := setup.TunnelOption{ID: t.ID, Name: t.Name, Connect: strings.HasPrefix(t.Name, cloudflare.ConnectPrefix)}
		if r.Tunnel != "" && t.ID == r.Tunnel {
			return t, nil
		}
		if r.Tunnel == "" && egress != "" && i < maxMatchedTunnels {
			connectors, err := client.TunnelConnectors(ctx, r.AccountID, t.ID)
			unread = unread || err != nil
			if err == nil {
				conns, same := 0, true
				for _, c := range connectors {
					for _, conn := range c.Conns {
						conns++
						same = same && conn.OriginIP == egress
					}
				}
				option.Match = conns > 0 && same
			}
		}
		if option.Match {
			matched = append(matched, t)
		}
		options = append(options, option)
	}
	// Only a certain, unique match is used: every connection read, the
	// public IP known, one tunnel whose connections (at least one) all come
	// from it. Anything else is the administrator's pick.
	if r.Tunnel == "" && !unread && len(matched) == 1 && len(healthy) <= maxMatchedTunnels {
		return matched[0], nil
	}
	return cloudflare.Tunnel{}, setup.TunnelChoice{Options: options}
}

// planInbound adds the inbound changes: Email Routing (when the mail domain
// has none yet), the VPC Service, the Worker and the exact-address rules.
func (c *cloudflareAdapter) planInbound(ctx context.Context, env core.Env, r setup.PlanRequest, plan *setup.Prepared) error {
	op := cloudOperation{Request: r, Owner: inboundOwner(r.SessionID)}
	client, err := c.client(ctx, env, op)
	if err != nil {
		return err
	}
	zone, err := client.GetZone(ctx, r.ZoneID)
	if err != nil || zone.Account.ID != r.AccountID || !(r.Domain == zone.Name || strings.HasSuffix(r.Domain, "."+zone.Name)) {
		return setup.ErrUnsafeZone
	}
	if len(r.Addresses) == 0 || len(r.Addresses) > 100 {
		return setup.ErrInvalid
	}
	host, err := lanIPv4(ctx, env)
	if err != nil {
		return err
	}
	if w := relayNetworksWarning(ctx, env, r.Domain); w != nil {
		plan.Warnings = append(plan.Warnings, *w)
	}
	tunnel, err := chooseTunnel(ctx, client, r)
	if err != nil {
		return err
	}
	subdomain := ""
	if r.Domain != zone.Name {
		subdomain = r.Domain
	}
	whole := r.ReceiveMode == setup.ReceiveDomain
	var catchAll cloudflare.RoutingRule
	if whole {
		// The whole domain: only the apex has a catch-all, and only an
		// unused one (disabled or drop) is ever changed.
		if subdomain != "" {
			return setup.ErrCatchAllInUse
		}
		catchAll, err = client.CatchAll(ctx, r.ZoneID)
		if err != nil {
			return setup.ErrUnavailable
		}
		if !cloudflare.CatchAllUnused(catchAll) {
			return setup.ErrCatchAllInUse
		}
	}
	status, err := client.RoutingStatus(ctx, r.ZoneID)
	if err != nil {
		return setup.ErrUnavailable
	}
	enabled := subdomain == "" && status.Enabled
	for _, s := range status.Subdomains {
		enabled = enabled || subdomain != "" && strings.EqualFold(s.Name, subdomain) && s.Enabled
	}
	var records []cloudflare.DNSRecord
	if !enabled || subdomain != "" {
		records, err = client.ListDNSRecords(ctx, r.ZoneID)
		if err != nil {
			return setup.ErrUnavailable
		}
	}
	if enabled && subdomain != "" {
		// A subdomain stays enabled after a removal deleted its receiving
		// records: without Email Routing's MX and SPF it is enabled again,
		// which adds back what is missing. Cloudflare refuses (1046) to
		// delete the MX it manages, so a removal may leave the MX and take
		// only the SPF; the routing step then runs and its ledger
		// records the SPF it adds.
		mx, spf := false, false
		for _, record := range records {
			if !strings.EqualFold(strings.TrimSuffix(record.Name, "."), subdomain) || !cloudflare.RoutingRecord(record) {
				continue
			}
			mx = mx || record.Type == "MX"
			spf = spf || record.Type == "TXT"
		}
		enabled = mx && spf
	}
	if !enabled {
		for _, record := range records {
			name := strings.TrimSuffix(record.Name, ".")
			// Only MX/SPF that are not Email Routing's own conflict: a
			// rollback keeps Routing's records, and a new run reuses them.
			if strings.EqualFold(name, r.Domain) && (record.Type == "MX" || record.Type == "TXT" && strings.HasPrefix(strings.ToLower(strings.Trim(record.Content, `"`)), "v=spf1")) && !cloudflare.RoutingRecord(record) {
				return setup.ErrRoutingConflict
			}
		}
	}
	rules, err := client.ListRoutingRules(ctx, r.ZoneID)
	if err != nil {
		return setup.ErrUnavailable
	}
	services, err := client.ListVPCServices(ctx, r.AccountID)
	if err != nil {
		return setup.ErrUnavailable
	}
	// A leftover rule may be taken over only when it cannot belong to a live
	// setup of another NAS: its owner's VPC Service is gone, or points to
	// this NAS's LAN address over the same tunnel.
	adoptable := func(owner string) bool {
		for _, s := range services {
			if s.Name == "syno-home-keeper-"+owner+"-smtp" {
				return s.Host.IPv4 == host && s.Host.Network.TunnelID == tunnel.ID
			}
		}
		return true
	}
	counted := 0
	var takeover []takenRule
	for _, rule := range rules {
		literal := false
		for _, m := range rule.Matchers {
			literal = literal || m.Type == "literal"
			for _, a := range r.Addresses {
				if m.Type != "literal" || m.Field != "to" || !strings.EqualFold(m.Value, a) {
					continue
				}
				// A rule this package left (another owner's Worker) is
				// taken over; any other rule on the address is a conflict.
				owner, ok := cloudflare.LeftoverOwner(rule)
				switch {
				case !ok || owner == op.Owner:
					return setup.ErrRoutingConflict
				case !adoptable(owner):
					// Its setup's VPC Service targets another address or
					// another tunnel: it may still carry another NAS's
					// mail. Never taken over; the administrator removes it.
					return setup.ErrRoutingLeftover
				case !rule.Enabled:
					// Taken over, it would stay disabled (its state is
					// kept) and the address would receive nothing; turning
					// it on would undo an administrator's choice.
					return setup.ErrRoutingLeftoverDisabled
				}
				takeover = append(takeover, takenRule{ID: rule.ID, Address: a, Owner: owner})
			}
		}
		if literal {
			counted++
		}
	}
	if whole && len(takeover) > 0 {
		// A leftover rule of this package on a mailbox would win over the
		// catch-all; the per-address mode takes it over instead.
		return setup.ErrRoutingLeftover
	}
	if !whole && counted+len(r.Addresses)-len(takeover) > maxRoutingRules {
		return setup.ErrRulesLimit
	}
	if _, found, err := client.FindVPCService(ctx, r.AccountID); err != nil {
		return setup.ErrUnavailable
	} else if found {
		return setup.ErrUnsafeInboundExists
	}
	if found, err := client.FindWorker(ctx, r.AccountID); err != nil {
		return setup.ErrUnavailable
	} else if found {
		return setup.ErrUnsafeInboundExists
	}
	add := func(id, target, before, after string, in inboundOp) error {
		in.Mode = r.ReceiveMode
		in.Subdomain, in.TunnelID, in.TunnelName, in.Host, in.Addresses = subdomain, tunnel.ID, tunnel.Name, host, append([]string{}, r.Addresses...)
		sealed := op
		sealed.Inbound = &in
		ref := "secret:mail.wiring.cloudflare." + fingerprint([]string{r.SessionID, id})
		raw, _ := json.Marshal(sealed)
		if err := env.Secrets.Put(ctx, ref, string(raw)); err != nil {
			return setup.ErrUnavailable
		}
		plan.Changes = append(plan.Changes, core.Change{ID: id, Target: target, ActionKey: "mail.setup.change." + id,
			Params: map[string]string{"domain": r.Domain, "operationRef": ref, "inbound": in.Step}, Before: before, After: after})
		return nil
	}
	if !enabled {
		if err := add("inbound.routing", "cloudflare.routing", "disabled", "enabled: "+r.Domain, inboundOp{Step: "routing"}); err != nil {
			return err
		}
	}
	if err := add("inbound.vpc", "cloudflare.vpc", "missing", client.VPCServiceName()+" → "+host+":25 via "+tunnel.Name, inboundOp{Step: "vpc"}); err != nil {
		return err
	}
	if err := add("inbound.worker", "cloudflare.worker", "missing", client.WorkerName(), inboundOp{Step: "worker"}); err != nil {
		return err
	}
	if whole {
		// Before: nothing receives the domain's other addresses (the unused
		// catch-all, kept whole in the snapshot); the preview shows "none".
		snapshot := catchAll
		return add("inbound.catchall", "cloudflare.routing", "", "*@"+r.Domain+" → "+client.WorkerName(),
			inboundOp{Step: "catchall", CatchAllBefore: &snapshot})
	}
	rulesAfter := strings.Join(r.Addresses, ", ") + " → " + client.WorkerName()
	if len(takeover) > 0 {
		taken := []string{}
		for _, t := range takeover {
			taken = append(taken, t.Address)
		}
		rulesAfter += " (takes over a leftover rule of this package: " + strings.Join(taken, ", ") + ")"
	}
	return add("inbound.rules", "cloudflare.routing", "missing", rulesAfter, inboundOp{Step: "rules", Takeover: takeover})
}

func (c *cloudflareAdapter) inboundSnapshot(ctx context.Context, client *cloudflare.Client, op cloudOperation, change core.Change) (json.RawMessage, error) {
	r := op.Request
	switch op.Inbound.Step {
	case "routing":
	case "vpc":
		if _, found, err := client.FindVPCService(ctx, r.AccountID); err != nil {
			return nil, setup.ErrUnavailable
		} else if found {
			return nil, setup.ErrStale
		}
	case "worker":
		if found, err := client.FindWorker(ctx, r.AccountID); err != nil {
			return nil, setup.ErrUnavailable
		} else if found {
			return nil, setup.ErrStale
		}
	case "rules":
		if owned, err := client.OwnedRoutingRules(ctx, r.ZoneID); err != nil {
			return nil, setup.ErrUnavailable
		} else if len(owned) > 0 {
			return nil, setup.ErrStale
		}
	case "catchall":
		current, err := client.CatchAll(ctx, r.ZoneID)
		if err != nil {
			return nil, setup.ErrUnavailable
		}
		if op.Inbound.CatchAllBefore == nil || !client.CatchAllOurs(current) && !cloudflare.SameCatchAll(current, *op.Inbound.CatchAllBefore) {
			return nil, setup.ErrStale
		}
	default:
		return nil, setup.ErrUnsafeRecord
	}
	return json.Marshal(map[string]string{"operationRef": change.Params["operationRef"], "before": change.Before})
}

// stepPermission is the permission code a step's write needs, for a clear
// Cloudflare refusal at apply.
var stepPermission = map[string]string{"routing": setup.PermZoneSettingsEdit, "vpc": setup.PermVPCAdmin,
	"worker": setup.PermWorkersEdit, "rules": setup.PermRoutingRulesEdit, "catchall": setup.PermRoutingRulesEdit}

// permissionCodes maps the client's API permission names to the sign-in
// codes (mail.setup.cloudflare.permission.<code>).
var permissionCodes = map[string]string{
	cloudflare.PermissionSettingsRead: setup.PermZoneSettingsEdit, cloudflare.PermissionSettingsWrite: setup.PermZoneSettingsEdit,
	cloudflare.PermissionRoutingRead: setup.PermRoutingRulesEdit, cloudflare.PermissionRoutingWrite: setup.PermRoutingRulesEdit,
	cloudflare.PermissionWorkersRead: setup.PermWorkersEdit, cloudflare.PermissionWorkersWrite: setup.PermWorkersEdit,
	cloudflare.PermissionVPCRead: setup.PermVPCAdmin, cloudflare.PermissionVPCWrite: setup.PermVPCAdmin,
	cloudflare.PermissionTunnelRead: setup.PermTunnelRead,
	cloudflare.PermissionZoneRead:   setup.PermZoneRead, cloudflare.PermissionDNSRead: setup.PermDNSEdit, cloudflare.PermissionDNSWrite: setup.PermDNSEdit,
}

// applyError maps a Cloudflare failure of one step: a documented
// authorization refusal names the permission of the refused call (else the
// step's own); anything else, a 403 with another code included, is
// unavailable, never "missing".
func applyError(step string, err error) error {
	if !cloudflare.PermissionRefused(err) {
		return setup.ErrUnavailable
	}
	var e *cloudflare.Error
	if errors.As(err, &e) {
		for _, name := range e.RequiredPermissions {
			if code := permissionCodes[name]; code != "" {
				return setup.PermissionRefused{Code: code}
			}
		}
	}
	return setup.PermissionRefused{Code: stepPermission[step]}
}

// inboundApply reconciles before writing, so a lost reply is never sent twice.
func (c *cloudflareAdapter) inboundApply(ctx context.Context, env core.Env, client *cloudflare.Client, op cloudOperation) error {
	r, in := op.Request, op.Inbound
	if in.Step == "vpc" || in.Step == "worker" {
		// The SMTP target was sealed at preview. Re-read it at apply (and on
		// a resumed apply): a NAS whose address changed needs a new preview.
		host, err := lanIPv4(ctx, env)
		if err != nil {
			return err
		}
		if host != in.Host {
			return setup.ErrStale
		}
	}
	switch in.Step {
	case "routing":
		if in.Subdomain != "" {
			// Records, by ID, the receiving DNS Cloudflare adds (removal
			// deletes exactly those).
			if err := enableSubdomainRouting(ctx, env, client, op); err != nil {
				return err
			}
			break
		}
		// EnableRouting itself returns without writing when already enabled.
		if _, err := client.EnableRouting(ctx, r.ZoneID, in.Subdomain); err != nil {
			if cloudflare.IsKind(err, cloudflare.ErrConflict) {
				return setup.ErrStale
			}
			return applyError(in.Step, err)
		}
	case "vpc":
		service, found, err := client.FindVPCService(ctx, r.AccountID)
		if err != nil {
			return applyError(in.Step, err)
		}
		if found {
			if service.Host.IPv4 != in.Host || service.Host.Network.TunnelID != in.TunnelID {
				return setup.ErrStale
			}
			break
		}
		if _, err := client.CreateVPCService(ctx, r.AccountID, in.TunnelID, in.Host); err != nil {
			if cloudflare.IsKind(err, cloudflare.ErrConflict) || cloudflare.IsKind(err, cloudflare.ErrNotFound) {
				return setup.ErrStale // the tunnel is gone or unhealthy now
			}
			return applyError(in.Step, err)
		}
	case "worker":
		service, found, err := client.FindVPCService(ctx, r.AccountID)
		if err != nil || !found {
			return setup.ErrUnavailable
		}
		if service.Host.IPv4 != in.Host {
			return setup.ErrStale
		}
		if _, err := client.UploadWorker(ctx, r.AccountID, cloudflare.WorkerConfig{ServiceID: service.ServiceID,
			EHLODomain: r.Domain, Domain: r.Domain, MaxBytes: inboundMaxBytes}); err != nil {
			return applyError(in.Step, err)
		}
	case "rules":
		// Take over an earlier setup's rules first (re-read, exact shape
		// only), then one zone read and one rule list for the whole step:
		// owned rules already there are kept (a lost reply), others created.
		for _, t := range in.Takeover {
			if err := client.TakeOverRoutingRule(ctx, r.ZoneID, t.ID, t.Address, t.Owner); err != nil {
				if cloudflare.IsKind(err, cloudflare.ErrOwnership) || cloudflare.IsKind(err, cloudflare.ErrNotFound) {
					return setup.ErrStale
				}
				return applyError(in.Step, err)
			}
		}
		if err := client.EnsureRoutingRules(ctx, r.ZoneID, in.Addresses, client.WorkerName()); err != nil {
			if cloudflare.IsKind(err, cloudflare.ErrConflict) || cloudflare.IsKind(err, cloudflare.ErrOwnership) {
				return setup.ErrStale
			}
			return applyError(in.Step, err)
		}
	case "catchall":
		if in.CatchAllBefore == nil {
			return setup.ErrUnsafeRecord
		}
		if err := client.SetCatchAll(ctx, r.ZoneID, *in.CatchAllBefore); err != nil {
			if cloudflare.IsKind(err, cloudflare.ErrOwnership) {
				return setup.ErrStale // somebody changed the catch-all since the plan
			}
			return applyError(in.Step, err)
		}
	default:
		return setup.ErrUnsafeRecord
	}
	return env.KV.Put(ctx, "mail.wiring", "inbound."+r.Domain, op)
}

// inboundRollback removes only this owner's resources. Email Routing stays
// enabled with its locked MX/SPF (D5): no change, said in the preview.
func (c *cloudflareAdapter) inboundRollback(ctx context.Context, env core.Env, client *cloudflare.Client, op cloudOperation) error {
	r := op.Request
	// The setup record of the receiving step is cleared once its step is
	// undone, so the Overview never lists a setup that is gone.
	clear := func() error {
		var stored cloudOperation
		if env.KV == nil {
			return nil
		}
		if found, err := env.KV.Get(ctx, "mail.wiring", "inbound."+r.Domain, &stored); err != nil {
			return setup.ErrUnavailable
		} else if found && stored.Owner == op.Owner {
			return env.KV.Put(ctx, "mail.wiring", "inbound."+r.Domain, cloudOperation{})
		}
		return nil
	}
	switch op.Inbound.Step {
	case "routing":
		return nil
	case "vpc":
		service, found, err := client.FindVPCService(ctx, r.AccountID)
		if err != nil {
			return undoError(err, setup.PermVPCAdmin)
		}
		if found {
			if err := client.DeleteVPCService(ctx, r.AccountID, service.ServiceID); err != nil {
				return undoError(err, setup.PermVPCAdmin)
			}
		}
	case "worker":
		if err := client.DeleteWorker(ctx, r.AccountID); err != nil {
			return undoError(err, setup.PermWorkersEdit)
		}
	case "rules":
		owned, err := client.OwnedRoutingRules(ctx, r.ZoneID)
		if err != nil {
			return undoError(err, setup.PermRoutingRulesEdit)
		}
		taken := map[string]takenRule{}
		for _, t := range op.Inbound.Takeover {
			taken[t.ID] = t
		}
		for _, rule := range owned {
			if t, ok := taken[rule.ID]; ok {
				// Given back to the earlier setup, as it was.
				if err := client.ReturnRoutingRule(ctx, r.ZoneID, t.ID, t.Address, t.Owner); err != nil {
					return undoError(err, setup.PermRoutingRulesEdit)
				}
				continue
			}
			if err := client.DeleteRoutingRule(ctx, r.ZoneID, rule.ID); err != nil {
				return undoError(err, setup.PermRoutingRulesEdit)
			}
		}
		return clear()
	case "catchall":
		// Back to the snapshot, only while the catch-all is still ours; one
		// somebody changed since is theirs now and left as it is.
		if op.Inbound.CatchAllBefore == nil {
			return setup.ErrUnsafeRecord
		}
		if _, err := client.RestoreCatchAll(ctx, r.ZoneID, *op.Inbound.CatchAllBefore); err != nil {
			return undoError(err, setup.PermRoutingRulesEdit)
		}
		return clear()
	default:
		return setup.ErrUnsafeRecord
	}
	return nil
}

// ---------- Verification ----------

// InboundCheckCode is the code the administrator puts in the check mail's
// subject when the assistant cannot send one itself. It is stable per flow.
func InboundCheckCode(session string) string {
	return "MPSA-" + strings.ToUpper(fingerprint([]string{session, "inbound.check"})[:8])
}

// transactionItem is the part of a MailPlus TransactionLog entry used here.
// ori_rcpt holds the full recipient address (rcpt holds local usernames);
// src_ip is the SMTP client MailPlus saw (the VPC target itself
// when cloudflared runs on the NAS host network).
type transactionItem struct {
	MsgID     string   `json:"msgid"`
	Subject   string   `json:"subject"`
	OriRcpt   []string `json:"ori_rcpt"`
	SrcIP     string   `json:"src_ip"`
	Status    string   `json:"status"`
	Timestamp int64    `json:"timestamp"`
}

// Transaction log paging: newest first (verified on a test NAS), 50 a page,
// read back to since. More than maxLogPages pages newer than since leaves
// the result unknown, never "not arrived".
const (
	logPage     = 50
	maxLogPages = 10
)

// arrived reads MailPlus's transaction log (SYNO.MailPlusServer.Audit.
// TransactionLog list v1, mail-read) for a completed delivery at or after
// since, matched by Message-ID or by the check code in the subject, that was
// addressed to address (ori_rcpt, case-insensitive) and came from host (the
// VPC Service target). A missing or different recipient or source is no
// evidence. A log in migration is unknown, never "not arrived".
func arrived(ctx context.Context, env core.Env, since int64, msgID, code, address, host string) (bool, error) {
	want := strings.Trim(msgID, "<>")
	for page := 0; page < maxLogPages; page++ {
		var out struct {
			Migrating bool              `json:"is_migrating"`
			Total     int               `json:"total"`
			Items     []transactionItem `json:"items"`
		}
		if err := env.DSM.Call(ctx, "SYNO.MailPlusServer.Audit.TransactionLog", "list", 1,
			map[string]any{"action": "enum", "offset": page * logPage, "limit": logPage}, &out); err != nil {
			return false, err
		}
		if out.Migrating {
			return false, setup.ErrUnavailable
		}
		older := false
		for _, item := range out.Items {
			if item.Timestamp < since {
				older = true
				continue
			}
			if item.Status != "complete" || item.SrcIP == "" || item.SrcIP != host {
				continue
			}
			addressed := false
			for _, r := range item.OriRcpt {
				addressed = addressed || strings.EqualFold(strings.Trim(r, "<> "), address)
			}
			if !addressed {
				continue
			}
			if want != "" && strings.Trim(item.MsgID, "<>") == want || code != "" && strings.Contains(item.Subject, code) {
				return true, nil
			}
		}
		if older || len(out.Items) < logPage || (page+1)*logPage >= out.Total {
			return false, nil
		}
	}
	return false, setup.ErrUnavailable
}

// relayNetworksWarning reads MailPlus's SMTP relay client networks
// (SYNO.MailPlusServer.SMTP.RelayControl get v1, list_type network,
// mail-read; verified read-only on a test NAS: {client_list: [], total: 0}).
// The entries' shape was not observed, so only their count is judged: any
// configured network is a warning (Postfix may relay for it; the inbound path
// relies on the Worker's exact recipients, not on Postfix). A failed read is
// stated as unknown.
func relayNetworksWarning(ctx context.Context, env core.Env, domain string) *core.Fact {
	if env.DSM == nil {
		return &core.Fact{LabelKey: "mail.setup.inbound.relayNetworksUnknown", Value: domain, Status: core.SeverityWarning}
	}
	var out struct {
		List  []json.RawMessage `json:"client_list"`
		Total *int              `json:"total"`
	}
	if err := env.DSM.Call(ctx, "SYNO.MailPlusServer.SMTP.RelayControl", "get", 1, map[string]any{"list_type": "network"}, &out); err != nil || out.Total == nil {
		return &core.Fact{LabelKey: "mail.setup.inbound.relayNetworksUnknown", Value: domain, Status: core.SeverityWarning}
	}
	if *out.Total == 0 && len(out.List) == 0 {
		return nil
	}
	n := max(*out.Total, len(out.List))
	// The value names the number of configured networks ({count}).
	return &core.Fact{LabelKey: "mail.setup.inbound.relayNetworks", Value: "mail.setup.inbound.relayNetworksCount",
		Params: map[string]string{"count": strconv.Itoa(n)}, Status: core.SeverityWarning}
}

type inboundCheck struct {
	Since int64  `json:"since"`
	MsgID string `json:"msgId,omitempty"`
	Sent  bool   `json:"sent"`
}

// verifyInbound reads back every inbound resource and looks for delivery
// evidence. Without a completed delivery in MailPlus's log it is unverified.
func (c *cloudflareAdapter) verifyInbound(ctx context.Context, env core.Env, request setup.PlanRequest, changes []core.Change, pollFor time.Duration) (bool, bool, []core.Finding) {
	finding := func(sev core.Severity, key string, params map[string]string) core.Finding {
		return core.Finding{ID: "mail.setup.inbound", Module: "mail", Check: "mail.setup", Severity: sev,
			TitleKey: key, WhyKey: key + "Body", Params: params}
	}
	var rules *core.Change
	for i := range changes {
		if changes[i].ID == "inbound.rules" || changes[i].ID == "inbound.catchall" {
			rules = &changes[i]
		}
	}
	if rules == nil || env.KV == nil || env.DSM == nil {
		return false, false, []core.Finding{finding(core.SeverityWarning, "mail.setup.inbound.readbackFailed", nil)}
	}
	op, err := cloudOp(ctx, env, *rules)
	if err != nil || op.Inbound == nil {
		return false, false, []core.Finding{finding(core.SeverityWarning, "mail.setup.inbound.readbackFailed", nil)}
	}
	client, err := c.client(ctx, env, op)
	if err != nil {
		return false, false, []core.Finding{finding(core.SeverityWarning, "mail.setup.inbound.readbackFailed", nil)}
	}
	in, r := op.Inbound, op.Request
	readback := func() bool {
		status, err := client.RoutingStatus(ctx, r.ZoneID)
		if err != nil {
			return false
		}
		enabled := in.Subdomain == "" && status.Enabled
		for _, s := range status.Subdomains {
			enabled = enabled || in.Subdomain != "" && strings.EqualFold(s.Name, in.Subdomain) && s.Enabled
		}
		service, found, err := client.FindVPCService(ctx, r.AccountID)
		if !enabled || err != nil || !found || service.Host.IPv4 != in.Host || service.Host.Network.TunnelID != in.TunnelID {
			return false
		}
		tunnels, err := client.ListTunnels(ctx, r.AccountID)
		healthy := false
		for _, t := range tunnels {
			healthy = healthy || t.ID == in.TunnelID && t.Status == "healthy"
		}
		if err != nil || !healthy {
			return false
		}
		if found, err := client.FindWorker(ctx, r.AccountID); err != nil || !found {
			return false
		}
		if in.Step == "catchall" {
			current, err := client.CatchAll(ctx, r.ZoneID)
			return err == nil && client.CatchAllOurs(current)
		}
		owned, err := client.OwnedRoutingRules(ctx, r.ZoneID)
		if err != nil {
			return false
		}
		live := map[string]bool{}
		for _, rule := range owned {
			if rule.Enabled {
				live[strings.ToLower(rule.Matchers[0].Value)] = true
			}
		}
		for _, a := range in.Addresses {
			if !live[strings.ToLower(a)] {
				return false
			}
		}
		return true
	}()
	if !readback {
		return false, false, []core.Finding{finding(core.SeverityWarning, "mail.setup.inbound.readbackFailed", nil)}
	}
	now := time.Now
	if env.Now != nil {
		now = env.Now
	}
	var check inboundCheck
	key := "inbound.check." + r.SessionID
	if _, err := env.KV.Get(ctx, "mail.wiring", key, &check); err != nil {
		return true, false, []core.Finding{finding(core.SeverityWarning, "mail.setup.inbound.logUnknown", nil)}
	}
	if check.Since == 0 {
		check.Since = now().Unix()
	}
	address, code := in.Addresses[0], InboundCheckCode(r.SessionID)
	// D4: with Email Sending set up by this flow, send the check mail once.
	if r.Decision.Send == setup.RelaySend && !check.Sent {
		check.Sent = true
		if err := env.KV.Put(ctx, "mail.wiring", key, check); err != nil {
			return true, false, []core.Finding{finding(core.SeverityWarning, "mail.setup.inbound.logUnknown", nil)}
		}
		id, err := client.SendMessage(ctx, r.AccountID, address, address, "MailPlus Setup Assistant inbound check "+code,
			"This message checks that mail sent to "+address+" arrives in MailPlus. You can delete it.")
		if err == nil {
			check.MsgID = id
		}
	}
	if err := env.KV.Put(ctx, "mail.wiring", key, check); err != nil {
		return true, false, []core.Finding{finding(core.SeverityWarning, "mail.setup.inbound.logUnknown", nil)}
	}
	wait := time.Duration(0)
	if check.MsgID != "" {
		wait = pollFor
	}
	deadline := now().Add(wait)
	for {
		ok, err := arrived(ctx, env, check.Since, check.MsgID, code, address, in.Host)
		if err != nil {
			return true, false, []core.Finding{finding(core.SeverityWarning, "mail.setup.inbound.logUnknown", nil)}
		}
		if ok {
			return true, true, []core.Finding{finding(core.SeverityOK, "mail.setup.inbound.delivered", map[string]string{"address": address})}
		}
		if !now().Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return true, false, []core.Finding{finding(core.SeverityWarning, "mail.setup.inbound.logUnknown", nil)}
		case <-time.After(5 * time.Second):
		}
	}
	return true, false, []core.Finding{finding(core.SeverityWarning, "mail.setup.inbound.checkMail", map[string]string{"address": address, "code": code})}
}
