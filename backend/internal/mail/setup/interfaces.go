package setup

import (
	"context"
	"encoding/json"
	"errors"

	"SynoMailPlusSetupAssistant/internal/core"
	"SynoMailPlusSetupAssistant/internal/mail/detect"
)

// PlanRequest contains public facts and encrypted secret references only.
// Adapters resolve references with Env.Secrets; they must never serialize values.
type Mailbox struct {
	Username string `json:"username"`
	Address  string `json:"address"`
}
type PlanRequest struct {
	SessionID    string       `json:"sessionId"`
	Intent       Intent       `json:"intent"`
	Domain       string       `json:"domain"`
	Decision     Decision     `json:"decision"`
	State        detect.State `json:"state"`
	Members      []Mailbox    `json:"members,omitempty"`
	Addresses    []string     `json:"addresses,omitempty"`
	AccountID    string       `json:"accountId,omitempty"`
	ZoneID       string       `json:"zoneId,omitempty"`
	TokenRef     string       `json:"tokenRef,omitempty"`
	SMTPTokenRef string       `json:"smtpTokenRef,omitempty"`
	// Tunnel is the Cloudflare Tunnel the administrator picked for inbound
	// mail. Empty: the adapter matches one by public IP, or asks.
	Tunnel string `json:"tunnel,omitempty"`
	// ReceiveMode (receiving through Cloudflare): ReceiveDomain (every
	// address of the apex domain through the zone's unused catch-all) or
	// ReceiveAddresses (one exact rule per mailbox, synced by hand).
	ReceiveMode string `json:"receiveMode,omitempty"`
}

// The two ways of receiving through Cloudflare.
const (
	ReceiveDomain    = "domain"
	ReceiveAddresses = "addresses"
)

// ReceiveModes says whether the whole-domain mode can be offered: the mail
// domain must be the zone apex (Cloudflare's catch-all exists there only)
// and the zone's catch-all unused (disabled or drop). DomainReason is a
// catalog key saying why not.
type ReceiveModes struct {
	Domain       bool   `json:"domain"`
	DomainReason string `json:"domainReason,omitempty"`
}

// KeptSetup is a kept transaction handed to the Overview's record: what was
// applied (with snapshots, for a later removal) and the sealed sign-in token,
// which the record owns from then on.
type KeptSetup struct {
	FlowID    string          `json:"flowId"`
	Domain    string          `json:"domain"`
	Intent    Intent          `json:"intent"`
	AccountID string          `json:"accountId"`
	ZoneID    string          `json:"zoneId"`
	TokenRef  string          `json:"tokenRef"`
	Applied   []AppliedChange `json:"applied"`
}

// InboundSync keeps the record of kept Cloudflare setups: the whole-domain
// check before the plan, and the hand-over of a kept setup.
type InboundSync interface {
	// ReceiveModes reads the zone and its catch-all with the sign-in token.
	ReceiveModes(ctx context.Context, env core.Env, tokenRef, zoneID, domain string) (ReceiveModes, error)
	// Kept records a kept setup; on success the record owns its token.
	Kept(ctx context.Context, env core.Env, kept KeptSetup) error
}
type Permission struct {
	Scope    string `json:"scope"`    // account / zone
	Resource string `json:"resource"` // exact account or zone ID
	Name     string `json:"name"`     // exact supported API permission name
}

// Prepared must carry exact public before/after values and all prerequisites.
// No vague composite changes; changes are durable/idempotent by session+change ID.
type Prepared struct {
	Changes     []core.Change `json:"changes"`
	Permissions []Permission  `json:"permissions,omitempty"`
	// Adapters must explicitly confirm safe ownership and complete restoration,
	// including old credentials; the wizard cannot infer these from a GET.
	Restorable bool `json:"restorable"`
	// Warnings are facts the plan found that the preview must show (for
	// example MailPlus relay networks); public values only.
	Warnings []core.Fact `json:"warnings,omitempty"`
}

// Writer contracts: reconcile lost replies by change ID, refuse foreign resource
// overwrite, and compare current values before restoring snapshots. Snapshot JSON
// contains only public fields or encrypted references; no secret values.
type Writer interface {
	Snapshot(context.Context, core.Env, core.Change) (json.RawMessage, error)
	Apply(context.Context, core.Env, core.Change) error
	Rollback(context.Context, core.Env, core.Change, json.RawMessage) error
}
type CloudflareClient interface {
	Writer
	// RequiredPermissions is local inventory only, so the UI can show exact names
	// and scopes before asking for any credential
	RequiredPermissions(PlanRequest) ([]Permission, error)
	Plan(context.Context, core.Env, PlanRequest) (Prepared, error)
}
type Relay interface {
	Writer
	// Plan returns the exact loopback address, STARTTLS and AUTH references in
	// relay configuration changes; MailPlus plans against the same public plan.
	Plan(context.Context, core.Env, PlanRequest) (Prepared, error)
}
type MailPlus interface {
	Writer
	Plan(context.Context, core.Env, PlanRequest, []core.Change) (Prepared, error)
}
type Verifier interface {
	// Verify must read back exact writes and verify real delivery for the intent;
	// missing evidence returns an error or a non-OK finding, never empty success.
	Verify(context.Context, core.Env, PlanRequest, []core.Change) (Verification, error)
}
type Verification struct {
	Readback bool
	Delivery bool
	Findings []core.Finding
}

var (
	ErrUnavailable = errors.New("mail.setup.integrationUnavailable")
	ErrInvalid     = errors.New("mail.setup.invalidAnswer")
	// ErrUnsafe: the App refused to go on because going on could change
	// what it cannot prove safe. Every refusal carries a specific reason
	// (UnsafeReason, below); errors.Is(err, ErrUnsafe) holds for each.
	ErrUnsafe = errors.New("mail.setup.unsafePlan")
	ErrStale  = errors.New("mail.setup.stalePlan")
	// ErrDomainInUse: the MailPlus Server domain this App created has users
	// now; the App never deletes it then.
	ErrDomainInUse = errors.New("mail.setup.domainInUse")
	// ErrPlanChanged: the plan was prepared for answers, facts or a decision
	// the flow no longer has. It is discarded; preview again.
	ErrPlanChanged = errors.New("mail.setup.planChanged")
	// ErrUnconfirmed: a read or write did not answer in time, so the current
	// MailPlus setting is not known. Nothing is written again automatically.
	ErrUnconfirmed = errors.New("mail.setup.unconfirmed")
	// ErrNotStarted: MailPlus Server was too busy to start one step (no
	// executor slot in time); that step sent nothing. Earlier steps of the
	// flow may have changed settings: the text describes only this step.
	ErrNotStarted = errors.New("mail.setup.notStarted")
	// ErrOtherTransaction: another administrator's flow is applying,
	// verifying or rolling back; one at a time for the whole package.
	ErrOtherTransaction = errors.New("mail.setup.otherTransaction")
	// ErrTunnelRequired: the Cloudflare account has no healthy tunnel that
	// could carry inbound mail to the NAS. Nothing was written.
	ErrTunnelRequired = errors.New("mail.setup.tunnelRequired")
	// ErrLANUnknown: DSM did not name one connected private IPv4 address on
	// the default-gateway interface, so there is no safe SMTP target.
	ErrLANUnknown = errors.New("mail.setup.lanUnknown")
	// ErrRulesLimit: the zone's Email Routing rules plus the new exact
	// addresses would exceed Cloudflare's limit.
	ErrRulesLimit = errors.New("mail.setup.rulesLimit")
	// ErrRoutingConflict: the mail domain already has MX or SPF records that
	// Email Routing would have to replace.
	ErrRoutingConflict = errors.New("mail.setup.routingConflict")
	// ErrRoutingLeftover: a requested address has a rule an earlier setup of
	// this package left, but that setup's VPC Service targets another address
	// or another tunnel (it may serve another NAS). Never taken over: the
	// administrator removes it in Cloudflare.
	ErrRoutingLeftover = errors.New("mail.setup.routingLeftover")
	// ErrRoutingLeftoverDisabled: a leftover rule that could be taken over is
	// disabled. Taking it over keeps its state, so the address would receive
	// nothing; enabling it would undo an administrator's choice. Refused.
	ErrRoutingLeftoverDisabled = errors.New("mail.setup.routingLeftoverDisabled")
	// ErrSendingPlan: Cloudflare answered that the account's plan does not
	// include Email Sending (it needs Workers Paid). Refused before anything
	// is written when the sign-in check or the preview hears it.
	ErrSendingPlan = errors.New("mail.setup.sendingPlan")
	// ErrSendingExisting: the mail domain is already in Email Sending but
	// disabled or with DNS Cloudflare reports as wrong. A working one is
	// reused; a broken one is the administrator's to fix or delete.
	ErrSendingExisting = errors.New("mail.setup.sendingExisting")
	// ErrCatchAllInUse: the whole-domain mode was asked for, but the mail
	// domain is not the zone apex or the zone's catch-all is in use. The
	// catch-all is never changed.
	ErrCatchAllInUse = errors.New("mail.setup.receive.domainUnavailable")
	// ErrSyncTokenRequired: the kept setup has no usable Cloudflare token
	// (none kept, revoked, or missing a permission): paste one again.
	ErrSyncTokenRequired = errors.New("mail.inbound.tokenRequired")
)

// TunnelOption is one healthy tunnel the administrator may pick. Connect
// marks a Syno Connect tunnel; Match marks a tunnel whose every connection
// comes from the NAS's public IPv4 (a hint, never proof).
type TunnelOption struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Connect bool   `json:"connect"`
	Match   bool   `json:"match"`
}

// TunnelChoice is returned by a plan when no single tunnel is certain: the
// administrator picks one (or confirms the preselected one) and previews
// again. Delivery verification is the final proof either way.
type TunnelChoice struct{ Options []TunnelOption }

func (TunnelChoice) Error() string { return "mail.setup.tunnelChoice" }

// PermissionRefused: Cloudflare clearly refused one step for a missing
// permission (a documented authorization code). Code is a Perm* code; the
// public text is mail.setup.permissionRefused.<code>.
type PermissionRefused struct{ Code string }

func (p PermissionRefused) Error() string { return "mail.setup.permissionRefused." + p.Code }

// UnsafeReason is ErrUnsafe with its specific reason, a catalog key
// mail.setup.unsafe.<code> in plain words (never the generic
// "integration unavailable").
type UnsafeReason struct{ Code string }

func (u UnsafeReason) Error() string        { return "mail.setup.unsafe." + u.Code }
func (u UnsafeReason) Is(target error) bool { return target == ErrUnsafe }

// The reasons (docs/mail-rules.md lists where each comes from).
var (
	// ErrUnsafeZone: the Cloudflare zone is not in the chosen account, or
	// does not hold the mail domain.
	ErrUnsafeZone = UnsafeReason{"zoneMismatch"}
	// ErrUnsafeInboundExists: Cloudflare already has the receiving
	// connection or mail program under the name this setup would create.
	ErrUnsafeInboundExists = UnsafeReason{"inboundExists"}
	// ErrUnsafeSendingDNS: Cloudflare's own check of the sending DNS reports
	// something other than missing records.
	ErrUnsafeSendingDNS = UnsafeReason{"sendingDns"}
	// ErrUnsafeEgress: the NAS's public IPv4 address is not known, so no
	// SPF or A record can name it.
	ErrUnsafeEgress = UnsafeReason{"egressUnknown"}
	// ErrUnsafeDKIM: MailPlus Server's DKIM selector or public key for the
	// domain was not read.
	ErrUnsafeDKIM = UnsafeReason{"dkimUnknown"}
	// ErrUnsafeDNSExists: a DNS record with the same name and type (or a
	// CNAME) already exists; the App never replaces a record it did not add.
	ErrUnsafeDNSExists = UnsafeReason{"dnsExists"}
	// ErrUnsafeRelayInUse: the App's mail forwarding service is already on
	// or holds a token (another setup uses it).
	ErrUnsafeRelayInUse = UnsafeReason{"relayInUse"}
	// ErrUnsafeReply: MailPlus Server answered in a form this App does not
	// know, so it does not write over the setting.
	ErrUnsafeReply = UnsafeReason{"mailplusReply"}
	// ErrUnsafeRecord: the App's own saved record of a change (its journal,
	// snapshot or sealed operation) is missing or does not match.
	ErrUnsafeRecord = UnsafeReason{"savedRecord"}
	// ErrUnsafePlanCheck: the prepared changes failed the App's own checks
	// (a change outside the plan, a missing permission, a step the path
	// needs); nothing was changed.
	ErrUnsafePlanCheck = UnsafeReason{"planCheck"}
	// ErrUnsafeSecret: a saved setting or check result would have held a
	// secret, so it was discarded.
	ErrUnsafeSecret = UnsafeReason{"secret"}
)

// UnsafeCodes lists every reason code (tests check each has a message).
var UnsafeCodes = []string{"zoneMismatch", "inboundExists", "sendingDns", "egressUnknown", "dkimUnknown", "dnsExists", "relayInUse",
	"mailplusReply", "savedRecord", "planCheck", "secret"}
