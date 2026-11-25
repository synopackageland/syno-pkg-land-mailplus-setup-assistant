// Shapes of the worker replies (backend/internal/{core,mail/setup,mail/diagnose,worker}).

export type Severity = 'ok' | 'info' | 'warning' | 'critical'

export interface Finding {
 id: string
 module: string
 check: string
 severity: Severity
 titleKey: string
 whyKey?: string
 fixKey?: string
 params?: Record<string, string>
 evidence?: unknown
 /** mail.setup or mail.diagnose: the wizard that addresses it. */
 fixWizard?: string
}

export type FactGroup = 'mailplus' | 'network' | 'dns' | 'cloudflare'
/** problem and unknown need attention; ok and notChecked (not checked by this version) fold away;
 * planned (the decided plan creates it) and optional (not needed, recommended) need no action. */
export type FactState = 'ok' | 'problem' | 'unknown' | 'notChecked' | 'planned' | 'optional'
/** group, state, unrelated and noteKey (why a planned or optional fact needs no action) come with the setup detection's facts (setup/factview.go). unrelated: not needed by the chosen route and intent. */
export interface Fact {labelKey: string; value: string; status?: Severity; params?: Record<string, string>; group?: FactGroup; state?: FactState; unrelated?: boolean; noteKey?: string}

export interface Field {
 name: string
 kind: 'text' | 'secret' | 'email' | 'domain' | 'number' | 'select'
 labelKey: string
 hintKey?: string
 required?: boolean
 default?: string
}

export interface Change {
 id: string
 target: string
 actionKey: string
 params?: Record<string, string>
 before?: string
 after?: string
}

// ---------- Setup flow (mail.setup.*) ----------

export type Intent = 'send' | 'receive' | 'both'
export type Phase = '' | 'applying' | 'verifying' | 'decision' | 'rollingBack' | 'rolledBack' | 'kept' | 'failed' | 'interrupted'

export interface FlowView {
 id: string
 intent?: Intent
 /** Where the domain came from; absent for a typed domain. */
 source?: Source
 domain?: string
 phase: Phase
 done: number
 total: number
 changes: Change[]
 findings: Finding[]
 verified: boolean
 outcome?: 'ok' | 'failed' | 'rolledBack'
 error?: string
 /** The change whose write failed, when the worker knows it. */
 failedStep?: string
 resume: boolean
}

export type BranchKind = 'configureMailPlus' | 'blocked' | 'diagnose' | 'already' | 'unavailable' | 'configure'

export interface BranchView {
 kind: BranchKind
 reason?: string
 titleKey: string
 bodyKey?: string
 params?: Record<string, string>
 records?: Change[]
 outcome?: 'ok' | 'failed'
 needsAccount: boolean
 fields?: Field[]
 warnings?: Fact[]
 /** Each decided direction's path and why (catalog keys mail.setup.why.*). */
 paths?: PathView[]
 /** The intent includes receiving but the domain has no enabled mailbox: this branch covers sending only, receiving waits. */
 receivePending?: boolean
 /** MailPlus Server is set up but lacks this mail domain: the plan creates it (mailplus.domain). */
 createsDomain?: boolean
 /** Receiving through Cloudflare: the domain's mailboxes read from MailPlus Server (shown, never asked for). */
 mailboxes?: string[]
}

export type PathBranch = 'direct-send' | 'cloudflare-relay' | 'direct-receive' | 'cloudflare-routing'
export interface PathView {direction: 'send' | 'receive'; branch: PathBranch; titleKey: string; why: string[]}

/** The route step's choice: Cloudflare receives and sends (recommended), or the confirmed own IP (direct). Only 'direct' allows a direct path. */
export type Route = 'cloudflare' | 'direct'
/** The start step's choice: where the domain comes from (typed, or the Cloudflare sign-in's zones). It decides no mail path. */
export type Source = 'own' | 'cloudflare'
/** route is absent until the route step (the first detection runs right after the domain). */
export interface Answers {source?: Source; route?: Route}

/** The Cloudflare sign-in (backend/internal/mail/setup/cloud.go). */
export interface CloudAccount {id: string; name: string}
/** status and type are Cloudflare's (type: full, partial, secondary). */
export interface CloudZone {id: string; name: string; status: string; type?: string}
export interface CloudView {
 accounts: CloudAccount[]
 /** The chosen account; with exactly one account the worker chooses it. */
 accountId?: string
 zones: CloudZone[]
 zoneId?: string
 /** Own-domain route: the zone that holds the flow's domain. */
 match?: string
 /** Permission codes Cloudflare refused (mail.setup.cloudflare.permission.<code>). */
 missing: string[]
 /** The token works but has no zone yet and Cloudflare names no account: register, then check again (zones with accountId ''). */
 accountUnknown?: boolean
 /** Once a zone is chosen: MailPlus Server's domains that are the zone or under it (the mail domain is one of them, never the apex by default). */
 mailDomains: string[]
 /** '' (no zone chosen), 'reading' (in the background; poll with {id, poll: true}), 'read', or 'unknown' (check again). */
 mailDomainsState?: '' | 'reading' | 'read' | 'unknown'
 /** probe_timeout (a call sent without an answer in time), probe_not_started (no executor slot), or another DSM cause. */
 mailDomainsCause?: string
 /** The cause as a catalog key (mail.setup.cause.*) with its params. */
 mailDomainsCauseKey?: string
 mailDomainsCauseParams?: Record<string, string>
}

export interface DetectView {done: boolean; facts?: Fact[]; branch?: BranchView}

export interface Permission {scope: string; resource: string; name: string}

/** pending: the worker still prepares the plan in the background; poll with {id, poll: true}. */
/** A healthy Cloudflare Tunnel that could carry inbound mail. connect: made by
 * Syno Connect; match: every connection comes from the NAS's public IPv4 (a
 * hint, not proof: delivery verification is the proof). */
export interface TunnelOption {id: string; name: string; connect: boolean; match: boolean}
/** tunnels: no single tunnel is certain; nothing was planned, pick one and preview again. */
export interface PreviewView {changes: Change[]; permissions: Fact[]; warnings: Fact[]; pending?: boolean; tunnels?: TunnelOption[]; receiveMode?: ReceiveMode}

/** Receiving through Cloudflare: the whole domain (any address @domain), or one rule per MailPlus mailbox. */
export type ReceiveMode = 'domain' | 'addresses'
/** Whether the whole-domain mode can be offered; domainReason is a catalog key (mail.setup.receive.*) when not. */
export interface ReceiveModes {domain: boolean; domainReason?: string}

// ---------- Kept Cloudflare setups (mail.inbound.*) ----------

/** The last mailbox sync of a kept setup (worker memory; a restart forgets it). */
export interface SyncRun {
 state: 'running' | 'done' | 'failed'
 added: number
 removed: number
 /** Mailboxes that still cannot receive (another rule, the zone's limit, a failed write). */
 pending: number
 addresses?: string[]
 /** failed: why nothing could be decided (mail.inbound.cause.*). */
 causeKey?: string
 at?: number
}
/** How many mailboxes receive through a per-address setup's rules after its last completed sync (or the setup). */
export interface Synced {
 mailboxes: number
 added?: number
 removed?: number
 at?: number
}
/** One DNS record a removal left because Cloudflare locks it. */
export interface LockedRecord {
 type: string
 name: string
 content: string
}
/** The automatic mailbox sync of a per-address setup (worker memory). */
export interface AutoSync {
 /** ok; failing (tried again later); stopped (MailPlus answered in an unexpected shape: waits for a manual sync). */
 state: 'ok' | 'failing' | 'stopped'
 causeKey?: string
 /** MailPlus mailboxes without this setup's rule. */
 unsynced?: number
 /** Rules a manual sync would delete that the automatic sync left. */
 held?: number
 checkedAt?: number
}

export interface KeptView {
 id: string
 domain: string
 intent?: Intent
 /** Receiving through Cloudflare, and how; absent when the setup does not receive through Cloudflare. */
 receive?: ReceiveMode
 /** A sealed Cloudflare token is kept for this setup. */
 token: boolean
 /** Cloudflare refused the kept token (deleted or rolled in its dashboard): sending and sync are paused until a new one is entered. */
 tokenInvalid?: boolean
 /** This setup sends through the relay (its SMTP login is the kept token). */
 relay?: boolean
 last?: SyncRun
 /** Per-address setups: the stored count of the last completed sync (or the setup), with what that sync added and removed. Survives a worker restart, unlike last. */
 synced?: Synced
 /** The automatic sync's state (per-address setups, once the worker checked). */
 auto?: AutoSync
 /** What removing the setup takes away, as catalog keys (ui.remove.item.*). */
 removes?: string[]
 /** This setup enabled Email Routing on the zone: removal may turn it off too. */
 routingOwned?: boolean
 removal?: RemoveRun
}
/** The last removal of a kept setup (worker memory). */
export interface RemoveRun {
 state: 'running' | 'done' | 'failed'
 done: number
 total: number
 /** failed: why it stopped (mail.inbound.cause.*, mail.remove.cause.*). */
 causeKey?: string
 at?: number
 /** done: receiving records Cloudflare would not delete (it locks them for Email Routing); left in place. */
 locked?: LockedRecord[]
 /** With locked: the Cloudflare account, and the zone's name when it was read (the dashboard link). */
 accountId?: string
 zone?: string
 /** done: the MailPlus Server mail domain this setup created, kept because it has users now. */
 keptDomain?: string
}

// ---------- Diagnosis (mail.diagnose.*) ----------

export type Symptom = 'cannot-send' | 'bounce-or-spam' | 'cannot-receive' | 'phone-connect' | 'not-sure'

export interface DiagnoseRun {
 id: string
 symptom: Symptom
 done: number
 total: number
 checks: string[]
 findings: Finding[]
 complete: boolean
 /** What the result step shows (backend/internal/mail/diagnose/summary.go); set when complete. */
 summary?: DiagnoseSummary
 /** True while the worker still reads MailPlus Server or runs the next check. */
 pending?: boolean
 phase?: 'reading' | 'checking'
}

/**
 * problems: at least one problem; unclear: none, but some checks could not
 * read what they need; clear: none; unreadable: MailPlus Server could not be
 * read (the run's only finding says why).
 */
export type DiagnoseVerdict = 'problems' | 'unclear' | 'clear' | 'unreadable'
export interface DiagnoseSummary {
 verdict: DiagnoseVerdict
 /** At most three, most likely first. */
 problems: Problem[]
 /** The problems past three, folded behind "Show more". */
 more?: Problem[]
 others: OtherCheck[]
}
/** One thing to fix: mail.diag.problem.<key>.title / .body / .action. */
export interface Problem {
 key: string
 severity: Severity
 /** Affected domains, addresses or hosts. */
 targets?: string[]
 /** The button: the setup wizard (with intent), a new Cloudflare token, MailPlus Server or Package Center; none when the action text names the place. */
 action?: 'setup' | 'token' | 'mailplus' | 'packages'
 intent?: Intent
 findings: string[]
 details?: {target?: string; evidence: unknown}[]
}
/** One line under Other checks: mail.diag.other.<key> with {check, targets, count}. */
export interface OtherCheck {key: string; state: 'ok' | 'note' | 'unknown'; check?: string; targets?: string[]; count?: number}

// ---------- Relay ----------

export interface ServiceStatus {
 running: boolean
 since?: string
 counters?: Record<string, number>
 lastError?: string
 info?: Record<string, string>
}
export interface ServiceView {id: string; enabled: boolean; status: ServiceStatus}

// ---------- DSM access (dsm.authority.*) ----------

export type AuthorityProfileName = 'mail-read' | 'mail-write'
export type AuthorityState = 'granted' | 'missing' | 'needs-authorization' | 'other-administrator' | 'needs-admin-approval'

/** SDK delegate.Capability; `ready` once an administrator approved the executor policy. */
export interface AuthorityCapability {state: string; reason?: string}

/** dsmauthority.WebAPIProfile: API -> method -> versions. */
export interface WebAPIProfile {purpose: string; apis: Record<string, Record<string, number[]>>}

export interface AuthorityProfile {
 name: AuthorityProfileName
 profile: WebAPIProfile
 state: AuthorityState
 configuredBy?: string
 grantId?: string
 canRevoke: boolean
}

/** SDK delegate.Grant, only the caller's grants for these profiles. */
export interface AuthorityGrant {
 delegation_id: string
 subject: {username: string; uid: string | number}
 expires_at: string
 lifetime?: string
 scope?: string
 revoked?: boolean
}

export interface AuthorityStatus {capability: AuthorityCapability; profiles: AuthorityProfile[]; grants: AuthorityGrant[]}

// ---------- Errors (core.RPCError, preserved by the CGI) ----------

export interface AssistantError {
 code: string
 message?: string
 /** authority_required carries the exact missing profile; mail refusals carry their fixed reason key. */
 details?: {profile?: AuthorityProfileName; reason?: string} & Record<string, string | undefined>
}

/** The MailPlus Server precondition (mail.mailplus.status); `checking` while the worker reads. */
export type MailPlusState = 'notInstalled' | 'stopped' | 'running' | 'unknown' | 'checking'
export interface MailPlusStatus {
 state: MailPlusState
 version?: string
 /** DSM marks the installation broken (state stopped). */
 broken?: boolean
 /** unknown: a fixed cause and its catalog key. */
 cause?: string
 causeKey?: string
 causeParams?: Record<string, string>
 /** running only: MailPlus Server finished its own first-run setup; absent when unknown. */
 setUp?: boolean
}

// ---------- Operation table: [params, result] ----------

export interface Operations {
 'app.status': [Record<string, never>, {package: string; version: string; user: string; admin: boolean}]
 'dsm.authority.status': [Record<string, never>, AuthorityStatus]
 'dsm.authority.grant': [{profile: AuthorityProfileName; confirmed: true}, {granted: boolean; profile: string; grantId: string}]
 'dsm.authority.revoke': [{profile: AuthorityProfileName; id: string}, {revoked: boolean}]
 'mail.relay.status': [Record<string, never>, ServiceView]
 'mail.relay.set': [{enabled: boolean}, Record<string, never>]
 'mail.mailplus.status': [Record<string, never>, MailPlusStatus]
 'mail.setup.start': [Record<string, never>, FlowView]
 'mail.setup.cloudflare': [{id: string; token: string}, CloudView]
 'mail.setup.zones': [{id: string; accountId: string; zoneId?: string} | {id: string; poll: true}, CloudView]
 'mail.setup.detect': [{id: string; intent: Intent; domain: string; answers: Answers; refresh?: boolean}, DetectView]
 'mail.setup.permissions': [{id: string; accountId: string; zoneId: string}, {permissions: Permission[]}]
 'mail.setup.preview': [{id: string; addresses?: string; members?: string; tunnel?: string; receive?: ReceiveMode; poll?: boolean}, PreviewView]
 'mail.setup.receivemodes': [{id: string}, ReceiveModes]
 'mail.setup.apply': [{id: string}, FlowView]
 'mail.setup.status': [{id: string}, FlowView]
 'mail.setup.decide': [{id: string; choice: 'keep' | 'rollback' | 'verify'}, FlowView]
 'mail.inbound.status': [Record<string, never>, {setups: KeptView[]}]
 'mail.inbound.sync': [{id: string; poll?: boolean}, KeptView]
 'mail.inbound.token': [{id: string; token?: string}, KeptView]
 'mail.cloudflare.remove': [{id: string; routing?: boolean; poll?: boolean}, KeptView]
 'mail.diagnose.symptoms': [Record<string, never>, {symptoms: {symptom: Symptom; checks: number}[]}]
 'mail.diagnose.start': [{symptom: Symptom}, DiagnoseRun]
 'mail.diagnose.next': [{id: string}, DiagnoseRun]
}
export type OpName = keyof Operations
