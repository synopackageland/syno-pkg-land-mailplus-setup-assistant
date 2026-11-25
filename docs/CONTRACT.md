# Operations contract

All operations are administrator-only (`permission: administrators`, and the
App's `entry: admin-only`). `operations.json` is the single source;
`synopkgland ctl generate` writes the policy and registry. Every `mail.*`
route forwards to the worker with the verified caller as owner.

Errors are `{code, message, details?}`. Fixed codes: `bad_request`,
`not_found`, `conflict`, `unsafe_plan`, `unavailable`, `authority_required`
(`details.profile` = `mail-read` | `mail-write`), `admin_required`,
`request_timeout`, `app_unavailable` (worker not running). Mail refusals add
`details.reason`, a fixed catalog key such as `mail.setup.stalePlan`.

## DSM access

| Operation | Params | Result |
| --- | --- | --- |
| `dsm.authority.status` | `{}` | `{capability, profiles[], grants[]}` |
| `dsm.authority.grant` | `{profile, confirmed: true}` | `{granted, profile, grantId}` |
| `dsm.authority.revoke` | `{profile, id}` | `{revoked}` |

Profile tuples: [dsm-access.md](dsm-access.md). Build 6 adds
`SYNO.MailPlusServer.License get_user_limit v1 / get_active_user_num v1` to
`mail-read` (read-only); the policy digest changes, so an administrator
approves the App again after upgrading.

## MailPlus Server precondition (`backend/internal/mail/detect/precondition.go`)

Everything this App does needs MailPlus Server installed and running. The
precondition is decided from `SYNO.Core.Package list v2` (`mail-read`) only:
the exact `MailPlus-Server` entry, its `additional.status` and
`installed_info.is_broken` / `is_brick`. States: `notInstalled`, `stopped`
(installed but not running, or broken: `broken: true`), `running`, `unknown`
(the list could not be read; `cause`, `causeKey`, `causeParams`).

| Operation | Params | Result |
| --- | --- | --- |
| `mail.mailplus.status` | `{}` | `{state: notInstalled\|stopped\|running\|unknown\|checking, version?, broken?, cause?, causeKey?, causeParams?, setUp?}`; one package read in the background per administrator, then, when running, `SYNO.MailPlusServer.Util initial_check v2` (`setUp` = `plusserver_initialized`: MailPlus Server finished its own first-run setup; absent when that read fails; two DSM call budgets), the reply waits at most 8 s, `checking` means poll again; a missing grant or a caller who is not an administrator is that refusal |

Every flow reads it first and sends no `SYNO.MailPlusServer.*` call unless it
says running: the detection pass (setup branch `configureMailPlus`/`notInstalled`),
the zone step's domain read (`mail.setup.zones` reads the package list before
`SYNO.MailPlusServer.Domain list`; `mailDomainsCauseKey`
`mail.setup.cause.mailplusNotInstalled` / `mailplusStopped`), preview and apply
(refused from the flow's detected package state), and diagnosis (the snapshot
reads the package first; not installed or stopped is the run's first and only
finding, `mail.diag.mailplus.missing` / `.stopped`, and no other check runs).
The worker also wraps each request's DSM transport in a gate: after a package
read through it says not installed or stopped, a MailPlus Server call is refused
before it is sent, and DSM error 102 (no such API) on a MailPlus Server call
becomes `mail.setup.cause.mailplusApiMissing`. Refusals are typed: codes
`mailplus_not_installed`, `mailplus_not_running`, `mailplus_unknown`, with
`details.reason` `mail.mailplus.notInstalled` / `.stopped` / `.unknown`.

User-facing text never shows a DSM error code. Known codes map to plain causes
(102 → `mailplusApiMissing`, 105 → `dsmPermission`, 106/107/119 →
`dsmSession`); any other `dsm_<code>` is `mail.setup.cause.dsm` (the code stays
in the detection fact's `params.code` and in the worker log, not in the text). A finding never carries one: its params drop the code, and its folded evidence replaces each `dsm_<code>` with that plain cause key, which the page shows in words.

## Setup (`backend/internal/mail/setup/flow.go`)

One flow per administrator, stored in KV `mail.setup/flow.<sha256(owner)>`.

| Operation | Params | Result | Effect |
| --- | --- | --- | --- |
| `mail.setup.start` | `{}` | `FlowView` | Resumes a flow with outstanding changes (`resume: true`); else reuses the open flow (detection cleared) or creates one |
| `mail.setup.cloudflare` | `{id, token}` (1–512 characters, no whitespace) | `CloudView` = `{accounts[{id,name}], accountId?, zones[{id,name,status,type?}], zoneId?, match?, missing[], accountUnknown?}` | Only a flow still collecting answers (`conflict` otherwise, with no secret written). Verifies the token first, held in memory only: a token no Cloudflare verify endpoint answered active is never sealed and reports no missing permission. Once accepted, it is sealed under a fresh reference (`secret:mail.setup.<id>.token.<gen>`) and replaces the flow's sign-in (the old token's secret is deleted); a failure after that deletes the new secret and leaves the old sign-in untouched. Sign-in: `GET /user/tokens/verify`; passed → a user token, accounts from `GET /accounts` or (403) the zones' accounts. Refused (401/403 or Cloudflare's token codes) → maybe an account-owned token (the account token form creates one; Cloudflare documents no specific error for it on the user endpoint): accounts are discovered the same way (401/403 there only mean "nothing found this way" and prove nothing: Cloudflare answers an unknown token there with 403, code 9109) and the token is verified with `GET /accounts/{id}/tokens/verify` of each candidate (at most 20); the one that accepts it owns it. No candidate account, or every candidate refused: invalid. Only these verify endpoints decide `bad_request`, reason `mail.setup.tokenInvalid`: a malformed credential (HTTP 400 with an Authorization-format code 6003/6111/6103/9106, as Cloudflare answers a token of the wrong shape) at once, with no account probe; otherwise every refusal clear and nothing accepted it (a well-formed unknown token gets 401, code 1000). An unclear Cloudflare answer (5xx, no answer, an unexpected reply) is `unavailable`, reason `mail.setup.cloudflareUnavailable` (never `mail.setup.integrationUnavailable`, which is about this build). After a verify, a sign-in read refused with HTTP 403 (any code, 9109 included) names a missing permission; 401 or anything else is `unavailable`, reason `mail.setup.cloudflareUnavailable`. A user token (verified), `/accounts` refused and no zone yet: `accountUnknown` (register a domain, then check again). With exactly one account it is chosen and its zones are listed. `missing` holds permission codes Cloudflare refused with HTTP 403 (`zoneRead`, `dnsEdit`, `sendingEdit`, catalog `mail.setup.cloudflare.permission.<code>`); anything else unclear is `unavailable`, never a guess. A new sign-in discards the account binding and plan, and on the Cloudflare route also the detection. `mail.setup.start` forgets the sign-in The sign-in lasts one setup run by design: `mail.setup.start` (every new opening of the wizard, also after an App upgrade restarts it) drops the sign-in of an open flow with nothing applied and deletes its sealed token; a flow with applied changes is resumed with its token (rollback needs it). The sign-in step says so (`mail.setup.cloudflare.oneRun`). Build 44: on a flow with applied changes waiting on its decision, failed or interrupted (not running), the call replaces the sealed sign-in in place (same reference, so the journal and the rollback use it) instead of `conflict`: the token must be active and see the bound account (`permission_refused` naming `zoneRead` otherwise) and pass the same probe as a sign-in (`permission_refused`, reason `mail.inbound.tokenMissing`, `details.permissions`); the relay's copy follows while it holds the old token; a token-caused `error` is cleared. Logged as `setup token replaced` (phase only) |
| `mail.setup.zones` | `{id, accountId, zoneId?}` or `{id, poll: true}` | `CloudView` | `accountId: ""` (no `zoneId`) is the Check again of an `accountUnknown` sign-in: it signs in again with the sealed token. Otherwise only an account the sign-in listed, and only a `zoneId` of the list just read. Lists its zones again (Check again). With `zoneId`: only an `active` zone of that fresh list; reads its DNS records and, once the flow's decision takes the Cloudflare relay, its Email Sending domains (a direct path never asks for Email Sending), and once the decision takes the Cloudflare inbound path, one read per inbound permission (Email Routing settings and rules, Workers scripts, VPC Services, tunnels; codes `zoneSettingsEdit`, `routingRulesEdit`, `workersEdit`, `vpcAdmin`, `tunnelRead`); these probes only read, so they cannot prove a write permission (the page says so); a write refused later is named at apply; only a 403 with the documented authorization codes 10000 or 9109 counts as missing, any other 403 (for example a product not enabled on the account) is `mail.setup.cloudflareUnavailable`, and names refused permissions in `missing`. Choosing another account or zone discards what rested on the old one; choosing an account without `zoneId` also cancels the old zone's MailPlus domain read at once (its executor slot is freed; it never stores), as a zone change does. `match` (own-domain route) is the zone holding the flow's domain: the longest label-boundary suffix (`a.b.example.com` → `example.com`, never `xexample.com`). With `zoneId`, also `mailDomains` (MailPlus Server's domains that are the zone or under it, sorted) from one `SYNO.MailPlusServer.Domain list v1` read (`mail-read`). The read runs in the background with the full DSM budget (slot wait plus `DSMReadTimeout`; `core.Authority` never sends a call with less than its full per-call budget left, which made build 26's 20 s read fail at once). The reply waits at most 8 s: `mailDomainsState` is `reading` (poll with `{id, poll: true}`, which reads nothing from Cloudflare; like the preview poll, a poll that also carries `accountId` or `zoneId` is `bad_request` and reads nothing), `read`, or `unknown` with `mailDomainsCause` and `mailDomainsCauseKey`. The cause is `probe_timeout` only for a call that was sent and did not answer in time, and `probe_not_started` for a call that never got an executor slot. A missing read grant (`authority_required`) or a caller who is not an administrator (`admin_required`) is returned as that refusal (the approval prompt), not as unknown. Path A reads the list too: when a zone is chosen, the flow can still carry the other route's source, so skipping the read is not safe. The Cloudflare route's detection accepts only one of those `mailDomains` (an unread or still-reading list accepts none). Any depth under the zone is accepted; Email Routing, its locked MX/SPF and Email Sending were verified live only one level under the zone (`mx.example.org`), so deeper names (`a.b.example.com`) are not verified live. The zone list is the sealed token's own `GET /zones?account.id=` view, so a token whose Zone Resources cover one zone lists only that zone; a token from the create-token link (all zones, unless the user narrowed it) lists every zone of the account. Write access is not checked per listed zone: the chosen zone's reads name refused permissions, and a refused write is named at apply |
| `mail.setup.detect` | `{id, intent: send\|receive\|both, domain, answers: {source?: own\|cloudflare, route?: cloudflare\|direct}, refresh?}` (build 32: `route` replaces `fixedIp`, `port25Out` and `port25In`, which are refused); `route` is the route step's choice, absent on the first detection (right after the domain), and only `direct` (the own IP, its requirements confirmed by the administrator) can give a direct path; `source` is where the domain came from and decides no path (the route decides, for both sources); `source: cloudflare` needs a complete sign-in with nothing missing (`conflict`, reason `mail.setup.stalePlan` otherwise) and a domain that is the chosen zone or a name under it, read from MailPlus Server's domains when the zone was chosen (`bad_request`, reason `mail.setup.invalidAnswer`, otherwise), or (build 51) one MailPlus Server lacks when the intent sends: the decision then plans `mailplus.domain`; changing the source, account or zone discards the detection and plan | `{done, facts?, branch?}`; each fact's `value` is a catalog key (`mail.setup.value.*` or `mail.setup.cause.*`) with `params`; a `mail.setup.cause.*` value is an unknown fact, and the facts step shows `mail.setup.factsBody` only for a real unknown (a read failure, timeout or undecidable fact), not for `mail.setup.cause.notChecked` (not checked by this version, unknown by design) or the certain negatives `mail.setup.cause.noDomain`, `mail.setup.cause.notInMailPlus` (accounts and DKIM of a domain missing from MailPlus Server's domain list as read) and `mail.setup.cause.ptrNone`; when DNS does not know the domain, MX/SPF/DMARC show `mail.setup.cause.noDomain` too, and SPF is `fail` only for an existing but invalid record, and `mail.setup.cause.dnsUnknown` (never `present`) when a TXT lookup in its include/redirect walk gives no usable answer; a MailPlus read that fails without a DSM code names why: `mail.setup.cause.incomplete` (the reply lacks a needed field), `mail.setup.cause.badResponse` (unreadable reply, or a failure without a code) or `mail.setup.cause.executor` with the refusal `{code}`; a domain with more than 1000 accounts (more than this app reads) shows accounts as `mail.setup.cause.accountsTooLarge`, an unknown that stops setup with `mail.setup.unreadable.accountsTooLarge`; a blocked `unknown` branch lists the missing facts in `warnings`; `branch.paths[]` = `{direction: send\|receive, branch, titleKey: mail.setup.path.<branch>, why: [mail.setup.why.<code>]}` for each decided direction; `branch.receivePending: true` when the intent is both and the domain has no enabled mailbox (only sending is decided; receiving waits); a missing domain, or no enabled mailbox for receive alone, is `configureMailPlus` with `titleKey` `mail.setup.prereq.noDomain` or `mail.setup.prereq.noMailbox` and `params.domain`; each fact also carries `group` (`mailplus`, `network`, `dns`, `cloudflare`), `state` (`ok`, `problem`, `unknown`, `notChecked`, `planned`: the decided plan creates it, `optional`: not needed, recommended), `noteKey` (planned and optional: why) and `unrelated` (not needed by the chosen route and intent); build 52: when the decision creates the MailPlus Server domain, `domains` is `planned` (`mail.setup.planned.mailplusDomain`) and the new domain's `accounts` and `dkim` are `planned` and `unrelated`, while receiving waits MX, inbound 25 and the tunnel are `unrelated`, and a worker that sends `state` gets `mail.setup.factsBody` only for a related `unknown` fact, see [mail-rules.md](mail-rules.md#detection-results) | Starts or polls the read-only detection. This version configures no external inbound-25 probe: receive/both trigger no external probe, and inbound stays unknown ("Not checked by this version"). The route changes the decision, not the detection: a changed route re-decides from the same facts, drops the account and plan, and cancels a plan still being prepared. Once the detection is done, only a poll whose route changed writes the flow (while the detection runs, each poll saves the flow, as before). On the Cloudflare route the detection also reads the zone fact with the sealed token (fresh zone list and its NS records; read-only): an active, full zone that holds the domain with no NS record at its apex (multi-provider DNS) and no delegation makes Cloudflare-managed known even when DNS timed out (`mail.setup.value.cloudflare.yesZone`), unless DNS gave a definite answer that differs; see mail-rules.md. See [mail-rules.md](mail-rules.md#path-decision-route-and-checks) |
| `mail.setup.permissions` | `{id, accountId, zoneId}` | `{permissions[]}` | Own-domain source: binds the signed-in account and zone (only the ones chosen through `mail.setup.zones`, and only a zone that holds the domain); local inventory only. The Cloudflare source binds them at detection (`branch.needsAccount` is then `false`) |
| `mail.setup.preview` | `{id, addresses?, members?, tunnel?, receive?: domain\|addresses}` or `{id, poll: true}`; `receive` only when receiving through Cloudflare (default `addresses`), see [mail-rules.md](mail-rules.md#receive-through-cloudflare) | `{changes[], permissions[], warnings[], pending?, tunnels?, receiveMode?}`; the whole-domain mode plans `inbound.catchall` instead of `inbound.rules` and is refused with `mail.setup.receive.domainUnavailable` when the domain is not the zone apex or the zone's catch-all is in use; `tunnels[]` = `{id, name, connect, match}` when no single inbound tunnel is certain (nothing was planned; preview again with `tunnel`, receive only); inbound refusals carry `mail.setup.tunnelRequired`, `lanUnknown`, `rulesLimit`, `routingConflict`, `routingLeftover` or `routingLeftoverDisabled` | Takes no token: uses the sign-in's sealed token for the Cloudflare calls and, for the relay send path, as the relay's SMTP password. Builds the exact plan in the background (MailPlus reads, two minutes each at worst); answers within 12 s, `pending` until ready; poll with `{id, poll: true}`. Work nobody polls for 3 min, or a stopping worker, is canceled; the next poll prepares again from the sealed answers. Journals changes as planned. No remote write. Each plan carries the basis it was prepared for (flow, detection, intent, answers, decision): a finished preparation whose basis no longer matches the flow is discarded (`conflict`, reason `mail.setup.planChanged`: generate the preview again), never stored |
| `mail.setup.apply` | `{id}` | `FlowView` (`phase: applying`) | Refuses a stored plan whose basis no longer matches the flow (answers or facts changed) with `conflict`, reason `mail.setup.planChanged`, writing nothing; the page offers "Generate the preview again". Background: snapshot → journal → apply per change; failure rolls back (with its own budget); then verify → `decision`. Every MailPlus read and write gets two minutes once it holds an executor slot. Only one flow in the package applies, verifies or rolls back at a time (another administrator gets `conflict`, reason `mail.setup.otherTransaction`). A write failure counts as sent-but-unknown unless the executor refused it before admission: exactly the codes protocol v1 marks `preAdmission: true` (SDK v0.53.19 `spec/protocol/v1/errors.json`, for example ROOT_BUSY, DELEGATION_DENIED, APP_DENIED, INELIGIBLE, POLICY_DENIED); EXECUTOR_PAUSED, ROOT_STAGING_FULL, disabled, APP_STOPPED and APP_STARTING are not; a step that got no executor slot was never sent (`mail.setup.notStarted`). A write without an answer is never sent again: apply and rollback read the current setting first; when it cannot be read in time the flow ends `failed` with `error: mail.setup.unconfirmed` and only an explicit rollback tries again; a Cloudflare write refused with code 10000/9109 ends the apply with `error: mail.setup.permissionRefused.<code>` (the refused call's permission) and rolls back; any other 403 is `mail.setup.integrationUnavailable`; an inbound plan whose NAS LAN address changed since the preview is `mail.setup.stalePlan` |
| `mail.setup.status` | `{id}` | `FlowView` | An orphaned running phase becomes `interrupted` |
| `mail.setup.receivemodes` | `{id}` | `{domain, domainReason?}` | Only on a new flow that receives through Cloudflare with its account and zone bound. Reads the zone and its catch-all with the sealed sign-in token (no write): `domain: true` when the mail domain is the zone apex and the catch-all is unused (disabled, or drop only); else `domainReason` `mail.setup.receive.subdomain` or `mail.setup.receive.inUse` |
| `mail.setup.decide` | `{id, choice: keep\|rollback\|verify}` | `FlowView` | keep only in `decision`; keeping a setup that changed Cloudflare records it for the Overview (`mail.kept`, below) and hands it the sealed token; rollback in `decision`, `failed`, `interrupted` (background); verify only in an unverified `decision`: re-runs the read-only verification in the background (`verifying` → `decision`), never writes or rolls back; an interrupted re-check returns to `decision` |

`BranchView.kind`: `configureMailPlus`, `blocked`, `diagnose`, `already`,
`unavailable`, `configure`. A licence shortfall (MailPlus Server's License API
counts more active users than licences: `get_active_user_num` `total` >
`get_user_limit` `limit`) is `configureMailPlus` with `reason: licenseShort`,
`titleKey: mail.setup.licenseShort`, `bodyKey: mail.setup.licenseShortBody`
and `params: {active, licensed}`; the fact `mail.setup.fact.license` then shows
`mail.setup.value.license.short` with status `warning`. An unknown licence
(`mail.setup.cause.*`) never blocks setup. `FlowView.phase`: `""`, `applying`, `verifying`,
`decision`, `rollingBack`, `rolledBack`, `kept`, `failed`, `interrupted`.
`FlowView.outcome` (finished flows): `ok`, `failed`, `rolledBack`.

## Kept Cloudflare setups (`backend/internal/mail/inbound_sync.go`)

| Operation | Params | Result | Effect |
| --- | --- | --- | --- |
| `mail.inbound.status` | `{}` | `{setups: KeptView[]}`; `KeptView` = `{id, domain, intent?, receive?: domain\|addresses, token, tokenInvalid?, relay?, last?, synced?, removes, routingOwned?, removal?}`; `synced` (build 49, per-address setups) = `{mailboxes, added?, removed?, at?}`: how many mailboxes receive through the setup's rules after its last completed sync (set by the setup itself, then by each completed sync; a failed sync keeps it), stored on the record so it survives a worker restart; records kept by builds 41–48 get it at their next sync (the record also keeps the hashed mailbox set, never returned); `auto` (build 50, per-address setups, worker memory) = `{state: ok\|failing\|stopped, causeKey?, unsynced?, held?, checkedAt?}`: the automatic sync (see [mail-rules.md](mail-rules.md#kept-setups-and-the-mailbox-sync)); `tokenInvalid` (build 44): Cloudflare refused the kept token (deleted or rolled in its dashboard), see [mail-rules.md](mail-rules.md#a-refused-cloudflare-token-build-44); `relay`: the setup sends through the relay; `removes` = catalog keys `ui.remove.item.*` of what a removal takes away; `removal` = `{state: running\|done\|failed, done, total, causeKey?, at?}`; `last` = `{state: running\|done\|failed, added, removed, pending, addresses?, causeKey?, at?}` | Reads the package's records only (KV `mail.kept`, and build ≤40 inbound records as legacy setups): no DSM or Cloudflare call, no write. It nudges the worker's automatic sync to check healthy setups whose last check is a minute old (in the background, not in this call). The token itself is never returned |
| `mail.inbound.sync` | `{id, poll?}` | `KeptView` | Per-address setups only (`bad_request` otherwise). Starts one background run unless one runs (`poll` only waits for the current one) and waits at most 8 s. The run reads the domain's MailPlus accounts, then adds missing exact rules and deletes this setup's rules for mailboxes that are gone; foreign rules are never touched; at most 100 writes. No token: `unavailable`, reason `mail.inbound.tokenRequired`. `causeKey`: `mail.inbound.cause.mailplus` (no definite MailPlus read: nothing changed), `token` (refused or unusable token: ask for one), `gone` (a legacy setup with none of its rules left), `interrupted`, `cloudflare`. Only the administrator's press calls it; nothing runs on its own |
| `mail.inbound.token` | `{id, token?}` | `KeptView` | With `token` (build 44): verifies it active (a user token, or one owned by the setup's account; `bad_request`, reason `mail.setup.tokenInvalid`, otherwise; nothing is sealed) and able to make the read of every permission the kept setup needs (`zoneRead`; `dnsEdit` when its journal changed DNS; `sendingEdit` when it changed Email Sending or uses the relay; `routingRulesEdit`, `workersEdit`, `vpcAdmin` when it receives through Cloudflare). Missing ones are named together: `permission_refused`, reason `mail.inbound.tokenMissing`, `details.permissions` = comma-separated codes (catalog `mail.setup.cloudflare.permission.<code>`). Accepted: sealed under the record's own reference (the journal's sign-in reference is answered with it, so the removal uses it), copied to the relay's SMTP login when this setup uses the relay and the relay holds a token, `tokenInvalid` cleared. Without `token`: forgets (deletes) the kept token. The token is held in memory only until sealed and never echoed or logged |
| `mail.cloudflare.remove` | `{id, routing?}` or `{id, poll: true}` | `KeptView` | Build 42. Removes a kept setup: undoes its journal newest first through the setup's rollback (only resources the journal proves are this App's; already gone counts as done), turns the relay off, restores MailPlus, then deletes the sealed token and the record. `routing: true` also turns Email Routing off on the zone, accepted only when `routingOwned` (this setup enabled it; `bad_request` otherwise). Starts one background run unless one runs and waits at most 8 s; `poll` only waits for the current run (none: `not_found`). No token: `unavailable`, reason `mail.inbound.tokenRequired`. Each done step is saved, so a stopped run resumes. `removal.causeKey`: `mail.inbound.cause.token` (ask for a token), `cloudflare`, `interrupted`, `mail.remove.cause.changed`, `nas`, `record`; build 55 splits `nas` into `mailplus` and `relay` (which NAS step stopped), and adds `authority` with `removal.profile` (the DSM access profile the executor refused, usually `mail-write`: the Overview offers Allow access beside Try again) and `admin`. Build 50: a MailPlus Server mail domain the setup created is deleted only while it has no users; otherwise it is kept and a done run says `removal.keptDomain`. After build 55: a subdomain routing MX the setup created that Cloudflare refuses to delete (locked by Email Routing) is unlocked with `PATCH /zones/{zone}/email/routing/dns {"name": <subdomain>}` (once per run, Zone Settings Write, never the apex) and deleted; `removal.locked` lists only records still refused, or all locked ones when the unlock itself is refused; a reply naming another domain stops the run (`cloudflare`) before any locked record is deleted. See [mail-rules.md](mail-rules.md#removing-a-kept-setup-build-42) |

## Diagnosis (`backend/internal/mail/diagnose/run.go`)

Runs live in worker memory (16 at most, ten minutes each), bound to the owner.

| Operation | Params | Result |
| --- | --- | --- |
| `mail.diagnose.symptoms` | `{}` | `{symptoms: [{symptom, checks}]}` |
| `mail.diagnose.start` | `{symptom}` | `Run` (no check run yet) |
| `mail.diagnose.next` | `{id}` | `Run`; within 12 s: one more check, or `pending` with `phase` (`reading`, `checking`) while background work continues; ranked findings and `summary` when `complete` (also when the MailPlus Server gate stops it); a complete run is returned unchanged |

`summary` (`summary.go`): `verdict` (`problems`, `unclear`, `clear`,
`unreadable`), `problems` (at most 3: `{key, severity, targets, action, intent,
findings, details}`; `action` is `setup`, `mailplus`, `packages` or absent),
`more` (the rest, same order) and `others` (`{key, state, check, targets,
count}`, `state` `note`, `unknown` or `ok`). Copy: `mail.diag.problem.<key>.*`,
`mail.diag.other.<key>`, `mail.diag.area.*`, `mail.diag.check.*`.

## Relay

| Operation | Params | Result |
| --- | --- | --- |
| `mail.relay.status` | `{}` | `{id: "mail.relay", enabled, status}` |
| `mail.relay.set` | `{enabled}` | `{}` (the setup's relay change turns it on) |

### Email Sending check mail (inbound verification): unverified assumptions

The inbound verification sends one check mail through Email Sending only when
the same flow onboarded a sender. Each of these is taken from the API
reference's example, not observed:

- the path `POST /accounts/{account_id}/email/sending/send`;
- the body fields `from` (string), `to` (array of strings), `subject`, `text`;
- `result.message_id` equals the Message-ID MailPlus records in its
  TransactionLog;
- mail from the account's own sender to an address of a routed zone goes out
  through MX and Email Routing (no internal short-circuit).

If any of them is wrong, the check mail is not found and the subject-code path
(the administrator's own mail, matched by code, routed recipient and VPC
source) stays the deterministic fallback. Nothing is ever claimed delivered
without that TransactionLog entry.

### Inbound routing conflicts and leftover rules

`mail.setup.preview` refuses with `mail.setup.routingConflict` only for
(a) MX/SPF on the mail domain that are not Email Routing's own (when the
domain has no Email Routing yet) and (b) a rule for a requested address that
is not this package's. Email Routing already enabled on the domain (for
example after a rollback, which keeps it) is reused with its records. A rule
this package left for a requested address (`syno-home-keeper:<owner>` to that
owner's Worker) is **replaced in place** ("taken over"), only when that
owner's VPC Service is missing or points to this NAS's LAN address over the
same tunnel, and only when the rule is enabled: apply re-reads it and, only
in that exact shape, points it at this flow's Worker and name, keeping its
address, priority and enabled state; a rule changed (disabled included) in
between is `mail.setup.stalePlan`. A leftover whose owner's VPC Service
targets another address or the same address over another tunnel is
`mail.setup.routingLeftover`: it may still serve another NAS, so it is never
taken over and stays manual cleanup (the copy says to delete the rule, its
Worker and VPC Service in the Cloudflare dashboard if that setup is no longer
used). A leftover that could be taken over but is disabled is
`mail.setup.routingLeftoverDisabled`: refused at plan time rather than taken
over and shown, because the state is kept, so the address would receive
nothing and verification could never pass, and turning it on would undo an
administrator's choice; the administrator enables or deletes it. Rollback gives it back to the earlier owner. The
preview's rules change says "takes over a leftover rule of this package".
