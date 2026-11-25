# Design

## Shape

```
DSM window (Vue, @synopackageland/ui)          CGI (api.cgi, per request)            worker (supervised, package account)
 SetupWizard / DiagnoseWizard   ── ctx.call ──▶ entry gate (admin-only) + policy ──▶  0600 Unix socket (var/run/assistant.sock)
 WizardDialog + WizardStep                      dsm.authority.* (SDK grants)          worker.Invoke: mail.setup.*, mail.diagnose.*,
 OverviewPage, AccessSettings                   mail.* forwarded with the caller      mail.relay.*, dsm.authority bindings
                                                                                      core.Host: store (KV + sealed secrets),
                                                                                      Authority (executor grants), relay service
```

The worker is the SDK jobs capability's supervised process, as in Home
Keeper. It is needed because three things outlive one CGI request: the
read-only detection job (up to three minutes), the apply/rollback transaction
and the mail relay listener.

## The wizards on the UI SDK Wizard

Home Keeper ran mail.setup and mail.diagnose as **server-driven** wizards:
`core.Wizard.Next(session)` returned the next `Step` (kind, fields, options,
facts, changes…) and a generic `WizardRunner.vue` drew whatever came back.

Here the **browser owns the step flow**, written once with the UI SDK's
`WizardDialog` and `WizardStep`, and the worker exposes explicit operations.
Every branch rule and validation is still in Go and unchanged; the browser
only decides which of its declared steps to show next from typed replies.

### mail.setup (`frontend/src/wizards/SetupWizard.vue`)

Only the chosen path's steps are rendered (`v-if`), so the wizard's "Step n of
total" counts that path (the sign-in steps of A, the MailPlus Server
prerequisite and the stop/already outcomes appear only when needed). Each
step's content is one `Space direction="column"` (or a `Form`), so blocks keep
the wizard's padding and one gap; numbered instructions are a `StepList`, long
lists fold in an `Accordion`. An error belongs to its step: any step
change or source change clears it.

| HK step (`Step.ID`, kind) | UI SDK step | Worker operation | Notes |
| --- | --- | --- | --- |
| `intent` choice | `intent`: `RadioGroup variant="card"` | `mail.setup.start` on open | "Diagnose mail problems" is a 4th card that hands off |
| – (new) | `start`: `RadioGroup variant="card"`, nothing pre-selected: **A** "I have my own domain and manage its DNS" → `domain`; **B** "Use Cloudflare (no domain yet, or the domain is already on Cloudflare)" → `cloudflare` → `zone` | – (the choice goes with every `mail.setup.detect` as `answers.source`) | the source says only where the domain comes from (typed, or the sign-in's zones). It decides no mail path: both choose the same `route` after the detection |
| – (new) | `cloudflare`: one line, then a `StepList` of three steps (open the form; in Cloudflare choose the account and zone, all zones by default and narrowable under Zone Resources, then create and copy; paste it here), the button **Create the token on Cloudflare** (the dashboard's account token form, `?to=/:account/api-tokens`, with every permission filled in by canonical permission group ID: Zone Read `c8fed203…`, DNS Write `4755a26e…`, Email Sending Write `5df633d6…`, and for inbound Zone Settings Write `30306871…`, Email Routing Rules Write `79b3ec0d…`, Workers Scripts Write `e086da7e…`, Connectivity Directory Admin `77efc2c0…`, Cloudflare Tunnel Read `efea2ab8…`: one token for every path; the user picks the account and zones), the permissions folded in an `Accordion` "Required permissions (8)", one per line as `Zone · DNS · Edit`, one password `Input`, then three short notes (the token is the relay's SMTP password; sign-in checks read access only; sealed on the NAS, kept with a setup that changed Cloudflare for Sync mailboxes, deleted by a rollback or Forget token); B after `start`, A after `facts` when `branch.needsAccount` | `mail.setup.cloudflare` in `pre-enter-next-step` | the worker checks the flow, seals the token under a fresh reference and signs in (user or account-owned token, see CONTRACT); the page drops the token as soon as the reply comes; a refused token is `mail.setup.tokenInvalid`; refused permissions are named with the link again and **Replace the token** (no upgrade flow) |
| – (new) | `zone` (B): account `Select` only when there are several (one is chosen silently; none says so); zone `Select` with each zone's status, non-active zones disabled with a note; choosing a zone reads it at once (the MailPlus read in the background; the page polls while it reads) and lists MailPlus Server's domains that are the zone or under it as a mail-domain `Select` (one preselected when there is exactly one; never the apex by default; none → exactly what to type in MailPlus Server, with copy buttons and **Open MailPlus Server**: never set up (`mail.mailplus.status` `setUp: false`) → its first-run wizard's domain name `<zone>` and host name `mail.<zone>`, set up → Domain → Create `<zone>` when the setup only receives, unknown → both; set up and the setup sends (build 50) → the `Select` offers **Create a MailPlus Server mail domain…** (chosen when the zone has none) with a name field (the zone's name by default; it must be the zone or a name under it and not one MailPlus Server already has), and a note that the preview adds the step and the new domain has no users yet; coming back to the window (the host's `window-activated`, else focus) reads the zone again at most once per 15 s; an unread list → unknown with **Check again**); no zones → explanation + **Register a domain on Cloudflare**; one **Check again** in the footer (`#actions`), which reads the chosen zone again or, without one, lists the zones; Next starts `mail.setup.detect` and goes to `detect` | `mail.setup.zones` (account choice, Check again, and the chosen zone as soon as it is picked) | the worker accepts only IDs it listed; choosing the zone reads its DNS records; once the decision takes the Cloudflare relay, `configuration` reads the zone again for Email Sending before the preview |
| `domain` form | `domain` (A, after `start`): `Form` + `Input` | `mail.setup.detect` (no route yet) in `pre-enter-next-step` | starts the read-only job right after the domain |
| `detect` progress (poll) | `detect`: `type="progress"`, indeterminate; Back (read-only) stops watching | `mail.setup.detect` every second while open on the step | moves on through `v-model:active-step-key`: to `prereq` when MailPlus Server lacks something, else to `route` (or to `facts` after the route or a stop's Check again) |
| `configureMailPlus` | `prereq` (only when needed): headline "MailPlus Server check", the line says exactly what is missing (`mail.setup.prereq.noDomain` / `noMailbox` with the domain, or the licence shortfall), a Callout with what to do, the MailPlus facts with a problem, **Open MailPlus Server** (SDK `openApp`); main action **Check again** (stays on the step while still missing); intent both with no mailbox is not blocking: "Receiving waits", main action **Set up sending**; `#actions` **Diagnose** | `mail.setup.detect` with `refresh: true` | see [MailPlus Server hand-off](#mailplus-server-hand-off); no MailPlus write |
| – (build 32) | `route`: `RadioGroup variant="card"`, nothing pre-selected: "Cloudflare receives and sends for me (recommended)" (its line: the NAS can be anywhere, no router setup) or "Use my own IP to send and receive directly" (its line: directly, needs a fixed IP and port 25); each card shows its `MailWayPicture` (build 39); the own IP lists its requirements (`StepList`: fixed public IP; inbound TCP 25 forwarded, when receiving), a `Link` to MXToolbox's SMTP test with the detected public IPv4, the detected IP / outbound 25 / PTR facts (with a warning when one is a problem or unknown), a `Checkbox` "I have confirmed these requirements" that Next waits for, and "Not eligible?" with **Use Cloudflare instead** | `mail.setup.detect` with `answers.route` (re-decides from the same facts) | replaces the build ≤31 `network` step (Yes / No / Not sure per question); the outside test is a link only, never a fact |
| `facts` info | `facts`: the facts that need attention (`state` problem or unknown) first, under their group with a `Badge`; an `Accordion` folds "N other items are fine" (ok and not checked) and the facts the chosen route does not need; then `PathList` (each decided direction's path and the reasons, `branch.paths`); `receivePending` adds a note | (reply of detect) | `next-step-key` is a function of `branch.kind`; `stop` shows the same `PathList` (`configuration` does not repeat it); nothing is dropped |
| `blocked` choice (`retry`/`diagnose`) | `stop`: Callout + manual DNS `ChangeList`; main action **Check again**; `#actions` **Diagnose** | `mail.setup.detect` with `refresh: true` | MailPlus Server's own gaps never reach this step |
| `already` choice (`done`/`diagnose`) | `already`: `type="result"`, tone `success` when outcome ok, else `warning` | – | DNS-only "ready" is not success |
| `account` form | `account` (A only): account `Select` when there are several, and the zone that holds the domain (`CloudView.match`, decided by the worker: the longest label-boundary suffix among the token's zones, so `mx.example.org` → `example.org`; the mail domain stays the subdomain); no typed IDs | `mail.setup.zones` without a zone on entering the step (a view kept from the other route or an earlier domain holds no or another match), then with the matched zone, then `mail.setup.permissions` | returns the exact token permission inventory; B binds account and zone at detection and skips this step |
| `configuration` form | `configuration`: headline "Mail for {domain}" (the domain once); at most three plain lines (send through Cloudflare; receive for the N current mailboxes; offline senders retry); an `Accordion` "Details" folds the mailboxes read from MailPlus (`BranchView.mailboxes`), the later-users note and the inbound limits (restore, SPF, plan); no address field, no `PathList`, no warning facts; no enabled mailbox → `mail.setup.noMailboxes` with **Open MailPlus Server** and Next disabled; fields from `BranchView.fields` only for the MailPlus-provisioning path (no token field: the sign-in holds the one token); for inbound, a tunnel `RadioGroup variant="card"` when the preview answers `tunnels` (a single Syno Connect tunnel preselected; Next waits for a pick), and `mail.setup.tunnelRequiredBody` under a `tunnelRequired` refusal | `mail.setup.preview` (with `tunnel` after a pick) | the plan uses the sealed sign-in token, also as the relay's SMTP password |
| `preview` (Apply via `wizards.apply`) | `preview`: `ChangeList`, permissions, warnings; main action **Apply** | `mail.setup.apply` | apply runs in the worker, not in the request |
| engine progress (apply/verify) | `applying`: `type="progress"`, determinate (done/total) while applying, indeterminate while verifying or rolling back; no Back, no stop | `mail.setup.status` every second while open on the step | a failed read keeps the progress, says "Status not up to date" and offers **Check again**; it never re-applies |
| `decision` choice (`keep`/`rollback`/`diagnose`) | `decision`: findings + changes; one `RadioGroup variant="card"` (Keep / Roll back) and one main action **Confirm**; Roll back returns `{goTo: 'applying'}` from the guard; an unverified inbound finding adds **Check again** | `mail.setup.decide` with the chosen value; Check again sends `verify` and polls `mail.setup.status` every 2 s while verifying | Keep card only in the decision phase (disabled after failure/interruption); pre-selected Keep only when verified; otherwise no card is selected and Confirm stays disabled until the admin picks one; choosing alone writes nothing |
| `kept` / `rolledback` / result | `result`: `type="result"`; tone `success` (kept, verified), `warning` (kept unverified, or rolled back after a failed check), `neutral` (rollback the admin chose), `danger` (failed) | – | anything the worker did not state is `warning`, never `success` |
| handoff `mail.diagnose` | closes and opens `DiagnoseWizard` | – | |

### Inbound through Cloudflare

Receive (or both) without a usable direct path plans Email Routing (only when
the mail domain has none) → a VPC Service on a healthy tunnel → this package's
Email Worker → either the zone's catch-all pointed at the Worker (**whole
domain**, the zone apex with an unused catch-all only) or one exact
rule per address of the domain's enabled MailPlus accounts (**chosen
mailboxes**, read from MailPlus Server, never typed); the Worker guards by
domain; see
[mail-rules.md](mail-rules.md#receive-through-cloudflare). Verification reads every resource back, then
looks in MailPlus's transaction log (`SYNO.MailPlusServer.Audit.TransactionLog
list v1`) for a completed delivery after the first check: by Message-ID when
this flow also set up Email Sending (one check mail, sent once, waited for up to
90 s), else by the code `MPSA-xxxxxxxx` in a subject the administrator sends
from outside. Until then the flow is unverified; **Check again** re-runs the
read-only verification and never writes or rolls back.

A delivery counts only when its entry also names the routed address
(`ori_rcpt`) and came from the VPC target (`src_ip`). The preview adds a
warning when MailPlus has relay client networks configured (or they could not
be read).

Not done yet (follow-ups): diagnostics that compare the VPC Service host with
the NAS's current LAN address and check the tunnel's health after Keep;
judging whether a MailPlus relay network covers the NAS (the entry fields are
unobserved).

### Facts and preview in plain words (build 43)

The owner's rule for the setup wizard: show only what the administrator must
decide or know, in plain words; never echo a choice back; technical detail
goes behind the **Details** (`詳細說明`) fold; the domain shows once, in the
headline.

- **Facts**: the decided paths are not listed. A path that follows the chosen
  route, with its "because you chose ..." reason (`mail.setup.why.routeCloudflare`,
  `routeDirect`, `routeUnset`), is an echo. Only on the own-IP route, a
  direction the detection moved to Cloudflare shows as one info line
  (`mail.setup.pathChanged.send|receive`) with the checks that moved it.
- **Account** (path A): headline `mail.setup.accountFor` ("Cloudflare
  account for {domain}"); the line says only that the account
  holds the domain (`mail.setup.account.found`), or names the parent domain
  it sits under (`foundParent`); no "zone" wording (`zone.matched` and
  `zone.noMatch` are no longer shown).
- **Configuration** (path A, after the account step): the token permissions
  are no longer listed raw (`scope / resource / name`).
- **Preview**: headline `mail.setup.previewFor` ("Confirm the changes for
  {domain}"); one line per change the administrator recognises
  (`mail.setup.summary.*`, keyed by change ID in `SetupWizard.vue` `SUMMARY`;
  `dns.*` counted per Cloudflare or external DNS; an unmapped ID falls back
  to its action text). Warnings the configuration step already gave (the
  branch's warnings) are dropped; at most two new plan warnings show. The
  relay client networks note (`mail.setup.inbound.relayNetworks`, and
  `relayNetworksUnknown`) is folded only and says no change is needed: the
  Worker hands MailPlus only recipients of the configured domain, so those
  networks cannot open a relay through the inbound path, and a LAN range
  there is often deliberate (printers, scanners). The fold holds every new warning in
  full, the token permissions as purposes with Cloudflare's name
  (`mail.setup.purpose.*`), and the exact before/after `ChangeList`.

The stop step still uses `PathList` (it explains why the wizard stops), without the route echoes.

### Receiving modes and Sync mailboxes (build 41)

The configuration step, when receiving through Cloudflare, shows one
`RadioGroup variant="card"` "How mail is received": **Receive the whole domain
automatically** (`整個網域自動收信`) and **Chosen mailboxes** (`指定信箱`).
Entering the step calls `mail.setup.receivemodes` (read only; Next waits for
it); the whole-domain card is preselected when available, else shown disabled
with its one-line reason (`mail.setup.receive.subdomain`: needs the main
domain; `inUse`: the domain's other addresses already go somewhere else;
`unknown`: could not be checked). The choice goes to the preview as
`receive`; the first consequence line and the Details fold follow it. No
visible copy says catch-all or Email Routing (vitest checks the nine
locales).

The Overview's **Receiving through Cloudflare** section (build 42: **On Cloudflare**)
(`frontend/src/components/InboundSection.vue`) lists each kept setup that
receives through Cloudflare (`mail.inbound.status`, read with the Overview's
own reads) and its mode. The whole domain says new users need nothing. Chosen
mailboxes show the hint "After adding or removing MailPlus users, press Sync",
the **Sync mailboxes** button, and one result line ("Added 2, removed 1
mailboxes", "already in sync", the mailboxes still pending), or the failure
with **Try again**. The row says how many mailboxes the setup syncs
(「指定信箱・已同步 5 個信箱（＋2／－1）・上次同步：16:47」, build 49): the count the last
completed sync (or the setup) left receiving, kept on the record (`synced`) so
it shows after a worker restart without asking Cloudflare, and what that sync
added and removed when it changed something. The whole-domain row says
「整個網域自動收信」 instead. A run that outlasts the 8 s reply shows progress and is
asked for again every 2 s until it ends; only that press starts it. A missing
or refused token shows the create-token button (same link as the setup) and
a password field; **Save token and sync** seals it and syncs once. There is
no **Forget token** on the Overview (removal and rollback
delete the token; forgetting it alone would only stop sending and sync).
Designs not taken: a sync on opening the
Overview, a timer, or a watcher of MailPlus users (owner decision: manual
only; MailPlus and DSM document no change signal). The optional "N mailboxes
not synced yet" line is not shown: the Overview does not read MailPlus's
users, and reading them only for that line would cost a DSM pass per open.

### Remove Cloudflare setup (build 42)

The Overview section is now **Cloudflare 上的設定** ("On Cloudflare") and lists
every kept setup, send-only ones too (mode "Sends through Cloudflare"). Build 44
shows each as one row: the domain, then muted "mode · 上次同步：
hh:mm" (a fresh sync result for 10 s after a press), with **同步信箱**
(listed mailboxes only; the "add or delete users, then sync" hint is its
tooltip) and a quiet **移除…** right-aligned; under the row only what needs
attention (a refused token with 「重新輸入權杖」, a failed sync, a stopped
removal, a token request) or what runs now. The danger styling is in the
confirm dialog only. **移除…** opens a `Dialog`
(size `md`): the title names the domain; "Only what this App created is
removed or put back:" then a bulleted list from `KeptView.removes` (receiving
for the whole domain or the listed mailboxes, sending, DNS records, MailPlus
settings put back, the forwarding service turned off, the saved token
deleted); "Anything else on Cloudflare stays as it is…"; and, only when this
setup turned Email Routing on (`routingOwned`), the unticked `Checkbox`
「同時關閉此網域的 Cloudflare 收信」 with what it changes. **Cancel** /
**Remove** (danger). The run shows a `Progress` "Removing the Cloudflare setup
(3/8)…", then a success `Callout` naming the domain and the setup leaves the
list; a stop shows why with **Try again** (same routing choice; done steps are
not repeated); a refused permission asks for a token like Sync (create-token
link, password field, **Save token**; the removal is pressed again). The section
description ends with 「解除安裝不會移除這些設定；要撤銷請按「移除」」 and the
dialog repeats it (the SDK uninstall wizard takes no note; see mail-rules.md). Designs
not taken: removing on uninstall (the package keeps no Cloudflare call in its
uninstall scripts, and a token may be gone by then); removing Email Routing or
DNS the App did not create.

A flow with applied changes that were neither kept nor rolled back is
**resumed** by `mail.setup.start` (Overview shows a notice), never discarded.
A worker restart during a transaction turns it into `interrupted`, and only
rollback is offered.

### mail.diagnose (`frontend/src/wizards/DiagnoseWizard.vue`)

| HK step | UI SDK step | Worker operation |
| --- | --- | --- |
| `mail.diag.symptom` choice | `symptom`: `RadioGroup` (5 options, vertical) | `mail.diagnose.start` in the guard |
| `mail.diag.run` progress (one group per poll) | `running`: `type="progress"`, determinate; Back (read-only) stops the run | `mail.diagnose.next` until `complete` |
| `mail.diag.result` result + findings | `result`: `type="result"`, the verdict as the description (tone `warning` for problems or unreadable, `success` for clear, `neutral` for unclear); at most 3 `ProblemCard`s (title, effect, affected targets, what to do, one button: setup wizard with the intent, MailPlus Server or Package Center through the SDK `openApp`), **Show more** for the rest; a next-step `Callout` (on "not sure": **Choose another problem**); a collapsed `SettingsSection` 「其他檢查（N 項）」 with one line per note, not-checked areas and passed check; raw evidence only under **Show details**, never a DSM code; `#actions` **Run again**. The dialog uses `WizardDialog` `width`/`height` (`clamp(…, 80%, 1040px)` × `clamp(…, 100% - 48px, 900px)`): the same size in a default DSM window, larger when maximized | – |

A missing grant (`authority_required`) stops the run in place with **Allow
access**; the same run continues after the grant.

### Two ways: the route step's headline and concept picture (build 39; moved in build 49)

Build 39–48 opened the Overview with one highlighted line and the two ways
side by side (`MailWays.vue`). Build 49 moves them into the setup
wizard, where the choice is made: the route step opens with the line
(`mail.setup.route.headline`, 「不論有沒有固定 IP，都能幫您把收發信架好」), and its
two cards already carry the pictures and the same captions as their hints, so
the panels merge into the cards instead of repeating them. The Overview now
starts with MailPlus Server. `MailWays.vue`, `ui.overview.headline` and
`ui.ways.<way>.title|caption` are gone.
The picture (`MailWayPicture.vue`) is a
concept, not an architecture: lucide icons, two-headed arrows, one-word labels
(`ui.ways.node.*`), no lanes, router or tunnel. Inline SVG with `role="img"`,
`aria-label` and `<title>` from `ui.ways.<way>.summary`, `--ui-*` tokens for
light and dark, a viewBox so it scales. The route
step's two cards carry it, small, in the card's icon tile; the UI
SDK draws that tile 32 px square and has no slot for a wider picture, so
`style.css` widens it for `[data-routes]` only. Build 38's folded "See how it
works", `MailPathDiagram.vue` and its `ui.diagram.*` keys are gone. User-facing
copy never names Email Routing, Workers (except the plan's name), VPC, PTR or
FCrDNS. The relay section says only how it sends (`ui.relay.body`).

`PlanNote.vue` adds one quiet line on the route step only
(before a choice and with Cloudflare, not with the own IP): receiving is free,
sending needs Cloudflare's Workers Paid plan (3,000 mails a month included),
Cloudflare's own page decides, with a **Cloudflare pricing** link
(`CLOUDFLARE_PRICING_URL`, figures checked by the owner on 2026-11-12).

A Workers Free account is refused in plain words (`mail.setup.sendingPlan`),
never as a code: `cloudflare.PlanLimited` (HTTP 402, or a message naming an
entitlement, Workers Paid, a plan limit or an upgrade) on the sign-in check of
Email Sending (`Probe`, zone step), on the preview's sender reads, and on the
sender onboarding while applying (the flow error). Receiving alone never reads
Email Sending. What Cloudflare answers a Free account is classified from its
documented shape; it has not been observed on a real Free account.

A mail domain already in Email Sending (set up by hand or by another tool) is
reused when it works: enabled, and Cloudflare's preview for it reports no DNS
issue (an existing healthy domain answered 200 with no issues). The
change is recorded with `before`/`after` `existing`; apply only checks it is
still there and enabled (`stale` otherwise, never re-enabled), and rollback and
removal never delete it (the removal list leaves out `ui.remove.item.sending`).
Disabled, or with DNS issues: refused before anything is written with
`mail.setup.sendingExisting` (fix or delete it in Cloudflare, then try again).
Builds up to 44 refused every existing domain as `unsafePlan`, which the page
showed as "integration unavailable". The reuse path is covered by Go tests, not
yet run live.

### MailPlus Server precondition (`frontend/src/api/mailplus.ts`, `MailPlusNotice.vue`)

`mail.mailplus.status` is asked first, everywhere:

- **Overview**: the first section shows the state (badge, version). Not
  installed: 「此 NAS 尚未安裝 MailPlus Server」 with **Open Package Center**;
  stopped (or broken): 「MailPlus Server 已停止」 with **Open Package Center**
  (the App never starts or installs it); unknown: neutral text naming the cause
  with **Check again**. While it is not running, coming back to the window
  (`window-activated`, or the page becoming visible) re-checks, at most once
  per 15 s; nothing is listened for once it runs.
- **Setup**: opening the wizard reads it; not running shows the `mailplus`
  step first (Next is **Check again** until it runs, then moves to the intent);
  nothing that needs MailPlus Server is asked before. Coming back after
  **Open Package Center** re-checks in place (the hand-off re-check).
- **Zone step**: a domain read refused by the precondition shows the same
  notice, never a DSM code.
- **Diagnosis**: not installed or stopped is the only finding; the result
  shows the notice with **Open Package Center**.

Package Center opens through the SDK's `openApp({appId:
'SYNO.SDS.PkgManApp.Instance'})`; DSM documents no launch to a single
package's page, so the text says to search for MailPlus Server.

### MailPlus Server hand-off

The `prereq` step (MailPlus Server lacks the domain, an enabled mailbox for
receiving, or licences) opens MailPlus Server with the platform SDK's
DSM App launcher (`openApp({appId: 'SYNO.SDS.MailPlusServer.Instance'})`,
SDK `docs/dsm-app-launcher.md`). The written path ("Open MailPlus Server from
the DSM main menu…") always shows.

- `requested` only means DSM was asked: the step stays, nothing advances.
- `unsupported`, `unavailable`, `failed` (and `invalid-input`, `blocked`)
  show "This window cannot open MailPlus Server" with the manual path.
- Coming back is the host's `window-activated` event (`ctx.host.subscribe`,
  SDK 0.53.16 with a host generated by CLI 0.52.11: the App's own DSM window
  activated, brought forward, restored or switched back to), and the page
  becoming visible again (`visibilitychange`). The wizard watches from the
  moment the step shows (the administrator may open MailPlus Server from the
  DSM menu, without the button) and stops when the step is left (Back, Next,
  close) or the wizard unmounts. When the host answers anything but
  `subscribed` (an older generated host), the browser window regaining focus
  or the focus returning into the wizard after it left it stands in.
- A come-back re-checks at most once per 15 s since the last detection, and one
  at a time. One inside the interval is not dropped: a single deferred re-check
  runs when the interval ends (cancelled with the hand-off).
- The re-check runs a fresh read-only detection, shows its answer as a status
  line (still needs the change; checked again; or unknown for `blocked` with
  reason `unknown`, `unavailable`, a failed read or anything else unclear) and,
  unless unknown, replaces the shown detection: the step then names what is
  still missing, or says MailPlus Server is ready and its main action becomes
  Next. Activation never moves the wizard by itself.
- **Check again** while a re-check runs follows the worker job that re-check
  started (`refresh: false`) instead of starting a second one; when the
  re-check's start failed there is no job, so it starts a fresh one
  (`refresh: true`).

### MailPlus Server mail domain step (build 50)

When MailPlus Server finished its own setup (it has at least one mail domain)
but has none for the chosen name, and the setup sends, the decision adds
`mailplus.domain` first. It is a previewed change like the others
(`mail.setup.change.mailplus.domain`), applied through `mail-write`
(`SYNO.MailPlusServer.Domain create v1`, description `Created by MailPlus
Setup Assistant`, no automatic users, alias pattern `<a>`), and recorded in
the ledger with the new domain's ID. The plan puts it before every other
change (build 52): a refused or failed create rolls back with
Cloudflare, the relay and MailPlus Delivery untouched, and the rollback and
**移除** delete the domain last. A create whose reply was lost is
reconciled on the next apply by that description. A new domain has DKIM off,
so the own-IP route stops with `dkimRequired` as for any unsigned domain; the
Cloudflare relay needs no MailPlus DKIM. With receiving too, receiving waits
(`receivePending`, `createsDomain`: the prerequisite step says the new domain
has no users yet and to run the setup again after adding them). Receiving
alone keeps the guidance (Domain → Create), because a new domain has no
mailboxes. MailPlus Server never set up (no domain at all) keeps the
first-run guidance.

**移除** deletes the domain (`SYNO.MailPlusServer.Domain delete v1`) only when
its ID is the recorded one (or, after a lost create reply, its description is
the App's) and it has no users. With users it is kept and the removal still
finishes, saying so (`RemoveRun.keptDomain`, `ui.remove.keptDomain`); a
different domain of the same name is never touched (`stalePlan`).

## UI SDK wizard: what is native now (UI 0.25.1, SDK 0.53.20)

| Gap found in 0.23 | Now | Where |
| --- | --- | --- |
| 1. No server-driven steps | Not an SDK feature, on purpose. Steps are declared; a `next-step-key` function maps the typed `BranchView.kind` (the UI SDK "branches the backend decides" recipe). Unknown kinds go to `stop`. | `SetupWizard.vue` `nextAfterFacts` |
| 2. No progress/polling step | **SDK-native**: `type="progress"` with `progress` (determinate/indeterminate, `status`). The app still polls (one request at a time, only while open on the step); no timeout, retry count or auto-advance in the SDK. | `detect`, `applying`, diagnose `running` |
| 3. No failure outcome | **SDK-native**: `type="result"` with `result-tone` (`success`/`warning`/`danger`/`neutral`); no step uses `done` any more. | setup `already`, `result`; diagnose `result` |
| 4. No external hand-off | **SDK-native launcher**: `openApp` from `@synopackageland/sdk` (0.53.20+; see below) and the `window-activated` host event (0.53.16) for the re-check; the step itself stays an ordinary `WizardStep` with **Check again**, as the UI SDK recipe says. | `stop` (`configureMailPlus`) |
| 5. No wizard-to-wizard hand-off | App-owned (UI SDK recipe "Handing over to another wizard"): close the source, open the target with a prop. | `App.vue` |
| 6. Decision step | Unchanged: one card choice + **Confirm** (UI SDK recipe "Two equal ways on"). | `decision` |
| 7. Card choices are 2–4 | Was a guide, not a limit (doc fixed in UI 0.25); five short symptoms stay a vertical list. | diagnose `symptom` |
| 8. A guard cannot redirect | **SDK-native**: a guard returns `{goTo}`. Roll back → `applying`. **Check again** moves through `next-step-key` instead of setting the step and returning `false`. | `decide`, `retry` |

### Formerly missing, now in the SDK

- **"The user came back" in a DSM window** (reported from this repo):
  SDK 0.53.16 adds the `window-activated` host event; the DSM host script that
  delivers it is generated by CLI 0.52.11, so the App must be rebuilt with it.
- **`openApp` actually opening the App on DSM** (found on a test NAS): up to
  SDK 0.53.19 the launcher passed DSM a prototype-free launch config; DSM's
  `AppLaunch` calls `config.hasOwnProperty()`, threw and swallowed the error,
  so the wizard showed `requested` while nothing opened. SDK 0.53.20 passes an
  ordinary object (`frontend/test/wizards.test.ts` pins it). The CLI host's own
  `openApp` was never affected.

## Go SDK errors

Since Go SDK 0.53.19 executor errors can arrive wrapped (`delegate.NotSent`),
so a direct `err.(*api.Error)` misses the code. Every classifier uses
`errors.As` (`internal/core/authority.go`, `internal/core/dsm.go`, and the
DNS/Cloudflare error checks); `internal/core/authority_test.go` feeds real SDK
wrapped refusals.

## Writes, secrets and hibernation

- Writes happen only in `mail.setup.apply`/`decide`, `mail.relay.set`, and the
  administrator's own `mail.inbound.sync` / `mail.inbound.token` /
  `mail.cloudflare.remove`.
- The pasted Cloudflare token goes straight to the sealed secret store
  (`secret:mail.setup.<flow>.token`, `mail.setup.cloudflare`); flow records,
  plans, replies and logs carry references only
  (`backend/internal/worker/worker_test.go`). One token is pasted once and
  serves the setup calls and the relay's Cloudflare SMTP login alike
  (a refused token is one `tokenInvalid` flag on the kept record, written
  only when it changes, and one replacement updates every copy: the previous behavior), so
  revoking the token, or removing a permission from it, stops the relay
  (its SMTP login fails) and breaks the rollback of applied changes (the
  Cloudflare rollback calls fail). The token step says so. Each sign-in is
  verified first with the token held in memory; only a token a Cloudflare
  verify endpoint answered active is sealed, under its own reference
  (`secret:mail.setup.<flow>.token.<gen>`), and replaces the flow's sign-in. Only a flow still collecting answers can sign in.
  The setup copy is deleted when nothing can need it: a new sign-in, a new
  wizard (`mail.setup.start`), a transaction fully rolled back, or a kept
  transaction that changed nothing on Cloudflare; never while a rollback can
  still come (decision, failed, interrupted). A kept transaction that changed
  Cloudflare hands the copy to its kept-setup record (`mail.kept/setup.<flow>`) for **Sync mailboxes** (and the removal of the setup); a replacement
  pasted on the Overview is verified first and sealed under the record's own reference. The
  relay keeps its own copy (`mail.relay.cloudflare-token`), which diagnosis
  also uses to read the Cloudflare sender's DKIM selector after the setup
  copy is gone.
- No scheduled checks, notifier or findings store: diagnosis runs on demand
  and its results stay in memory. The one schedule is the automatic mailbox
  sync (docs/mail-rules.md): a MailPlus read per per-address setup
  every 10 min, Cloudflare only on a change; 同步信箱 syncs now;
  `mail.inbound.status` reads KV only; the last run stays in memory, and a completed run keeps only its counts on the record (`synced`). `Store.Put` skips unchanged values, and
  reading the Overview reuses the open flow instead of creating one.
- The relay host is event-driven: no timer runs while nothing changes.
