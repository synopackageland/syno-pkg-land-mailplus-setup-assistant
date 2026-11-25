# Mail diagnostics integration

This package implements `core.Check` and the read-only `mail.diagnose`
`core.Wizard`. It has no `Applier`, settings writes, mail submission, package
control, credential reads, custom listener, or background goroutine.

## Wiring owned by the mail module

`mail/detect` was absent from `origin/main` when this task started. Adapt its
read-only results to `StateSource.Snapshot(ctx, env) (State, error)` rather than
duplicating the detector here. The method must honor cancellation and return
credential-free observations only. A nil pointer means unknown, not disabled.
An error makes that run explicitly unavailable; its raw text is never returned.

```go
diagnostics := diagnose.New(diagnose.Dependencies{
    State: diagnose.WithRelay(detectorAdapter, relayService),
    DNS: net.DefaultResolver,
    Network: diagnose.SystemNetwork{Resolver: net.DefaultResolver},
    // Opt in only to providers for which product access has been confirmed.
    DNSBLProviders: approvedDNSBLProviders,
})
// Append diagnostics.Checks() to mail.Module.Checks().
// Append diagnostics.Wizard() to mail.Module.Wizards().
```

There are nine checks:

| ID suffix | Schedule | Reads |
| --- | --- | --- |
| `mailplus` | 15 minutes | Package running/SMTP, queue total/oldest/reason categories |
| `relay` | 15 minutes | Whether MailPlus uses the assistant relay, service running, last success vs queue |
| `network` | 6 hours | IPv4/IPv6 HTTP egress, PTR/FCrDNS, DNSBL controls, outbound TCP 25 handshakes |
| `domain` | 6 hours | MX, SPF, configured DKIM selectors, DMARC, MTA-STS TXT, TLS-RPT TXT |
| `certificate` | 24 hours | Expiry of the actual postfix/dovecot certificate assignments |
| `inbound` | On demand | External inbound TCP 25 observation; none is configured in this version, so always unknown |
| `client` | On demand | IMAP enabled and independently observed app connectivity |
| `transport` | 6 hours | Selected send/receive/client hops and provider/protocol failures |
| `access` | On demand | Selected-mailbox activation/home, affected-client Auto Block, licence observations |

`WithRelay` accepts the existing `relay.New(dataDir)` service through its
`Status()` interface, prefers its in-memory `info.lastSuccess` over persisted
state, and falls back to the existing KV `mail.relay/lastSuccess` timestamp.
It does not read credentials or call `TestUpstream`. The detector adapter still
establishes whether the MailPlus route actually uses the assistant relay.

All IDs start with `mail.diag.`. Checks produce issues/information rather than
success receipts. `Env.Now` supplies a deterministic clock.

A run reads its state once (`Snapshot`, bounded by `SnapshotBudget`: every
MailPlus DSM read may take its full two-minute budget, see `core.DSMReadTimeout`
and `detect.DSMPassBudget`) and judges every check against that snapshot
(`Evaluate`, bounded by `CheckBudget`, 15 minutes; `RunTimeout` defaults to it
and never exceeds it). Both run in the worker's background: `Runner.Next`
waits at most `NextWait` (15 s) and otherwise returns the run with `pending`
and `phase` (`reading` or `checking`), so no HTTP request waits for a slow
NAS. A snapshot that cannot read MailPlus Server makes every check
`unavailable` with the fixed cause (`mail.setup.unreadable.*`). Each DNS probe
has a five-second timeout (up to 30 seconds). The system network adapter has
its own five-second per-request timeout, asks both egress sources at once, and
does not probe IPv6 when the host has no global IPv6 address (the family stays
unknown). A batch deadline returns an error, preserving previous findings
instead of claiming a clean result from an incomplete run.

## State normalization and visibility

Use the exact read tuples documented in
the observed MailPlus API response shapes; this package does not invent additional
WebAPIs or timestamp formats.

| State | Detector source / requirement |
| --- | --- |
| Installed/running | `SYNO.Core.Package.list` v2, exact `MailPlus-Server` entry and `additional.status` |
| SMTP enabled | `SYNO.MailPlusServer.Service.SMTP.get` v1 |
| Domains/selectors | `Domain.list` v1 with offset/limit and `Domain.get_security` v2 per domain |
| Queue total | `Queue.list` v1 with offset/limit; never assume denied means zero |
| Queue oldest | Entire queue with a verified enqueue-time interpretation; partial pages do not prove the oldest item |
| Queue reasons | Allowlisted `DeferredReason` categories from `Queue.reason` or `Audit.TransactionLog.list` v1 `status_detail` when visible |
| Relay enabled | Verified MailPlus route to **the assistant relay**, not just a default host row or an unrelated third-party relay |
| Relay running/success | assistant relay status provider, never MailPlus queue emptiness as proof of success |
| Certificates | `SYNO.Core.Certificate.CRT.list` v1, actual `MailPlus-Server` postfix/dovecot service assignments |
| Inbound/client | Trusted external observation only, not LAN/hairpin reachability or tunnel presence |

E3 saw an empty queue, so nonempty queue element timestamps are **unverified**.
Keep `Oldest == nil` until normalized against verified API behavior, and retain
no sender, recipient, subject, message body, raw rejection, password or token.
Do not guess the unit of `maximal_queue_lifetime` or parse locale dates.
Transaction log migration/denial cannot establish an empty history.

Relay last success older than one hour becomes a warning only with pending
mail; no history is unknown and idle relays are not stale. A queued message
becomes stale at one hour if the true oldest timestamp is available. Certificate
warnings begin at 30 days; expiry is critical. These are diagnostic thresholds,
not claims about MailPlus queue lifetime.

## Wizard and fix intent

The first step is `mail.diag.symptom`; its answer is the JSON string option
value. `Plans()`/`PlanFor()` expose a defensive copy of the symptom → check
sequence → cause-priority table. Adding CSS-ticket scenarios changes this data
and its table tests, without changing the runner. Ranking is a rule-based
heuristic, not a measured probability.

The first answered call returns a `progress` step immediately. Each subsequent
poll advances one check group, stores only sanitized findings and a cursor in
`session.State["mail.diag.progress"]`, and eventually returns a final result.
Progress uses `Step.Done`/`Step.Total`; a completed diagnosis uses
`Step.Outcome = core.OutcomeOK`, meaning the diagnosis finished, not that mail
delivery succeeded or every observation was available.
Completed polls do not repeat probes. Choosing a different symptom clears this
cache. A canceled check leaves the previous cursor intact.

Fixable findings use `FixWizard: "mail.setup"` and `Params["intent"]` set to
`send`, `receive`, or `both`. The coordinator's wizard engine must retain the
originating finding's intent when starting that wizard with `from: findingId`
and hand it to the setup wizard's intent step. `core.Finding` and `core.Step`
already have parameter carriers, so no shared contract change is required.
Actions such as ISP PTR changes or certificate renewal give explicit manual
instructions; diagnose itself never applies them.

## Result summary (`summary.go`)

A completed run carries `Summary`: the result page shows it, never the
findings one by one. Every finding lands in exactly one place:

- **Problem** (warning or critical with a rule in `problemRules`): at most
  `MaxProblems` (3), critical first, then the symptom's rank; the rest in
  `More`. Findings with the same cause from several paths merge (a queue
  reason and the relay's `relay_failure` category; `queue_stale` and
  `relay_stale`); per-domain or per-address findings group and list their
  `Targets`. The action is `setup` only when a member finding hands off to
  `mail.setup` with an intent; otherwise MailPlus Server.
- **Other line**: notes (queue count, missing DMARC or MX, no DKIM selector,
  outbound 25), one `not_checked` line naming every area this version could
  not observe, and one `ok` line per check that ran and found nothing.
- **Hidden**: how a path is chosen (`path_*`), optional records (MTA-STS,
  TLS-RPT), `queue_age`, `group_activation`, `dnsbl_unknown`, and the NAS's
  own PTR/DNSBL/port-25 facts when a relay or provider sends the mail
  (`Params["relay"]`).

The verdict is `problems`, `unclear` (no problem, something not checked),
`clear` or `unreadable` (the MailPlus Server gate could not read it).

## Ported E4 behavior and limits

The DNS algorithms and system network probes reuse
the original health-check prototype; the CLI, historical evidence and
region-specific recommendations were not copied into product code. Probes use
the caller context, fakeable resolver/network interfaces and sanitized errors.

- No DNSBL provider is enabled implicitly. Supported opt-in names are
  `Spamhaus ZEN`, `Barracuda`, `SpamCop`, `PSBL`. Confirm product access and
  resolver eligibility before opting in; low traffic is not sufficient proof
  of public-mirror eligibility.
- A Spamhaus DQS key can be injected in memory from the encrypted store;
  query names and raw DNS errors never appear in findings. Do not serialize
  `Dependencies` or log resolver traffic. Each provider needs both positive and
  negative controls; refusal/error codes and unsupported IPv6 remain unknown.
- Two HTTP sources must agree on an egress IP before PTR/DNSBL queries use it.
  HTTP egress is not proof of the SMTP route. Both TCP address families are
  probed; connection failure alone does not establish ISP filtering.
- PTR/DNSBL direct-send issues are informational when assistant relay is
  enabled, because its upstream egress is a different system. A generic PTR
  name does not prove a dynamic address.
- SPF is a bounded static include/redirect analysis, not a complete RFC 7208
  evaluator or sender authorization check.
- DKIM checks only supplied selectors and public-key parsing, not sent-message
  signing or alignment; no guessed selector is shipped.
- Exact-domain DMARC does not evaluate organizational-domain fallback.
  Missing exact DMARC and absent explicit MX are informational because parent
  DMARC and implicit address fallback are not ruled out; null MX is explicit.
- MTA-STS and TLS-RPT are optional TXT checks only; HTTPS policies, certificates,
  MX coverage, report authorization and report delivery need separate checks.
- No direct inbound or phone compatibility claim is inferred from a tunnel.
  The product decision that an existing phone setup works is preserved.

Nine locale files provide `mail.diag.*` titles, explanations and actions.
Tests use only in-memory sources, resolvers and network results, with nil DSM,
KV and Secrets to catch accidental use of unrelated services.

## CSS evidence additions (2026-11-07)

There are now nine checks: the original seven plus `mail.diag.transport`
(six-hour schedule) and `mail.diag.access` (on demand for selected-client and
mailbox context). Every symptom runs transport first; account access is included
for send, receive, phone and unknown symptoms. Route findings sort before fix
recommendations. Provider-relay queued authentication failures use manual
MailPlus/provider guidance without handing off to a replacement setup.

`State.Transport` and `State.Access` are normalized integration inputs, not new
DSM transports. See `css.go` for their exported types and
`docs/mail-wizard-flow.md` under “Wave 3 changes from CSS” for every top-ten
decision and exact detection handoff. Missing observations yield informational
unknown findings. The adapter must independently confirm the affected client's
source and selected account; never substitute the administrator running the
wizard. Group control is context alongside authoritative effective activation,
not a locally recomputed activation rule. No account names, IPs, licence keys,
owner identities or provider error strings enter the new evidence types.

Licence counts come from `SYNO.MailPlusServer.License` `get_user_limit` v1 and
`get_active_user_num` v1 (added to `mail-read` in build 6). The
existing
`Domain.User/list/v1` inventory can provide `is_activated` and
`is_under_group_control`; home readability, licence ownership and Auto Block
need independently verified adapters. Their absence is an integration gap,
not permission to guess APIs. Tests use in-memory states and fake DSM only.
