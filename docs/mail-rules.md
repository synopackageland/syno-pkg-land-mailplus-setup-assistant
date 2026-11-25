> **Note (MailPlus Setup Assistant).** This is Syno Home Keeper's mail
> decision record (`docs/mail-wizard-flow.md` at `1a4fdb2`), kept as written.
> The decision table, adapter contracts and safety rules still hold. The step
> engine it names (`core.Wizard.Next`, `wizards.apply`, …) is replaced here by
> the browser-side UI SDK Wizard and the `mail.setup.*` operations: see
> [DESIGN.md](DESIGN.md) and [CONTRACT.md](CONTRACT.md).

# Mail setup decision tree

The product is Syno Home Keeper. This document is the mail wizard contract for
wave 1; `docs/CONTRACT.md` and `backend/internal/core/contract.go` remain authoritative.
Detection is read-only. All remote access is injected; this task performs no
NAS, Cloudflare, Gmail, browser or deployment acceptance.

## Flow and input

`intent → domain → detect progress → facts → branch → account/zone (if needed) →
exact permission manifest → branch-specific secret/address form → preview →
snapshot → apply progress → verify → keep / rollback`.

Intent is one of send, receive, both, diagnose, or check. The latter two hand off
to `mail.diagnose` immediately. Both computes the independent sending and receiving
branches and combines only their required changes. Changed intent/domain invalidates cached detection and preview; changed account,
zone or credential reference invalidates preview and verification. No write runs from `Next`.

Domain input precedes domain-specific probes when no domain has been selected.
This version configures no external inbound-25 probe: neither receive nor send
triggers one, and inbound reachability stays unknown ("Not checked by this
version"). The design reserves the probe for receive/both, behind explicit
consent, if an external vantage point is ever approved (no port-probe service
was approved; see the Home Keeper roadmap). A timeout, permission denial, missing adapter or malformed response is
unknown, never false, clean, configured, or successful. Show partial results even
when one probe fails. Static addressing needs explicit provider evidence; observing
one address repeatedly does not prove an ISP static allocation. A changed history
can establish changing addressing. DNSBL negative answers require positive and
negative provider controls, as in E4.

## Detection facts

| Area | Read / evidence | Interpretation |
|---|---|---|
| Package | `SYNO.Core.Package list v2`, additional status/installed_info | absent, stopped, running, broken or unknown; never install/start automatically |
| Capabilities | `SYNO.API.Info query v1` | require the researched version before a MailPlus read; API presence is not write acceptance |
| SMTP | `Service.SMTP get v1` | enabled and listener ports; no daemon-file reads |
| Domains | `Domain list v1`, offset 0, limit -1 | retain IDs and primary-domain status |
| Members | `Domain.User list v1`, bounded pagination per domain (the read chain holds one of the two slots, see `detect.DSMPassBudget`) | aliases plus activation; existing directory users only |
| Licence | `License get_user_limit v1` (`limit`) and `get_active_user_num v1` (`total`), verified on a test NAS (MailPlus Server 4.1.1-31785) | MailPlus Server's own counts across every domain, never this assistant's account list; known only when both reads answer with non-negative integers; a failed or unsupported read stays unknown with its cause and decides nothing; `License list` is not read (its entries' format is unverified) |
| Delivery | `SMTP.Delivery get_type/get_multiple v3`, default/sender/recipient | redact credentials; no password is returned by GET |
| DKIM | `Domain get_security v2` per domain | public selector/key only; signing needs delivered-message verification |
| Queue | `Queue list v1`, offset 0, limit 1 | total only; no flush, delete, retry or message reads |
| Network | E4 public egress, PTR/forward-confirmation, TCP 25, controlled DNSBL | bounded per-probe timeouts; TCP failure alone is unknown, not proof of ISP blocking |
| Inbound | none in this version (an injected external probe would run only for receive/both) | always unknown here; a local/hairpin connection never proves public inbound reachability |
| Tunnel | none in detection; the inbound plan reads the account's tunnels and their connections with the administrator's token | no tunnel creation, takeover or modification anywhere |
| Domain existence and zone | NS, A/AAAA (`LookupHost`), MX, TXT and CNAME (`LookupCNAME`) of the domain; when all are not found, one reply-code query (SOA, to the `/etc/resolv.conf` nameservers); then NS and CNAME of each parent label, down to two labels | exists when any lookup returns records or the name is an alias (a dangling CNAME too; a subdomain has records but no NS of its own, and Go's `LookupNS` says not-found for it). Go reports NXDOMAIN and NODATA alike, so "every lookup not found" is missing only when the reply code is NXDOMAIN without answers; NXDOMAIN with an answer (a dangling alias) exists; NOERROR without answers is unknown (an empty non-terminal answers so, but so does compact denial, RFC 9824, used by Cloudflare, NS1 and Route 53 for names that do not exist); anything else is unknown, as is any timeout or resolver failure without records elsewhere. The zone is the first name with NS records of its own: Go does not check an answer's owner name, so an alias is never a zone (its NS are the target's), and NS with an unknown alias check leave the zone unknown. Cloudflare-managed is decided from that zone's NS. No public-suffix list: the walk never asks a TLD but can reach a two-label name; a zone found there that may be a public suffix (`co.uk`, `com.tw`: a common second-level label under a two-letter TLD) is unknown, and a failed NS lookup on the way leaves the zone (and Cloudflare) unknown |
| Cloudflare-managed from the zone fact (Cloudflare route only) | the sealed token's `GET /zones?account.id=` (fresh, at detection, beside the DNS checks) and that zone's NS records (`GET /zones/{id}/dns_records?type=NS`, the apex's included); Zone Read and DNS read, both already asked for | the zone is the longest label-boundary suffix of the mail domain among the account's zones. Only `status: active` with `type: full` counts; any other status (pending, moved, deactivated…) or type (partial, secondary), a refused or failed read (the NS read included), or no token gives no zone fact and DNS decides as above. Limit: `active` means Cloudflare last saw the registrar's NS point at it; after a registrar change it becomes `moved` only after a while, so until then the zone still reads `active`, and a definite DNS answer that differs still wins (below). An NS record named the apex is multi-provider DNS (Cloudflare lists none for its own name servers; the registrar may also list another provider's): no zone fact. Below the apex, an NS record at the mail domain or at any name between it and the apex is a delegation (the parent's servers hand one out only from such a record): no zone fact. A definite DNS answer that differs stands: Cloudflare false from the NS records, a zone DNS found at another name, or no zone at all down to two labels. Otherwise (a DNS timeout, a name not in DNS yet, or agreement) Cloudflare-managed is true with the zone as evidence: the fact reads `mail.setup.value.cloudflare.yesZone` (`{zone}`), while a DNS-decided one reads `cloudflare.yes`/`cloudflare.no` (source: DNS name servers) |
| DNS | MX, TXT SPF/DKIM/DMARC | selectors from MailPlus or explicit input; never enumerate or assume a selector |
| Existing setup | injected independent verifier | record existence alone never proves delivery works |

## Branch precedence and full decision table

These rules run top to bottom. Package and configuration prerequisites apply to
both independent direction tables. Unknown MailPlus and DNS facts stop at an
explanation with a diagnose handoff. The send and receive path choice is
different: an unclear network fact, or any route but the confirmed own IP,
means the direct path is not usable, so the wizard takes the Cloudflare path
and says why (see [Path decision](#path-decision-route-and-checks)).

| Condition | Branch / next step | Planned changes | Never touched |
|---|---|---|---|
| Diagnose / check intent | hand off `mail.diagnose` | none | all resources |
| Package unknown or broken | inspect/diagnose first | none | package state |
| MailPlus absent | explain, open Package Center manually, stop | none | installation |
| MailPlus stopped | explain, administrator starts it manually, stop | none | start/stop |
| Licence known and `total` > `limit` (more active MailPlus users than licences) | `licenseShort`: hand off to MailPlus Server (add licences under License, or deactivate users under Account), then check again; comes before the other MailPlus prerequisites | none | licences, accounts, activation |
| Licence unknown | nothing: the decision continues as if the licence were enough | none | — |
| SMTP/domain/members unknown | resolve missing facts | none | existing configuration |
| Target domain absent (any intent), or no enabled mailbox on it (receive) | `configureMailPlus` prerequisite, shown right after the domain and before the route: names exactly what is missing (`mail.setup.prereq.noDomain` / `noMailbox`, with the domain); the administrator adds it in MailPlus Server; the wizard re-checks on coming back | none; no MailPlus write | primary domain, unrelated aliases/users, licences, DSM accounts |
| No enabled mailbox on the domain, intent both | sending is decided and set up alone; `receivePending` says receiving waits for a mailbox (receive verification needs one, sending does not); run setup again for receiving | send changes only | everything receive would touch |
| No enabled mailbox on the domain, intent send | nothing: sending needs no mailbox | — | — |
| SMTP off (and nothing above) | minimal configuration prerequisite | enable only SMTP automatically when that is the only missing prerequisite, then re-detect | primary domain, unrelated aliases/users, licences, DSM accounts |
| Entire selected intent independently verified correct | already correct, offer diagnose | none | all resources |
| Send independently verified correct | keep existing sending branch | none for send | existing relay and DNS |
| Send: the administrator chose and confirmed the own-IP route, and egress IP known, PTR present, FCrDNS pass, outbound 25 confirmed, every DNSBL clean, address not known to change | direct send | missing SPF, DKIM public record, DMARC only | MX, Delivery, relay service, inbound settings |
| Send, anything else: the Cloudflare route or no route; on the own-IP route a bad check (known changing IP, no PTR name, FCrDNS failure, confirmed blocked 25, a DNSBL listing) or a check that could not be done (egress IP, PTR, FCrDNS, outbound 25, DNSBL) | Cloudflare relay | onboard selected sending domain, provider-proposed DNS, relay configuration, MailPlus Delivery STARTTLS + AUTH + no fallback, disable signing on selected domain if enabled | unrelated domains, receiver validation DKIM, queues, other relay rules |
| Receive independently verified correct | keep existing receiving branch | none for receive | existing routing/MX |
| Receive: the administrator chose and confirmed the own-IP route, egress IP known (for the A record), address not known to change, inbound 25 not known blocked | direct receive | missing A/MX only, unproxied SMTP host | send SPF/DKIM/DMARC, Delivery, relay |
| Receive, anything else: the Cloudflare route or no route; on the own-IP route a known changing IP, a known blocked inbound 25 or an unknown egress IP | Cloudflare inbound | exact-address Email Routing → Worker → VPC Service → a healthy tunnel (Syno Connect's or the administrator's own) → MailPlus :25 on the NAS LAN IPv4 | catch-all, apex/unrelated mail routing, any tunnel's configuration |
| Both | combine send + receive independently | union of above, deduplicated; prerequisite/blocked branch prevents partial hidden application | settings needed only by neither branch |
| Direct branch, DNS not Cloudflare | manual DNS instructions | show required records and unknown host-address preconditions, no automated writes | external DNS host |
| Cloudflare branch, DNS not Cloudflare | explain moving selected DNS / choose viable direct path | none until explicit migration done outside this wizard | nameservers and non-Cloudflare DNS |
| Missing provider/relay/verification adapter | explain integration unavailable | none; no pretend success | all resources |
| Required DNS already exists but conflicts | explain conflict / diagnose | none; never replace user-owned RRsets or add a second SPF | existing DNS |
| Direct DNS already correct | already correct DNS, offer diagnose | none; DNS presence is not proof of deliverability | all resources |

## Path decision: route and checks

The `start` step only says where the domain comes from (`answers.source`):
typed by the administrator (Path A) or picked from the Cloudflare sign-in's
zones (Path B, "Use Cloudflare"). It decides no mail path. Both paths ask the
same route (Path B after choosing the zone), and `Decide` treats both alike.

The read-only detection starts as soon as the domain is chosen (it does not
depend on the route). MailPlus Server's side is decided first (see the table
above); only then does the wizard's `route` step ask how mail travels
(`answers.route`, build 32; it replaces the earlier Yes/No/Not sure questions
about the fixed IP and port 25 per direction):

- `cloudflare`, "Cloudflare receives and sends for me (recommended)": both
  directions take the Cloudflare path, whatever the checks say;
- `direct`, "Use my own IP to send and receive directly": only after the
  administrator confirms the requirements the step lists: a fixed public IP;
  for receiving, inbound TCP 25 reachable from outside with the router
  forwarding it; and, for sending, the outbound 25 and PTR results the NAS
  already detected (shown, with a warning when one of them is a problem or
  unknown). The step links an outside SMTP test (MXToolbox, with the detected
  public IPv4 filled in). The wizard never tests from outside and never reads
  that test's result: it is not a fact. A "not eligible" action switches the
  choice to Cloudflare.

No route yet (the first detection, before the route step) decides like
Cloudflare. Only `direct` can give a direct path, per direction:

- direct only on the own-IP route **and** when no check says otherwise;
- a check that came out clearly bad wins over the choice and forces the
  Cloudflare path for that direction;
- a check this version runs but could not complete is unclear, and unclear is
  not usable: Cloudflare path;
- a fact this version never checks (static addressing; inbound 25) is covered
  by the administrator's confirmation. Outbound 25 is checked from the NAS, so
  for sending the check must confirm it.

| Direction | Bad check (wins) | Not checked: the confirmation stands | Unclear check: not usable |
|---|---|---|---|
| Send | address known to change (`ipChanging`), PTR without a name (`ptrNone`), FCrDNS fails (`fcrdnsFail`), outbound 25 blocked (`outboundBlocked`), a DNSBL listing (`dnsblListed`) | static addressing | egress IP (`ipUnknown`), PTR (`ptrUnknown`), FCrDNS (`fcrdnsUnknown`), outbound 25 (`outboundUnknown`), DNSBL (`dnsblUnknown`) |
| Receive | address known to change (`ipChanging`), inbound 25 blocked (`inboundBlocked`) | static addressing, inbound 25 | egress IP (`ipUnknown`) |

The decision names its reasons. The Cloudflare route names one:
`routeCloudflare` (or `routeUnset` before a route is chosen). On the own-IP
route the reasons come in a fixed order: bad checks, then unclear checks. A
direct path names what it rests on: `routeDirect` and `sendChecksPass` for
sending, `routeDirect` for receiving. Each code is the catalog key
`mail.setup.why.<code>`; the branch view returns them per direction with the
path title `mail.setup.path.<branch>`, and the facts, stop and configuration
steps show them. A direction already verified correct is not decided again and
has no reasons. Changing the route re-decides from the same detection and
cancels a plan still being prepared; a plan is stored and applied only while
the flow still has the route, facts and decision it was prepared for
(otherwise `mail.setup.planChanged`, nothing written; the wizard offers to
generate the preview again).

A domain MailPlus Server does not have stops at the prerequisite before either
path is decided: the DNS, signing and relay facts a path needs are read again
once MailPlus has the domain, so that stop shows no path.

### Detection results

Each detection fact carries a `group` (`mailplus`, `network`, `dns`,
`cloudflare`), a `state` and `unrelated` (`setup/factview.go`). `state` is
`problem` for a definite negative (MailPlus Server stopped, missing or broken;
SMTP off; no domains; a licence shortfall; no enabled mailbox when receiving;
a changing address; no PTR name; FCrDNS failure; port 25 not reachable; a
DNSBL listing; no ready tunnel; an invalid record; DNS not on Cloudflare
unless the route is the own IP; the certain negatives `noDomain` and
`notInMailPlus`), `unknown` for any other cause, `notChecked` for "not checked
by this version", else `ok` (a missing record is `ok`: the plan adds it).
`unrelated` marks facts the chosen route and intent do not need: on the
Cloudflare route the egress IP, addressing, PTR, FCrDNS, DNSBL and port 25; on
the own-IP route the tunnel; port 25 out, PTR, FCrDNS and DNSBL only for
sending; inbound 25 and MX only for receiving; delivery, signing, SPF and
DMARC only for sending. Before a route is chosen nothing is unrelated. The
facts step shows `problem` and `unknown` rows first, by group, with a badge;
`ok` and `notChecked` rows fold under "N other items are fine", unrelated rows
under their own fold. Nothing is dropped.

What the decided plan creates is not a problem. A fact that says the
record, or the whole name, is not in DNS yet (`record.missing`, `noDomain`)
becomes `planned`, with a `noteKey` naming who creates it, when the decision's
`Needs` (the list the preview's changes are built from) cover it:
`cloudflare.inbound` → MX, SPF and the name (`mail.setup.planned.routing`);
`cloudflare.sending` → the name only (`mail.setup.planned.sending`: Email
Sending writes its own `cf-bounce` MX, SPF and DKIM under the name);
`dns.spf`, `dns.dmarc`, `dns.mx`, `dns.a` → that record and the name
(`mail.setup.planned.dns`). A stop, a hand-off or a MailPlus Server gap
(`Minimal`) plans nothing. On the Cloudflare relay an absent SPF or DMARC of
the name itself is `optional` (`mail.setup.optional.spfRelay`,
`mail.setup.optional.dmarc`): relayed mail is checked against Email Sending's
own records, and a subdomain without its own DMARC record falls under its
organisational domain's policy, which a new `p=none` record would only weaken
(`example.org` publishes `p=reject`). The Cloudflare route therefore adds no
DMARC record. The own-IP route (build 50) does the same when a policy
applies: detection reads the parent domains' `_dmarc` records up to the zone
(down to two labels when the zone is unknown) when the name has none of its
own (`DNS.ParentDMARC`); a valid parent policy makes DMARC `optional` and no
`dns.dmarc` step is planned; no parent policy keeps the `dns.dmarc`
(`p=none`) step, shown as planned; a parent lookup that fails is unknown and
waits for **Check again**, never guessed. Both states carry severity `info` and show in their own list
("No action needed from you"), each reason said once under its facts.

A plan that creates the MailPlus Server mail domain (`mailplus.domain`, not
stopped, build 52) warns about nothing only the new domain lacks: the
domain list is `planned` (`mail.setup.planned.mailplusDomain`), and the new
domain's accounts and DKIM (`notInMailPlus`) are `planned` and `unrelated`
(sending needs no mailbox and the Cloudflare relay signs itself; receiving
waits). Whenever receiving waits (`receivePending`), inbound 25, the tunnel and
MX are `unrelated`: this run does not set receiving up. The prerequisite step
then offers no hand-off to MailPlus Server and lists the domain as planned,
and the facts step asks for more evidence (`mail.setup.factsBody`) only for a
related fact whose `state` is `unknown`.

`setup/answers_test.go` covers every route (own IP, Cloudflare, none) crossed
with each direction's checks good, bad, unclear and not checked;
`setup/branch_test.go` the mailbox rule per intent; `setup/factview_test.go`
the groups, states and relevance.

The diagnosis does not choose a path, so it is unchanged.

## Branch forms and preview

Nobody types an account ID, a zone ID or a second token. Path B signs in to
Cloudflare right after `start` with one API token (pasted once, sealed at once),
then picks the account (only when there are several) and an active zone from
Cloudflare's own lists, with an optional one-label mail subdomain. Path A asks
for the domain, and signs in with the same token step only when its branch
needs Cloudflare; its account step shows the zone that holds the domain. The
same sealed token serves the setup calls and the relay's Cloudflare SMTP login
(username `api_token`, which needs Email Sending: Edit; read only once the
decision takes the relay). A permission Cloudflare refuses on the sign-in's
reads is named, and the token is replaced
through the create-token link (no upgrade flow). Direct manual DNS never asks
for a token.
The core must ingest `Field.Kind=secret` into `Env.Secrets` before persisting any
answer and replace it with its reference. This module refuses raw token answers.
Never put credentials in session state, preview, history, findings or errors.

Provider `RequiredPermissions` is local inventory with no network or credential
access. `Plan` returns exact public before/after records and the same permission
manifest before preview. Direct DNS requires Zone / Zone / Read and Zone / DNS /
Edit restricted to the selected zone. Sending requires Account / Email Sending /
Edit (API group `Email Sending Write`, E1); the SMTP token must be a separate
account-scoped sending-only credential, not a general provisioning token.
Inbound requires, besides Zone Read and DNS Write, exactly these API
permission groups (`setup.InboundPermissions`, IDs from
`cf user tokens permission-groups list`): Zone Settings Write
(`3030687196b94b638145a3953da2b699`, zone: Email Routing enable and read), Email
Routing Rules Write (`79b3ec0d10ce4148a8f8bdc0cc5f97f2`, zone), Workers Scripts
Write (`e086da7e2179491d91ee5f35b3ca210a`, account), Connectivity Directory
Admin (`77efc2c0724d4c4eb94bfd9656247130`, account: VPC Service) and Cloudflare
Tunnel Read (`efea2ab8357b47888938f101ae5e053f`, account). Each name is checked;
a count is never enough. There is no "Email Routing Settings" group. No R2 or
Queues permission: there is no spool.

Relay setup obtains a loopback listen address and generated AUTH credentials from
the relay adapter using encrypted secret references. Never preview credentials.
MailPlus default Delivery affects all default-routed senders, not only the chosen
domain: preview must explain this impact and block replacement of an unrelated
active default relay. Turn off only the selected domain's outbound DKIM signing,
never inbound DKIM validation (E5 saw Cloudflare Message-ID rewriting invalidate
MailPlus's signature). Preserve existing sender/recipient exception rules.

### Receive through Cloudflare

Nobody types or picks addresses. The plan takes every address of an
enabled MailPlus account of the selected domain from MailPlus Server's own list
(`SYNO.MailPlusServer.Domain.User list`, read by the detection;
`setup.Mailboxes`): exactly that domain, a plain local part, no `*`, `%` or
`!`, each once, at most 100. None is refused (the page says
`mail.setup.noMailboxes`; the prereq step normally stops earlier), more is
`mail.setup.rulesLimit` (per-address mode only). A request that still
carries typed addresses on this path is refused. The inbound path:

- **Two receiving modes (owner decision 2026-11-13)**, chosen on the
  configuration step (`receive`: `domain` or `addresses`, default
  `addresses` for an older client). `mail.setup.receivemodes` reads the zone
  and its catch-all with the sign-in token (no write) and says whether the
  whole-domain mode can be offered; the page preselects it when it can.
  - **Whole domain** (`整個網域自動收信`): the zone's catch-all points at
    this setup's Worker, so any address @domain reaches MailPlus and adding or
    removing users needs nothing. Cloudflare offers the catch-all on the zone
    apex only (docs, "Email Routing subdomains", read 2026-11-13; a literal
    `*@sub` does not match, the previous behavior), so the mode needs the mail domain to be
    the zone itself (`mail.setup.receive.subdomain`) and the catch-all to be
    unused, that is disabled or enabled with the drop action only
    (`mail.setup.receive.inUse`). Otherwise the option is shown disabled with
    that one line and a request for it is `mail.setup.receive.domainUnavailable`.
    The plan's `inbound.catchall` change keeps the catch-all as read
    (`CatchAllBefore`); the snapshot and the apply re-read it and write only
    while it is still exactly that and unused (a lost reply that finds it
    already ours writes nothing); a changed one is `stalePlan`. The rollback
    puts the snapshot back only while the catch-all is still ours (name
    `syno-home-keeper:<owner>`, one `all` matcher, one action to this owner's
    Worker); one somebody changed since is left as it is. A foreign catch-all
    is never written. No per-address rule is created, so the rules limit does
    not apply; the addresses only name the check mail's recipient.
  - **Chosen mailboxes** (`指定信箱`, the build 40 behaviour): one exact rule
    per address, below. Users added or removed in MailPlus later are brought
    in line by the Overview's **Sync mailboxes** (`mail.inbound.sync`), see
    "Kept setups and the mailbox sync".

- **SMTP target**: the NAS LAN IPv4 from DSM (`SYNO.Core.Network get v2`,
  `gateway_info`: connected, RFC 1918, not loopback or link-local); anything
  else is `mail.setup.lanUnknown`. It is read again when the VPC Service and
  the Worker are applied (also on a resumed apply); a different address is
  `stalePlan` and needs a new preview. Never `127.0.0.1`: MailPlus's Postfix
  trusts loopback and relayed to an outside domain in E3.
- **Relay prevention** rests on the Worker's domain guard and on the VPC
  Service being bound by this account's Worker only, not on Postfix. The Worker
  hands on a recipient only when its domain is exactly the configured MailPlus
  domain (case-insensitive) and its local part is a plain dot-atom without `%`
  or `!` (Postfix's percent hack and bang paths could rewrite such a local part
  into another destination); quoted local parts, source routes and a second `@`
  are refused. MailPlus is the final destination for that domain and decides
  whether the user exists (its 5xx is passed on as a rejection). A LAN
  range in MailPlus's relay networks would let Postfix relay mail the Worker
  hands it. The plan reads those networks (`SYNO.MailPlusServer.SMTP.RelayControl
  get v1`, `list_type: network`) and warns when any is configured
  (`mail.setup.inbound.relayNetworks`, the count) or when the read fails
  (`relayNetworksUnknown`). The entries' fields were never observed (the list
  was empty on a test NAS), so whether one covers the NAS is not judged.
  The preview folds this note and says no change is needed: the
  Worker's domain guard keeps every recipient inside the MailPlus domain, so
  a trusted network cannot turn the inbound path into a relay.
- **Tunnel**: any healthy tunnel of the account (`Cloudflare Tunnel Read`),
  including Syno Connect's (`synopkgconnect-*`, locally managed, HTTP ingress
  only: Workers VPC needs no ingress, E3). The tunnel itself is never changed.
  A tunnel whose every connection comes from the NAS's public IPv4 is used when
  it is the only one; none, several, or an unknown public IP returns the
  healthy tunnels for the administrator to pick (`PreviewView.tunnels`, a single
  Connect tunnel preselected). No healthy tunnel at all is
  `mail.setup.tunnelRequired` with the steps to get one. A match is a hint;
  only delivery verification proves it.
- **Binding**: one owned VPC Service (`syno-home-keeper-<owner>-smtp`, TCP 25,
  that IPv4), so the Worker reaches only that host and port; `connect()` needs
  an address argument but uses the registered target.
- **Delivery**: direct, no spool. The Worker accepts only after MailPlus's
  final 250; a MailPlus 5xx to MAIL, RCPT or DATA is passed on as a
  rejection; any other failure, a 5xx to the 220 greeting or to EHLO included
  (a refused session, not a refused message), throws, Cloudflare answers the
  sender `421`, and the sender retries on its own schedule. A lost 250 can make the sender send the message again.
- **Rules**: one exact rule per address to the Worker. Conflicts
  (`mail.setup.routingConflict`) are only: (a) MX/SPF on a domain without
  Email Routing that are not Email Routing's own (flagged
  `meta.email_routing`, or an SPF TXT exactly
  `v=spf1 include:_spf.mx.cloudflare.net ~all`), and (b) a rule for a
  requested address whose action is not this package's Worker. A domain that
  already has Email Routing (for example after a rollback, which keeps it) is
  reused with its records. A rule this package left for a requested address
  (`syno-home-keeper:<owner>` to that owner's Worker, another owner: an
  earlier setup that was kept) is **taken over** only when it cannot belong to
  another NAS's live setup: that owner's VPC Service
  (`syno-home-keeper-<owner>-smtp`) is missing, or points to this NAS's LAN
  address over the same tunnel; otherwise it is `mail.setup.routingLeftover`
  (manual cleanup in the Cloudflare dashboard; never taken over). A disabled
  one is `mail.setup.routingLeftoverDisabled` (refused, not taken over: kept
  disabled the address would receive nothing). The rules step re-reads it
  and, only in that exact shape, points it at this setup's Worker and name
  (address, priority and enabled state kept); the preview says so; rollback
  gives it back to the earlier owner. Zone rules plus new addresses (taken-over
  ones counted once) over 200 are `mail.setup.rulesLimit`.
- **Mail domain depth**: any depth under the zone is planned the same way;
  only one level under the zone was verified live.
- **Rollback**: removes the rules, Worker and VPC Service of this owner only
  and restores the catch-all (whole-domain mode, above). Email Routing enable
  and Cloudflare's locked MX/SPF stay (the API can only disable a whole zone);
  the preview says so. Undoing the rules or catch-all step also clears the
  setup's inbound record (`mail.wiring inbound.<domain>`), so the Overview never
  lists a setup that is gone.
- **SPF, a fact**: MailPlus computes SPF against the tunnel's LAN source (the
  NAS's own address with cloudflared on the NAS; E2 and E3 show
  `Received-SPF … client-ip=<LAN IP>`), so a sender with an SPF record gets
  softfail (`~all`) or fail (`-all`). **Unknown**: whether that crosses the
  spam threshold, and whether MailPlus's SPF rejection turns a fail into a
  5xx, which the Worker passes back to the sender as a rejection. The Workers
  Free plan is unverified (tested on Workers Paid only). No trust-network or
  anti-spam change.
- **Delivery evidence**: a `complete` TransactionLog entry at or after the
  first check whose `ori_rcpt` holds the routed address (case-insensitive) and
  whose `src_ip` is the VPC target, matched by the check mail's Message-ID or
  by the code in the subject. A missing or different recipient or source is no
  evidence, so a tunnel that does not run on the NAS host network never
  verifies. The log is read newest first in pages of 50 back to the check's
  start; more than 500 newer entries leave delivery unknown.
- **EHLO**: the Worker greets MailPlus with the mail domain; whether MailPlus
  scores that name is unverified.

### Kept setups and the mailbox sync

Keeping a setup that changed anything on Cloudflare records it (KV
`mail.kept/setup.<flow>`): domain, account, zone, the journal of applied
changes with their snapshots, the receiving mode and owner, and the reference
of the setup's sealed Cloudflare token, which the record owns from then on
(the flow no longer drops it). A setup with no Cloudflare change is not
recorded and its token is dropped as before. Rolling back deletes the token as
before. The token never appears in a record, reply or log.

`mail.inbound.status` lists the kept setups from the package's own records
only (no DSM or Cloudflare call, no write), with the last sync of each (worker
memory). A build ≤40 per-address setup (only its `mail.wiring inbound.<domain>`
record) is listed too, as a legacy setup with no token; it syncs only while the
zone still holds at least one of its rules (else `mail.inbound.cause.gone`).

**Sync mailboxes** (`mail.inbound.sync`, per-address setups only) syncs now
when the administrator presses it; the automatic sync (below) does the same
on its own. One press starts one background
run (`core.Background`, budget `detect.DSMPassBudget` + 2 min) unless one runs;
the call waits up to 8 s and the page asks again (`poll`) while it still runs.
The run:

1. reads the domain's MailPlus accounts (`SYNO.MailPlusServer.Domain.User
   list`, the setup's filters, `setup.Mailboxes`); a read that is not definite
   changes nothing (`mail.inbound.cause.mailplus`);
2. lists the zone's routing rules once;
3. deletes this owner's exact rules (`syno-home-keeper:<owner>` to its Worker)
   for addresses that are no longer mailboxes, then
4. adds an exact rule for each mailbox without one. A mailbox that another
   rule routes stays pending (`conflict`; the foreign rule is never touched),
   as does one over the zone's 200 rules or the run's cap of 100 writes
   (`limit`), or whose write failed (`failed`). Over 100 mailboxes, the rest
   stay pending.

It is idempotent (a run in line writes nothing) and logged
(`inbound mailbox sync`: domain, state, added, removed, pending, cause). A
refused write or an unusable token is `mail.inbound.cause.token` and the page
asks for a token: `mail.inbound.token` verifies a pasted token (active, and
able to read the zone's rules; for a send-only setup, the zone), seals it under the record's own name and drops
the old one; an empty token forgets it. No token at all is
`mail.inbound.tokenRequired`. MailPlus and DSM offer no documented change
signal for users (not verified, moderate confidence), so the automatic sync
polls the same read instead.

**Automatic sync** (build 50, owner decision 2026-11-16: a new
MailPlus user received nothing until someone pressed the button). The worker
checks every per-address setup about every 10 min (`AutoInterval`), and again
when the Overview opens if its last check is a minute old. Each run takes the
setup's lock (a manual sync or a removal of the same setup never runs beside
it) and re-reads the record (a removed setup is never synced). Guards, each
tested (`autosync_test.go`):

| Situation | What the automatic run does |
|---|---|
| MailPlus stopped, upgrading, restarting; package read not definite | nothing on Cloudflare; `failing`, retried with back-off (20, 40, 80 min… at most 2 h) |
| Account read fails or times out | the same (`mail.inbound.auto.cause.mailplus`) |
| Access waits for approval | the same (`…auto.cause.approval`) |
| Empty mailbox list | nothing on Cloudflare (`…auto.cause.empty`); the Overview says 同步信箱 would remove the setup's N rules |
| Reply shape changed: API version not offered (`api_unsupported`), incomplete reply, undecodable DSM reply, API missing | `stopped` (`…auto.cause.changed`): no further automatic read until a manual sync succeeds or the worker restarts; never guesses |
| Mailbox set unchanged (hashes kept on the record, `synced.set`) | no Cloudflare call; a full reconcile at most every 6 h (`AutoReconcile`) |
| Set changed | the manual sync's Cloudflare run, adding freely; removing at most max(2, 1/5 of the setup's rules), else no removal at all and the Overview says 同步信箱 will remove N (`held`) |
| Token refused or missing | `failing` with `mail.inbound.cause.token`; the existing re-entry state; no Cloudflare call while it is marked invalid |

It uses only the read the setup and the manual sync use
(`SYNO.MailPlusServer.Domain.User list v1`, through `ReadAccounts`, `mail-read`
with the worker's shared background grant) and no other API. The state
(`auto` in `mail.inbound.status`: state, cause, unsynced, held, checkedAt)
lives in worker memory; the record keeps only the counts and the hashed set.
A successful manual sync clears failures, a stop and a hold. Logged as
`inbound mailbox auto sync` (domain, state, cause, counts; no address).

**Minimal Cloudflare permissions for the sync**: Email Routing Rules Write
(zone) only. Listing rules accepts Read or Write, and creating or deleting a
rule needs Write; the sync makes no zone read. The kept token is the setup's
sign-in token, which has more (the setup's list, `frontend/src/api/cloudflare.ts`);
the removal needs more, below.

### Removing a kept setup (build 42)

**Remove Cloudflare setup** (`mail.cloudflare.remove`, Overview, confirmed in
a dialog) undoes exactly what the kept setup applied and nothing else. It walks
the record's journal newest first through the setup's own rollback
(`setup.Wizard.RollbackChange`, the same code as the decision step's
rollback), so it touches only what the journal proves this App created: the
recorded rule, Worker and VPC Service IDs (each also checked for the owner
marker), the catch-all only while it still equals what the setup wrote
(restored to its snapshot, else left alone and the step counts as
`mail.remove.cause.changed`), the recorded Email Sending and DNS changes (with
the `_dmarc` record Email Sending added, see below), the
MailPlus settings back to their recorded pre-setup values, and the relay
turned off with its copy of the token deleted. Foreign resources are never
written. A resource already gone counts as done.

- **`_dmarc` that Email Sending added (build 52).** Enabling a name
  in Email Sending adds `_dmarc.<name>` (`"v=DMARC1; p=reject;"`, listed in
  its preview) and deleting the sender leaves it. Onboarding records in the
  sending receipt (the ledger) whether any `_dmarc.<name>` record existed just
  before, and the content the preview listed. Rollback and removal delete it
  only when none existed before and the name now holds exactly one record, a
  TXT whose content is unchanged (quotes and surrounding spaces aside), not
  locked; anything else, and every receipt from before build 52, keeps it.
  A sender already gone still gets this check, so a retried rollback finishes it.
- Cloudflare steps use the setup's **current** token (the record's; it may
  have been replaced on the Overview) for the journal's sign-in token
  reference. The relay is turned off directly (`relayAdapter.relayOff`): its
  own rollback compares its token with the journal's, which no longer matches
  after a replacement.
- Each undone step is dropped from the record and saved at once. A run that
  stops (refused permission, a changed resource, a NAS write that failed, an
  interruption) keeps what is left; pressing again goes on from there and
  never repeats a done step. At the end the sealed token is deleted and the
  record cleared, so the setup leaves the Overview.
- Email Routing on the zone, the apex's locked MX/SPF and every other DNS record
  stay as they are (a subdomain's receiving records: below), **unless** this setup enabled Email Routing on the zone apex
  itself (the journal's `routing` step, no subdomain): then the dialog offers
  the unticked option 「同時關閉此網域的 Cloudflare 收信」 and says what it
  changes (Cloudflare stops accepting any mail for the domain and deletes the
  MX and SPF records it added for receiving). Ticked, the run calls
  `DELETE /zones/{zone}/email/routing/dns` (Cloudflare's documented "Disable
  Email Routing"; nothing when already disabled) before undoing the routing
  step. `routing: true` for a setup that did not enable it is `bad_request`.
- **A subdomain's receiving DNS (build 46).** Turning receiving on for
  a subdomain (`POST /zones/{zone}/email/routing/dns {"name": sub}`) makes
  Cloudflare add three MX records (`route1–3.mx.cloudflare.net`, read-only,
  `meta.email_routing`) and the SPF TXT `v=spf1 include:_spf.mx.cloudflare.net ~all`
  at that name. Cloudflare documents no per-subdomain
  "disable": `DELETE …/email/routing/dns` takes no name and turns Email
  Routing off for the whole zone, and its unlock (`PATCH … {name}`) is
  documented for the zone apex only. So the App keeps a **ledger**
  (`mail.wiring` KV, `routingdns.<domain>`): before enabling it lists the MX
  and SPF records at the name, after enabling it lists them again, and records
  the IDs that appeared (created) and the pre-existing ones whose content
  changed (before/after). Removal deletes exactly the created IDs with
  `DELETE /zones/{zone}/dns_records/{id}` — MX first, then the TXT, each only
  while it still equals what the ledger recorded (changed since: left alone)
  — and puts a changed pre-existing record (for example an SPF the
  enable merged into) back to its recorded content with `PUT`, only while it
  still holds what the enable left. Records that were there before are never
  deleted. A record already gone counts as done. Cloudflare refuses the
  delete of a routing MX it manages: on a test NAS (2026-11-13)
  `DELETE dns_records/{id}` on each of a subdomain's route1–3 MX returned
  HTTP 400 `{"code":1046,"message":"This record is managed by Email Routing.
  Disable Email Routing to modify/remove this record."}`, while the SPF TXT
  (no `meta.email_routing`) was deleted (200). Cloudflare's docs say only the
  apex's routing records can be unlocked and give no way to remove one
  subdomain's. So (owner decision, build 48) a record refused with 1046 is
  left in place, not a stop: the SPF and everything else are removed, the
  ledger is cleared and the removal is done; the result (`RemoveRun.locked`,
  with `accountId` and the zone's `zone` name read once for it) lists the
  records left, and the page says so plainly and links to Cloudflare's Email
  Routing page of the account in a new tab
  (`https://dash.cloudflare.com/?to=/<account>/email-service/routing`, the
  documented `?to=/:account/email-service/routing` with the account filled
  in; developers.cloudflare.com/email-service/configuration/domains/ and
  …/subdomains/, read 2026-11-13: select the apex domain, then Settings),
  warning that turning Email Routing off there may stop receiving for the
  whole domain. The refusal `mail.remove.cause.locked` is gone. Untested and
  not used: the OpenAPI schema gives `DELETE …/email/routing/dns` the same
  optional `{name}` body as the enable (a call that ignored the name would
  turn off the whole zone).
  The dialog lists 「設定時 Cloudflare 為此子網域加上的收信 MX 與 SPF 紀錄」 only
  when a ledger exists. Setups kept before build 46 have no ledger, so their
  subdomain records stay. Because a subdomain stays listed as enabled after
  its records are gone, planning and the enable step treat it as enabled only
  while Email Routing's MX **and** SPF exist at the name (build 47; build 46
  looked at the MX only, so after a removal that left the locked MX and
  deleted the SPF, the next setup skipped the routing step, wrote no ledger
  and left the SPF missing). Otherwise it enables routing again, which adds
  back what is missing, and the ledger records the MX it found as before
  and the SPF as created.
- **Sealed operations.** Each planned change seals its operation
  under the references in its parameters (`operationRef`, `credentialRef`,
  with `.user`/`.pass`/`.attempt`/`.receipt` derived from them). They live as
  long as something can read them: a flow that is fully rolled back deletes
  its plan's, and a removal deletes each step's right after the step is undone
  and dropped from the record. A kept setup keeps its operations and token
  until it is removed. Values sealed by builds ≤45 for flows already rolled
  back or removed are swept once (build 47, `mail.SweepOperationSecretsOnce`):
  at its first start the worker, before it serves anything, deletes every
  value under an operation family (`secret:mail.setup.operation.`,
  `secret:mail.wiring.cloudflare.|credentials.|relay.`) that no kept
  record's remaining steps and no flow other than a rolled-back one (or a
  kept one whose record exists) refers to. Tokens and the relay's values are
  never in those families. A record it cannot read stops it before any
  delete; the `core.sweep` marker is written only after it succeeded. It logs
  counts only. A second one-time sweep (build 48, `mail.SweepFlowTokensOnce`,
  its own marker `flowTokens.v1`) deletes the flows' sign-in tokens
  (`secret:mail.setup.<flow>.token[.<gen>]`) that no kept record's `tokenRef`
  and no unfinished flow's sign-in (any phase but kept and rolled back) refers
  to, with the same rules; the relay's token and credentials, build ≤44
  `secret:mail.kept.` tokens and operations are never in that family.
- **After a removal** the Overview reads the relay's state again
  (`mail.relay.status`), so its card shows the relay off once the removal
  turned it off (build 47 kept showing the state read when the page opened).
- A build ≤40 receiving setup (no journal) removes only resources carrying its
  owner marker (its rules, Worker, VPC Service) and clears its inbound record.
- Causes: `mail.inbound.cause.token` (403/401 or a refused permission: the page
  asks for a token, guided like the setup), `mail.inbound.cause.cloudflare`,
  `mail.remove.cause.changed`, `mail.remove.cause.nas` (MailPlus or relay),
  `mail.remove.cause.record`, `mail.inbound.cause.interrupted`. One background
  job per setup, budget `(steps + 3) × 2 min`; the call waits up to 8 s and the
  page polls with `poll`. Logged as `cloudflare setup removal` (domain, state,
  done, total, cause, locked count); the token never appears.

**Minimal permissions for one kept token that covers Sync and Remove** (the
token's account and the setup's zone):

| Permission | Scope | Needed for |
| --- | --- | --- |
| Zone Read | zone | checking a replacement token of a send-only setup |
| Email Routing Rules Write | zone | sync; removing the rules or restoring the catch-all |
| Workers Scripts Write | account | removing the inbound Worker |
| Connectivity Directory Admin | account | removing the VPC Service |
| Email Sending Write | account | removing the sending setup (only if sending was set up) |
| DNS Write | zone | removing the DNS records the setup added, and a subdomain's receiving MX/SPF (only if it added any) |
| Zone Settings Write | zone | only the optional "also turn off Cloudflare receiving" |

The setup's create-token link already fills all of them (plus Tunnel Read,
used only by the setup), so a sign-in token kept from the setup covers both.

**Uninstall**: the SDK's uninstall wizard
(`dsm-package.yaml` `uninstall`) takes only fixed options (data to delete,
root purge); it has no free-text note, and listing the Cloudflare setup as
"data" would claim uninstall removes it. So the note 「解除安裝不會移除這些設定；要撤銷請按「移除」」 ends the
Overview section's description, and the remove dialog repeats it (build 44).

Preview lists every write with a stable ID, exact resource, before, after, and
permission manifest. No vague “configure everything” operation is executable.
The provider planner must reject foreign resources and resolve generated DNS
values before presenting preview. Once preview exists, apply uses that exact plan;
changing any form invalidates it and requires fresh detection and preview.

### A refused Cloudflare token (build 44)

The administrator may delete or roll the token in Cloudflare's dashboard. One
kept setup has one token, used by the relay's SMTP login to
`smtp.mx.cloudflare.net:465` (the relay's own sealed copy), Sync mailboxes,
Remove Cloudflare setup (the journal's sign-in reference is answered with the
current token) and the diagnosis's Email Sending read. Nothing polls; each
place notices a refusal where it already calls Cloudflare:

- the relay: an upstream AUTH refused with a 5xx (535 and the like) marks
  every kept setup that uses the relay and holds a token; the next accepted
  AUTH clears it. The last state is kept in memory, so the steady state costs
  no store access, and a record is written only when its state changes.
- Cloudflare API calls (sync, removal, diagnosis): a 401/403 or a token code
  is confirmed with the verify endpoints (user, then the setup's account);
  only a verify that refuses the token marks it. A 403 with an active token is
  a missing permission, not a dead token. A successful sync clears it.

The state is `tokenInvalid` on the kept record (no secret), logged as
`cloudflare token state` (domain, invalid). The Overview shows 「Cloudflare
權杖已失效（可能已被刪除），寄信與同步暫停」 with 「重新輸入權杖」; the diagnosis
adds a critical `token_invalid` finding per domain (problem action `token`,
the same button). Both open the setup's guided token entry.

**Queued mail is kept.** MailPlus (Postfix) hands mail to the relay; while the
upstream login is refused the relay answers DATA with `451 4.7.0` (any other
upstream failure `451 4.4.0`), never 5xx, so MailPlus keeps the mail deferred
and retries it with its back-off until its queue lifetime ends: MailPlus
Server 4.1.1 sets `maximal_queue_lifetime = 48h` and `bounce_queue_lifetime =
48h` in its `main.cf` (read on a test NAS, the previous behavior), so mail waits up to 48 hours
and then bounces to the sender. The Overview's hint says so. Verified live
In a live check, with a refused token the relay answered `451 4.7.0 Upstream login
refused`, the mail stayed deferred, and after the token was replaced it left
at MailPlus's next retry with no manual flush. The relay reads its
token for every message, so the retry after a replacement logs in with the
new token; no restart is needed.

**One replacement fixes everything** (`mail.inbound.token`): the new token is
verified active, then each permission the kept setup needs is checked with a
read (Zone Read: the zone; DNS: the DNS records; Email Sending: the sending
subdomains; Routing Rules: the rules; Workers: the scripts; Connectivity
Directory: the VPC services). A read cannot prove a write; a refused write is
still named when the sync or the removal runs. All missing permissions are
named together. Accepted, it is sealed under the record's reference, the
relay's copy is replaced when the setup uses the relay and the relay holds a
token, and `tokenInvalid` is cleared. A setup flow whose rollback Cloudflare
refused enters the new token on its decision step (`mail.setup.cloudflare`
replaces the flow's sign-in in place).

## Snapshot, verify and rollback

The engine calls `Snapshot` before every `Apply`, journals the applied change,
and calls `Rollback` in reverse order. Adapters receive only the exact previewed
change and secret references. Snapshot payloads are public resource data and
opaque encrypted snapshot references; no credential values. Preserve MailPlus
Delivery IDs and require a demonstrably restorable password strategy before
modifying authenticated rows: GET cannot recover the old password. If this cannot
be guaranteed, block before any write. Rollback uses compare-before-restore and
resource ownership checks; external drift stops rollback rather than overwriting
another administrator's work. Delete only resources created by this session.
A lost write reply is reconciled by stable change ID, never blindly retried.

**Refusals say their reason.** A plan or write refused as unsafe
returns `unsafe_plan` with one specific reason key
(`mail.setup.unsafe.<code>`), never the generic sentence:

| Code | When |
| --- | --- |
| `zoneMismatch` | the token's zone is not the domain's, or is in another account |
| `inboundExists` | a receiving Worker or VPC Service with this App's name exists that this setup did not create |
| `sendingDns` | Email Sending reports a problem with the domain other than missing records |
| `egressUnknown` | the NAS's public IPv4 is unknown, so the SPF or A record cannot be written |
| `dkimUnknown` | MailPlus Server's DKIM selector or key for the domain is unread |
| `dnsExists` | a record the plan adds already exists with other content (or as a CNAME) |
| `relayInUse` | the forwarding service already runs or holds a token |
| `mailplusReply` | a MailPlus Server reply this App cannot read safely |
| `savedRecord` | the journal, kept record or sealed operation does not match what is found |
| `planCheck` | the plan no longer matches the current settings or misses a reference |
| `secret` | a snapshot would carry a secret, or a sealed value could not be read back |

A MailPlus write refused for a missing DSM grant ends the flow with
`authority_required:<profile>` and `failedStep` (the change ID). The wizard
names the step (its action text) and the access (「MailPlus 變更權」), says
whether earlier changes were put back, and offers Allow access; it shows no
DSM code.

Verify reads back every exact change and uses injected delivery evidence for the
selected intent. Queue size zero, DNS presence and provider “dropped, worker” logs
are not delivery receipts. Missing or failed verification never shows success.
The result offers keep or rollback even on verification failure. Keeping a failed
verification is explicitly recorded as unverified, with a diagnose handoff.

## Integration boundaries

`detect.Detector` exports typed `State` and timeout-isolated probes for diagnose.
`setup.Wizard` implements `core.Wizard` and `core.Applier`; `setup.CloudflareClient`,
`setup.Relay`, `setup.MailPlus`, and `setup.Verifier` isolate remote effects.
`mail.New` accepts injected checks/services/wizards so parallel packages need not
exist at compile time. Core owns the operation registry and module registration.
See exported Go interfaces for exact method signatures. No core contract edits
are made by this thread.


## Implemented integration contract (2026-11-07)

Rebased onto main containing contract commit `4c8b1e9` and relay PR #1.
Result steps populate `Step.Outcome` (`ok`, `failed`, `rolledBack`). Detection
progress has indeterminate `Done=0, Total=0`; it starts immediately and polls
without tying the read-only job to the poll request’s cancellation.

| Step ID | UI answer |
|---|---|
| `intent` | string: `send`, `receive`, `both`, `diagnose`, `check` |
| `domain` | form object: `{domain}` |
| `detect` | no answer, poll |
| `facts` | `true` |
| `blocked` | choice string: `retry` or `diagnose` where offered |
| `account` | form object: `{accountId, zoneId}` |
| `configuration` | form object: `{tokenRef, smtpTokenRef?, addresses?}` after secret ingestion |
| `already` | choice string: `done` or `diagnose` |
| `preview` | call `wizards.apply`, never `Next` to write |
| `decision` | choice string: `keep`, `rollback`, `diagnose` |
| `rollback` | result with instructions to call `wizards.rollback` |
| `kept`, `done`, `rolledback` | terminal result with typed outcome |

`setup.New(setup.Options{Detector, Cloudflare, Relay, MailPlus, Verifier})` is the
constructor. `detect.New()` supplies real DNS/HTTP/TCP adapters but does no work
until `Detect` is called. Optional `detect.Extensions` would supply authoritative
static allocation, external inbound reachability, Connect status and
independent readiness evidence (licence counts are a DSM read since build 6). Production sets none in this version, so those
facts are unknown ("Not checked by this version"), never a fallback API guess.
In particular no external inbound-25 probe runs for any intent. Existing account enumeration is bounded to 1,000 members
of the chosen domain and follows the reported total rather than page length.

Exact parallel-thread interfaces:

```go
// setup.CloudflareClient
RequiredPermissions(PlanRequest) ([]Permission, error) // local inventory only
Plan(context.Context, core.Env, PlanRequest) (Prepared, error)
// setup.Relay
Plan(context.Context, core.Env, PlanRequest) (Prepared, error)
// setup.MailPlus
Plan(context.Context, core.Env, PlanRequest, []core.Change) (Prepared, error)
// all three embed setup.Writer
Snapshot(context.Context, core.Env, core.Change) (json.RawMessage, error)
Apply(context.Context, core.Env, core.Change) error
Rollback(context.Context, core.Env, core.Change, json.RawMessage) error
// setup.Verifier
Verify(context.Context, core.Env, PlanRequest, []core.Change) (Verification, error)
```

`Prepared.Restorable` must be true, every change must name the selected `domain`
in Params, and each write needs exact nonempty before/after values. DNS-only
plans are restricted to the required DNS action keys and each missing record
must be covered. Direct sending must not modify MX or receive policy. Cloudflare
inbound must explicitly plan routing, Worker and VPC. Adapters must return the
nine-locale `mail.setup.change.*` keys shipped here (or add translations).

The wizard binds each exact change to a session/plan and persists it under
`Env.KV` namespace `mail.setup`, key `change.<canonical digest>`. It writes a
possibly-delivered marker before dispatch; retries retain the original change
ID and require the adapter to reconcile. Only durable snapshotted changes can
apply. Snapshot JSON is size-bounded and obvious credentials/known token values
are refused. An apply reply loss leaves the journal uncertain, never successful.
The engine must include that in-flight snapshot when it offers rollback.

`setup.NewMailPlus()` is the concrete researched MailPlus adapter. It supports
SMTP-only enabling with every existing listener/account setting preserved,
outbound DKIM disable on the chosen domain only, and Delivery from an empty,
disabled default relay to the new loopback STARTTLS+AUTH route with no fallback.
It refuses existing default rows because GET cannot recover passwords. It keeps
sender/recipient lists untouched. Settings and operation specifications live only
in `Env.Secrets`; public snapshots contain encrypted references and hashes.
A partial Delivery write is reconciled by reading back the created host before
activating it; replay does not resend credentials. Rollback refuses external drift.

For relay planning, the `homekeeper.relay` change must include public Params
`domain`, `listen` (literal loopback IP:port), `starttls=required`, `usernameRef`,
and `passwordRef` (both encrypted secret references). Core’s DSM transport must
implement the additional local `setup.ConfidentialDSM.CallConfidential` method
with the same signature as `DSM.Call`; Delivery credential writes are refused
without this protected-payload transport. No raw credentials go through `DSM.Call`.

The existing relay service has its own native secret keys
`mail.relay.credentials` and `mail.relay.cloudflare-token`, port KV
`mail.relay/port`, and methods `Credentials`, `ListenAddr`, `TestUpstream`.
An integration adapter must bridge the wizard’s credential references to those
native keys and the core service host’s enable/disable operation; this module
does not start an unsupervised duplicate relay. `TestUpstream` verifies TLS/AUTH,
not delivery, so it cannot satisfy `Verification.Delivery` on its own.

## Explicit limits for this wave

- Cloudflare, relay planning/service control and actual delivery verification
  require adapters from the parallel modules/coordinator; absent adapters stop
  before token forms or writes, rather than returning pretend success
- Domain/member/licence onboarding is a manual MailPlus prerequisite, with a
  working retry that discards old detection and starts a fresh read-only job
- Keeping an SMTP-only prerequisite change finishes that stage; reopen setup to
  select the subsequent DNS/relay stage, retaining the core’s rollback history
- Core must convert secret form fields to `secret:` references in `Env.Secrets`
  **before** persisting answers; the wizard rejects raw credentials but cannot
  undo a secret already saved by its caller
- The current Step contract has no Package Center navigation/link action, so
  missing/stopped packages receive localized Package Center instructions
- No guaranteed delivery, ARC trust policy, offline retention or subscription
  support is inferred from the historical experiments (the whole-domain mode,
  uses Cloudflare's documented apex catch-all, not those experiments)
- Global packaging checks remain subject to the coordinator-owned SDK pin fix;
  local Go results do not establish SPK, NAS or end-to-end acceptance

Manual DNS instructions mark the proposed SMTP host A record’s previous value as
unknown because that hostname is not independently enumerated by detection; review
it at the existing provider and never overwrite an existing host blindly.

## Wave 3 changes from CSS

**Add now** describes read-only logic in
this change, not a claim that an unavailable adapter or NAS read has been
implemented. **Needs setup/detect** specifies follow-up outside the diagnosis checks. Confidence is high in the implemented branch logic and the saved
field shapes; runtime access and uncaptured response shapes remain unknown.

### Mail top ten

| # | Decision | Implemented behavior or exact setup/detect change |
|---|---|---|
| 1 | Add now | `mail.diag.transport` shows separate selected send, receive and client hops before recommendations; accepts direct/provider/Home Keeper send, direct/forwarded receive and web/IMAP/submission client observations, and shows unknown for absent or invalid observations |
| 2 | Add now for diagnose; needs setup/detect for provider onboarding | Provider relay failures use manual MailPlus Delivery/provider instructions, including application-password requirements, without a setup handoff that replaces the relay; add a setup intent choice `host-domain` versus `existing-provider`, preserve the detected default and exception routes, then branch authentication refusals to provider requirements before considering a new relay |
| 3 | Needs setup/detect | Extend DNS detection with distinct public and NAS resolver observations plus authoritative nameserver ownership, using the same domain/record type and observation time; if public succeeds and NAS fails, branch to NAS resolver/internal-zone guidance without a public DNS write; a single `net.Resolver` result must not populate both views |
| 4 | Add now for diagnose evidence | `mail.diag.access` consumes authoritative selected-mailbox activation, home readability and Auto Block status for the affected client source; missing evidence is informational unknown, not an account pass; do not use the diagnosing administrator's address or trust a forwarded header as the client's IP |
| 5 | Add now for diagnose evidence | Effective activation and `GroupControlled` are separate observations, so group policy is explained without computing activation by OR-ing flags; licence counts and owner comparison are separate, owner mismatch goes to MailPlus Server > License (self-serve; never "contact support"), and no identity or licence key is persisted |
| 6 | Needs setup/detect | Before offering migration, detect model/package compatibility independently of installed/running state; branch absent-compatible-package to Package Center/model guidance, stopped to manual start, and copied-mail/settings-failed/delivery-failed to distinct migration recovery stages; preserve source mail and never infer unsupported-version from a delivery failure alone |
| 7 | Needs setup/detect beyond existing DNS checks | Preserve the existing duplicate-SPF and configured-selector checks; extend the independent delivery verifier with correlated receiver SPF/DKIM/DMARC alignment and forwarding-hop results, keyed to the selected sending route; distinguish absent/invalid/unaligned signatures, show unknown without receiver evidence, and block policy changes based only on TXT presence or a blanket ARC workaround |
| 8 | Add now for diagnose; needs detect endpoint observations | Selected IMAP/submission failure alongside successful web access yields a protocol-path finding; working web access cannot establish raw-mail protocol reachability; detector must observe hostname/protocol/port/address-family and LAN/WAN vantage separately, then offer the already verified web/mobile route without claiming tunnel support for raw TCP |
| 9 | Needs setup/detect | Keep assignment-expiry diagnostics, but bind additional TLS observations to the actual selected hostname, protocol, port and HA endpoint with served chain, hostname verification, expiry and timestamp; DSM default/assignment metadata alone must not satisfy this endpoint check or trigger a global TLS profile change |
| 10 | Add now by preserving bounded queue diagnostics; needs detect/verifier for trace | Retain complete-queue oldest-time requirements, age and allowlisted failure categories without purges/replays; for existing relays, authentication findings preserve the relay; add a user-authorized correlated test that distinguishes submission, relay acceptance, final receiver and mailbox access, with explicit content/size refusal categories and no success inference from queue count or a missing log |

### Storage top ten

| # | Decision | Implemented behavior or remaining evidence requirement |
|---|---|---|
| 1 | Add now | Every capacity plan carries `storage.plan.transition` explaining unverified model/DSM/current-member eligibility and volume growth separately from fresh-layout arithmetic; preserve the researched smallest-member addition floor and largest-member mixed-SHR replacement floor; do not substitute historical ticket rules or calculator agreement for transition acceptance |
| 2 | Add now | `storage.operation` branches explicitly to add, replace, repair or conversion; add/replace reject mixed purchase fields, repair gives DSM repair guidance, and conversion asks current/target type and never supplies a physical swap plan; free bays and installed unowned disks are shown separately and neither establishes conversion eligibility |
| 3 | Add now by preserving size rules and adding repair explanation | Existing planner rejects shrinking and undersized mixed-SHR replacements regardless of stored-data size; the dedicated repair branch explains member geometry and sends the user to Storage Manager rather than treating equal-size repair as capacity expansion |
| 4 | Needs setup/detect evidence | Obtain supported pool total, unallocated pool bytes, per-volume allocated/current bytes and model/filesystem limits with units and pool-volume linkage; show them separately and branch grown-pool/unchanged-volume to volume allocation/limit guidance rather than another purchase; current plan explicitly leaves volume growth unverified |
| 5 | Needs setup/detect evidence | Add authorized metadata-workspace/reclamation state and before/after volume-byte readback; branch insufficient workspace to user-selected space reclamation and retry in DSM, never automatic deletion or a success message based on task completion alone; no workspace threshold is guessed from free bytes |
| 6 | Add now | `storage.pools` surfaces active-task/background-building/failure evidence even with a normal summary; add/replace remain gated by healthy members and no active task; exact replacing/repairing/expanding stage remains explicitly unverified until a supported task adapter supplies it, so the user confirms the current stage in DSM before another swap |
| 7 | Add now | Preserve enclosure/slot cross-checks and block ambiguous mapping with a new why/fix finding; never derive a physical bay from an OS device name or emit a removal instruction when the mapping is unknown |
| 8 | Add now | Contradictory normal and abnormal DSM status labels produce an explicit conflict finding; captured `io_err_info.type` produces a separate error-context finding even if the summary is normal; no new slow-drive detector, raw-log classifier or physical-failure prediction is introduced |
| 9 | Add now for progress evidence; defer missing timestamps/results | Captured `smart_progress` is execution evidence with `completionVerified=false`, never a passed test; an empty progress string and `smart_test=normal` do not become completion; start time, last actual completion and elapsed/stall claims require a verified result/timestamp adapter |
| 10 | Add now for visible gaps; defer unavailable distinctions | Captured `smartInfo_support` or `smart_test_support=false` explains the monitoring gap; incomplete health reads produce explicit unknown findings plus `ErrUnavailable` to preserve prior warnings; retain per-drive schedule coverage checks, but require supported NAS-zone/schedule/last-execution and drive-database/transport evidence before classifying a time-zone, USB bridge or database fault |

### Integration handoff and authority

`diagnose.State.Transport` and `.Access` are additive, credential-free adapter
contracts. Populate only facts obtained from a verified authorized source:

- `TransportState.Send/Receive/Client` identify the selected hops, not package
  installation or mere tunnel presence; `RelayFailure` is an allowlisted category
- `TransportState.ClientReachable` concerns the chosen IMAP/submission endpoint;
  `WebReachable` is an independent web/mobile observation
- `AccountAccess.Ref` is a stable nonzero opaque mailbox reference;
  `EffectiveActive` is the authoritative effective result and `GroupControlled`
  preserves group policy context, while `HomeReadable` needs independent evidence
- `AccessState.BlockedSource` concerns the affected client's confirmed source;
  licence counts and `OwnerMatches` are independent, with nil meaning unknown;
  the snapshot fills `Licensed`/`Activated` from the License API v1 counts, so
  `license_count` (warning) shows when `Activated` > `Licensed` and
  `license_unknown` (why: `license_unread`) when the read failed; the linked
  Synology Account is still not read (`owner_unknown`, why: `license_unchecked`)

The existing researched `SYNO.MailPlusServer.Domain.User/list/v1` response includes
`is_activated` and `is_under_group_control`; it is already in `mail-read` and
requires `domain_id`, bounded `offset`/`limit` pagination and a selected mailbox.
It does not prove home readability or licence ownership. Storage additions use
only fields of the existing `Storage/load_info/v1` and
`Smart/get_health_info/v1` tuples, also already in `storage-read`.

**New exact API tuples requested from HK-INT: none in this change.** There is
no verified Auto Block, licence-owner, home-readability, task-stage or
volume-workspace method/response contract in the supplied evidence. Those
observations remain injected/unknown; do not invent tuples or widen profile
permissions to satisfy the new checks. HK-INT owns both
`backend/internal/core/dsmauthority/contract.go` and `dsm-package.yaml` and must
add any later verified tuple to both before its adapter uses it. No shared core
contract change is needed. All new findings carry why/fix copy and name the
manual DSM/MailPlus screen; none promises an executable navigation link that
`core.Finding` does not support.
