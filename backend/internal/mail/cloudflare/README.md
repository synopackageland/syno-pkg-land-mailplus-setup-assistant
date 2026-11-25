# Cloudflare mail client

This package is the standard-library HTTP boundary for setup and diagnosis.
It does not register SDK routes or depend on the module/core contract. Consumers
can declare narrow interfaces containing only the methods they use. All network
access goes through `HTTPDoer`, which is replaced by loopback `httptest` servers
in the unit tests.

Construct a client using a token obtained from `core.Secrets`. Do not serialize
or log `Config`, HTTP requests, or the token. `Client` formatting is redacted;
returned errors contain local text, numeric Cloudflare codes and permission
names, never upstream message text or transport errors. The standard HTTP client
has a 30-second deadline and refuses redirects. A custom `HTTPDoer` must honor
context deadlines and must not redirect or log credentials.

Use a stable, nonsecret `OwnerID` (lowercase letters, digits and hyphens, up to
40 characters). Use separate owners for independently rolled-back DNS change
sets. The caller must serialize writes for a given owner. No mutation is
automatically retried: after a lost response, inspect current state and reconcile
the original request before deciding what to do.

## API for callers

| Area | Methods | Behavior |
| --- | --- | --- |
| Token | `VerifyToken`, `InspectToken`, `TokenAccess.PermissionState` | User or account-owned token verification; actual policy and resource inventory when permitted |
| Zone | `ListZones`, `GetZone`, `FindZone` | Paginated visible zones; exact longest-suffix lookup |
| DNS | `ListDNSRecords`, `ListOwnedDNSRecords`, `CreateDNSRecord`, `UpdateDNSRecord`, `DeleteDNSRecord` | Diagnostic reads; owned mail DNS mutations only |
| DNS rollback | `SnapshotDNS`, `RestoreDNS` | Owner-scoped full-set snapshot; recreate, restore and remove additions |
| Sending | `ListSendingDomains`, `GetSendingDomain`, `PreviewSendingDomain`, `OnboardSendingDomain`, `SendingDNS`, `SendingDNSStatus`, `PollSendingVerification`, `RollbackSendingDomain` | New sender onboarding with DNS preview and a private creation receipt |
| Routing | `RoutingStatus`, `RoutingDNS`, `EnableRouting`, `UnlockSubdomainRouting`, `ListRoutingRules`, `OwnedRoutingRules`, `CreateRoutingRule`, `DeleteRoutingRule`, `CatchAll` | Zone/subdomain enable (body field `name`); unlock of one subdomain's routing MX (never the apex) for a removal; exact addresses to this owner's Worker; catch-all reads only |
| Worker | `WorkerName`, `UploadWorker`, `FindWorker`, `DeleteWorker`, `ListWorkers`, `InboundWorkerSource` | Embedded module upload with ownership tags, one `vpc_service` binding and a JSON config |
| VPC | `VPCServiceName`, `ListVPCServices`, `GetVPCService`, `FindVPCService`, `CreateVPCService`, `DeleteVPCService`, `PrivateIPv4` | Owned SMTP TCP 25 service on a private NAS IPv4 through a healthy tunnel |
| Tunnel | `ListTunnels`, `TunnelConnectors`, `ConnectPrefix` | Read-only discovery (not deleted; connections' origin IPs); no tunnel configuration or credentials |
| Send | `SendMessage` (assumptions unverified, see CONTRACT) | One plain-text message through Email Sending; returns Cloudflare's Message-ID (inbound check only) |

Permission names are API permission-group names, including
`Email Sending Write` (called Email Sending: Edit in the dashboard). Email
Routing enable and status take `Zone Settings Read`/`Zone Settings Write`
(the API reference; there is no "Email Routing Settings" group).
`TokenAccountID` selects the account-owned token verification/metadata API;
leave it empty for a user-owned token. The permission catalog is **not** used
as evidence of a token's grants.

A least-privilege token can verify successfully yet be unable to read its own
policy or enumerate zones. `InspectToken` preserves those partial failures as
`PoliciesError` and `ZonesError`; `PoliciesKnown=false` means permissions are
unknown. When policies are available, `PermissionState` distinguishes a present
group name from a missing one. It does not claim that a present group authorizes
the selected account/zone: inspect `Token.Policies[].Resources` and rely on the
actual endpoint refusal. `Error.RequiredPermissions` identifies the relevant
operation permissions (read/write names on reads are alternatives); it is not
a reconstructed token policy or a claim that every listed permission is absent.

## Ownership and rollback

Every resource this package creates carries the owner's prefix or marker,
from `client.go` (`marker()` = `syno-home-keeper:<OwnerID>`,
`resourceName()` = `syno-home-keeper-<OwnerID>`). Audited no create
call bypasses them.

| Resource | Created by | Name / marker |
| --- | --- | --- |
| DNS record (A/AAAA/CNAME/MX/TXT) | `CreateDNSRecord`, `UpdateDNSRecord` | comment `syno-home-keeper:<OwnerID>` |
| Email Routing rule | `CreateRoutingRule`, `EnsureRoutingRules`, takeover | name `syno-home-keeper:<OwnerID>`, action Worker `syno-home-keeper-<OwnerID>-inbound` |
| Worker | `UploadWorker` | script `syno-home-keeper-<OwnerID>-inbound`, tag `syno-home-keeper:<OwnerID>` |
| Workers VPC Service | `CreateVPCService` | `syno-home-keeper-<OwnerID>-smtp` |
| Email Sending domain | `OnboardSendingDomain` | none possible (keyed by the domain); ownership is the private `SendingReceipt` |
| Email Routing enable | `EnableRouting` | none possible (a zone setting); never disabled by rollback |

Cloudflare's own locked records (Email Routing MX/SPF, Sending `cf-bounce`)
cannot be tagged and are never edited. The one exception is a removal deleting
the routing MX its own setup created on a subdomain (by recorded ID): it first
unlocks that subdomain with `UnlockSubdomainRouting`
(`PATCH /email/routing/dns {"name": <subdomain>}`), which live unlocked only
that subdomain's MX, and trusts only a reply naming that subdomain.

Ordinary DNS records use the exact comment `syno-home-keeper:<OwnerID>`.
Update/delete re-read that comment and refuse read-only or Email Routing-managed
records. Mutable types are A, AAAA, CNAME, MX and TXT; other types are readable.
Mail records cannot be proxied. Creating an existing identical record fails
instead of adopting it; duplicate SPF and CNAME conflicts also fail.

`RestoreDNS` only affects that owner in the snapshotted zone. It leaves other
owners alone, refuses ownership drift and returns new IDs for recreated records.
Persist its returned snapshot even when it returns a partial-progress error.
Cloudflare does not provide an atomic comment compare-and-swap here, so external
concurrent edits can race the final ownership check. Do not run two change sets
under the same owner concurrently.

Sending onboarding refuses an existing sender, including disabled senders that
the create API could otherwise re-enable. It previews required DNS and refuses
collisions before creation. Existing DMARC is preserved by the service, as
observed in E1. The service-created cf-bounce records are locked and cannot be
tagged; they are never edited through this client's ordinary DNS methods.
Persist the `SendingReceipt` privately and use it for sender rollback. Do not
accept a receipt from browser input. Deleting the new sender is a service-level
rollback; this client does not separately edit locked DNS or restore the zone's
global Sending flag.

Routing enable refuses existing target-domain MX/SPF and returns without writing
if routing is already enabled. It sends `{"name": <zone or subdomain>}`: an
unknown field would be ignored and enable the zone apex. `RoutingDNS` keeps the
`subdomain` query parameter: the API marks it deprecated without a documented
replacement, and its result is only used to refuse (a non-`missing` issue),
never to allow; the caller's own MX/SPF check on the target name decides. It does not change
catch-all settings or expose a disable: `DELETE /email/routing/dns` disables
the whole zone. Exact rules are named with the ownership marker and may only
target `WorkerName()`. Rule deletion verifies name, exact matcher and Worker
destination. A literal `*@domain` is rejected.

Worker names are `syno-home-keeper-<OwnerID>-inbound`, with an exact ownership tag.
An existing untagged or differently tagged Worker is never overwritten/deleted.
VPC services are `syno-home-keeper-<OwnerID>-smtp`, TCP port 25, on an RFC 1918
IPv4 (`PrivateIPv4`: never loopback, link-local, public, CGNAT or IPv6). Loopback
is refused because MailPlus's Postfix trusts 127.0.0.0/8 and relayed to an
outside domain in testing. A private address is not by itself relay-safe:
a LAN range in MailPlus's relay networks would let Postfix relay too. Relay
prevention rests on the Worker's exact recipient list and on the VPC Service
being bound only by this account's Worker. The service may sit on any healthy tunnel of the
account, including a Syno Connect tunnel (`synopkgconnect-*`): registering a
service does not change the tunnel. The package exposes no tunnel mutators,
private-route mutators or token retrieval.

## Inbound Worker

The Worker delivers each message straight to MailPlus over the `NAS`
`vpc_service` binding. `connect()` must be given an address (E3: without one it
throws); the service's registered host and port are used whatever the
argument. There is no R2 spool or Queue. The message is accepted only after
MailPlus's final `250`; a MailPlus `5xx` to `MAIL`, `RCPT` or `DATA` becomes
`setReject`; anything else throws, so Cloudflare answers the sender with `421`
and the sender retries (E2). A `5xx` to the `220` greeting or to `EHLO` refuses
the session, not the message (MailPlus overloaded, misconfigured or blocking the
VPC address), so it throws too instead of bouncing mail that could be delivered
later. `email()` reads `env.CONFIG` once and passes the parsed config to
`deliver()` as its own argument; `env` (the `NAS` binding) is passed unchanged
and never copied: the harness env refuses enumeration.
A `250` lost after DATA can make the sender deliver twice. `CONFIG` is a `json` binding whose value is
uploaded as a JSON **object** (a string reaches the Worker as a string: build
27 threw on every message; the Worker also parses a string defensively); the
exact upload is pinned in `testdata/inbound-upload-metadata.json`, which the
Worker harness builds its env from. It carries the
EHLO domain, the MailPlus `domain` it guards (only plain `local@domain`
recipients are handed on; MailPlus decides whether the user exists) and
`maxBytes` (Cloudflare's
25 MiB; MailPlus enforces its own lower `SIZE` with a 5xx). The source has no
HTTP handler, embedded credentials, personal domain or logging, and is
exercised by `frontend/test/inbound-worker.test.ts`.

## Evidence and checks

- Additional endpoint paths and multipart `vpc_network`/`vpc_service` metadata
  were read from the locally installed Cloudflare `cf` CLI distribution;
  that CLI was not executed against an account

The allowed local verification commands are:

```sh
cd backend
go build ./...
go vet ./...
go test -count=1 -p=1 ./internal/mail/cloudflare
```

Unit tests exercise endpoint payloads and returned values using `httptest`.
They establish local client behavior, not Cloudflare entitlement, email delivery
or NAS acceptance. No UI strings are introduced; consumers translate typed error
kinds with their own nine-locale keys.
