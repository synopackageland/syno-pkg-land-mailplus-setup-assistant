# Mail relay service

Adapted from the original relay prototype and its experiment
report. This package uses the Go standard library, the SDK's declared TCP
listener and the existing core contract. It does not register itself.

## Host and setup integration

```go
service := relay.New(packageDataDir)
// Return service from the mail module's Services(), once in the daemon.
// The service host owns enablement, cancellation, restart and backoff.

credentials, err := relay.Credentials(ctx, env)
// Pass credentials.Username / Password directly to MailPlus Delivery,
// with STARTTLS and AUTH enabled and fallback disabled.
// Do not include credentials in UI facts, snapshots, logs or status.

err = env.Secrets.Put(ctx, relay.TokenSecretKey, cloudflareSendingToken)
err = relay.TestUpstream(ctx, env) // verified implicit TLS + AUTH only
// Start the service through the host before configuring the MailPlus address.
address := service.ListenAddr() // require service.Status().Running
```

`New(packageDataDir)` supplies the host-owned private directory. The module
registry/mail glue and daemon wiring belong to the coordinator/mail wizard.
No contract change is required for this constructor integration.

Secrets keys:

- `mail.relay.credentials`: one JSON record with generated username/password,
  reused on restart; `Credentials` creates it only when `Get` returns `""`, nil
- `mail.relay.cloudflare-token`: Cloudflare Email Sending token, with upstream
  SMTP username `api_token`; read again for every DATA attempt, so replacing or
  revoking a token does not leave a process-lifetime credential cache

Missing-secret convention: the shared Secrets interface requires the core
store to return `""`, nil for a missing key.
An error or corrupt record fails closed and never rotates MailPlus credentials.
Creation is serialized inside this daemon; the store has no cross-process
create-if-absent operation, so concurrent CGI writers must use a single wizard/
daemon authority. Credential rotation must be coordinated with MailPlus.

KV namespace `mail.relay`:

| Key | JSON value | Contract |
| --- | --- | --- |
| `port` | integer | Defaults to 2525 and is persisted at start; allowed 1024–65535 |
| `lastSuccess` | RFC3339 time | Persisted after each upstream post-DATA 250 |

The service calls `ipc.ListenTCP(ctx, "mail_relay", port)`. The package manifest
declares default port 2525, configurable range 1024–65535 and the default
loopback scope, binding literal `127.0.0.1` using TCP4. Package identity and
policy are bound by the build; an unbound binary refuses to listen. There is
no configurable bind host, upstream endpoint or TLS verification bypass in the production API.
Configure a different port in KV **before** starting/restarting the service and
coordinate that change with MailPlus. `ListenAddr` retains its last bound
address while stopped; always pair it with `Status().Running`.

## Delivery and resource limits

- Greeting, EHLO, STARTTLS, a fresh EHLO and AUTH PLAIN/LOGIN precede MAIL
- Local envelope acceptance does not promise delivery; the relay obtains
  upstream greeting/EHLO/AUTH/MAIL/all RCPT/DATA 354 before issuing local 354
- The body streams through SMTP dot decoding/encoding; it is never spooled or
  placed in another queue, and the relay never retries a submission itself
- Only upstream post-DATA **250** yields local final 250; upstream 4xx, 5xx,
  disconnects, unknown final acknowledgment and timeouts yield local **451**
- Local violations are rejected locally: 50 recipients, 25 MiB decoded body,
  unnegotiated extensions and malformed SMTP paths; oversized DATA gets 552
  and connection close without sending an upstream body terminator
- SIZE and BODY=7BIT/8BITMIME on MAIL are supported; DSN, SMTPUTF8, BINARYMIME,
  pipelining and recipient extensions are not advertised or passed through
- Commands/reply lines are at most 4096 bytes; multiline upstream replies are
  capped at 64 KiB; eight sessions cap both idle peers and upstream transactions
- Local sessions and upstream exchanges have 120-second absolute deadlines;
  upstream dialing has a 15-second total budget, preferring IPv4 for up to
  seven seconds and using the remainder for IPv6 fallback
- Context cancellation closes the listener, all local peers and their
  outstanding upstream connections, and Start waits for the handlers to exit

Cloudflare is fixed at `smtp.mx.cloudflare.net:465`, implicit TLS 1.2+, system CA
and hostname verification. External SMTP calls are isolated behind `Upstream`
and `Transaction`; package tests substitute a local fake implicit-TLS server.

A lost upstream final reply, or a lost downstream reply after upstream commit,
can produce a duplicate when MailPlus retries. This is ordinary SMTP ambiguity;
the service supplies no exactly-once promise. The relay does not edit headers,
so the prototype's MailPlus DKIM/Cloudflare Message-ID caveat still applies.

## Certificate and status

The package writes only `<DataDir>/mail-relay/starttls.pem` (certificate and
private key together, atomic rename, mode 0600 in a 0700 directory). It reuses
an existing valid certificate and rotates it at start when it has less than a
day remaining. The self-signed P-256 certificate is valid for one year and
names `localhost` and `127.0.0.1`. The DataDir must already be package-owned;
unsafe modes, symlinks and corrupt records fail closed. No credentials or
message data go into this directory. Renewal happens on start, so the host
must restart a continuously running relay before its certificate expires.
MailPlus accepting the prototype's self-signed certificate demonstrated
encryption, not verified server identity for this local hop.

`Status()` returns independent map copies, with process-instance counters:

| Field | Meaning |
| --- | --- |
| `accepted` | DATA attempts admitted with local 354, not a delivery receipt |
| `sent` | Messages whose upstream post-DATA 250 was observed |
| `deferred` | DATA attempts that encountered upstream/missing-token/stream failure |
| `rejected` | Local protocol/auth/limit refusals, counted per response |
| `lastError` | Safe diagnostic code/stage + numeric SMTP code, never peer text |
| `info.listen` | Last successfully bound loopback address |
| `info.lastSuccess` | RFC3339Nano UTC time, restored from KV on Start |

After a successful upstream commit the relay still ACKs when last-success
persistence fails: the delivery already happened. In-memory lastSuccess stays
current and lastError is `mail.relay.state_write`. The durable timestamp may
then be stale until another successful delivery.

No `mail.relay.health` check is registered here. Whether a service is enabled
and whether the MailPlus queue is non-empty require host/detect state outside
this package. Diagnose should consume this status/lastSuccess and its own
queue evidence, rather than warn merely because an idle relay has no recent
success. The diagnose thread can read KV `mail.relay/lastSuccess` after restart.

## Local verification

From the project root, bind the same identity and normalized TCP policy that
the packager uses. The lifecycle test exercises the real SDK listener rather
than replacing it with an unrestricted test listener:

```sh
relay_ldflags=$(node --input-type=module <<'JS'
import {readFileSync} from 'node:fs'
import {parse} from 'yaml'
import {readTCPListeners, tcpPolicyFlag} from './node_modules/@synopackageland/cli/dist/standalone/tcp-listeners.js'
const manifest = parse(readFileSync('dsm-package.yaml', 'utf8'))
console.log([
  `-X github.com/synopackageland/syno-pkg-land-sdk/ipc.packageID=${manifest.package}`,
  ...tcpPolicyFlag({tcpListeners: readTCPListeners(manifest.tcp_listeners)}),
].join(' '))
JS
)
go -C backend build ./...
go -C backend vet ./...
go -C backend test -p 1 -parallel 1 -count=1 -timeout 30s \
  -ldflags "$relay_ldflags" ./internal/mail/relay
```

Tests use local sockets and fake secrets only. They cover pass-through and the
commit barrier, AUTH PLAIN/LOGIN and TLS sequencing, upstream 4xx/5xx,
post-DATA refusal/lost reply/timeout, size and recipient limits, dot transparency,
AUTH-only probing, certificate verification/persistence/modes/symlinks, stable
credentials, persisted last-success, status copy isolation and canceled shutdown.
They do not establish NAS installation, MailPlus configuration, package reboot,
Cloudflare delivery, Gmail receipt or SDK packaging acceptance.
