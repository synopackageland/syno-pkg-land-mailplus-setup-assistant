# MailPlus Setup Assistant

MailPlus Setup Assistant helps DSM administrators configure and troubleshoot
Synology MailPlus Server. It runs in a DSM window and supports DSM 7.2-64570
or later on x86_64 and aarch64.

## Features

- **Set up mail.** Check the mail domain, DNS, network and MailPlus Server
  settings. Preview supported changes before applying them, then verify and
  keep or roll back the changes.
- **Diagnose mail.** Run read-only checks for sending, receiving and mobile
  connection problems. Results distinguish confirmed problems from unknowns.
- **Cloudflare routes.** Use Email Sending through a loopback SMTP relay or
  receive through Email Routing, a Worker and a Cloudflare Tunnel.

## Architecture

The Vue frontend uses the Package Land UI SDK. A Go CGI uses the DSM session
and sends requests to a package-owned worker over a private Unix socket. The
worker talks to DSM through the SDK's `mail-read` and `mail-write` WebAPI
profiles and runs the optional SMTP relay.

## Build and install

Use Node.js 24, npm and Go 1.26.10 or newer.

Package Center descriptions and release notes come only from the
[catalog](https://github.com/synopackageland/catalog). Point
`SYNOPKGLAND_CATALOG` at a checkout of its `catalog.yaml` (or pass
`--catalog <file>`) before checking or building.

```sh
npm ci --include=dev
(cd frontend && npm ci --include=dev)
export SYNOPKGLAND_CATALOG=/path/to/catalog/catalog.yaml
npx --no synopkgland check --json
npx --no synopkgland build --json
```

Install the SPK for your NAS architecture using **Manual Install** in DSM
Package Center. Install and initialize MailPlus Server, then open MailPlus
Setup Assistant as a DSM administrator. Follow the wizard to grant the needed
DSM access. For a Cloudflare route, have access to the Cloudflare account and
zone you want to configure.

Run `npm test`, `npm run test:go` and `(cd frontend && npm test)` for local
development checks. See [design](docs/DESIGN.md) and [the operation
contract](docs/CONTRACT.md) for implementation details.
