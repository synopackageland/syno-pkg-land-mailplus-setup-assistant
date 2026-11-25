#!/bin/sh
# Go build, vet, gofmt and tests for the backend. The relay test binds the
# package identity and TCP listener policy the same way the packager does.
set -eu
cd "$(dirname "$0")/.."
flags=$(node scripts/relay-ldflags.mjs)
go -C backend build ./...
go -C backend vet ./...
test -z "$(cd backend && gofmt -l .)"
go -C backend test -count=1 -race -ldflags "$flags" ./...
