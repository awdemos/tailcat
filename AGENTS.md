# Tailcat Agent Guide

**Project:** Tailcat — Tailscale-style data-plane connections without the control plane
**Language:** Go 1.26+
**License:** BSD-style (Tailscale)

## Overview

Tailcat uses Tailscale's `magicsock`/`derp` libraries to create encrypted,
peer-to-peer WireGuard tunnels between two machines using an out-of-band
token. It can run as a CLI (`cmd/tailcat`), a web demo (`cmd/tailcat-web`),
or as a Go library (`github.com/tailscale/tailcat`).

## Repository Layout

| Path | Purpose |
|------|---------|
| `cmd/tailcat/` | Main CLI tool |
| `cmd/tailcat-web/` | WASM web demo server |
| `cmd/tailcat-webdist/` | Web asset bundler |
| `cmd/tailcat-dagger/` | Dagger build helper |
| `internal/wasmbuild/` | WASM build tooling |
| `internal/wirecbor/` | CBOR wire-protocol helpers |
| `web/` | Browser WASM demo frontend |
| `webdemo/` | Web demo Go backend |
| `tailcat.go` | Core library |
| `disco.go` | DERP/peer discovery |
| `wire*.go` | WireGuard + plumbing |
| `go.mod` | Module definition |
| `flake.nix` | Nix flake entry |

## Build Commands

```bash
# CLI
go build ./cmd/tailcat

# All binaries
go build ./...

# Web demo assets (requires Bun/Node for JS)
go run ./cmd/tailcat-webdist
```

## Test Commands

```bash
go test ./...
```

## Lint / Format

```bash
go fmt ./...
go vet ./...
```

## Run

```bash
# Listener
./tailcat listen

# Connector (with printed token)
./tailcat connect <token>
```

## Key Conventions

- Uses `tailscale.com` module for DERP/magicsock internals.
- Web demo compiles the core library to WebAssembly; browser traffic is DERP-only.
- Default DERP map: `https://tailcat.dev/derpmap.json`

## Gotchas

- Requires a reachable DERP relay (default public relays or bring your own).
- No routing/DNS changes; it is userspace only.
- WebAssembly build has no direct P2P path until WebRTC support lands.
