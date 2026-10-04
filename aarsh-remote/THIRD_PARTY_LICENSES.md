# Third-Party Licenses (DRAFT — Phase 1)

Planned dependencies. Licenses are from my understanding and **must be verified against each
project's pinned version** (including transitive dependencies) before release. A machine-generated
inventory (`license-checker`, `dotnet-project-licenses`, `go-licenses`) will replace this table in
Phase 8. Not legal advice.

## Runtime / infrastructure

| Component | Use | License | Notes |
|---|---|---|---|
| RustDesk client (`rustdesk/rustdesk`) | Remote desktop engine, launched unmodified | AGPL-3.0 | Not embedded or modified; source link + version recorded |
| RustDesk Server OSS (`hbbs`, `hbbr`) | Rendezvous/relay | AGPL-3.0 | Unmodified official image |
| PostgreSQL | Database | PostgreSQL License | |
| Caddy | TLS reverse proxy | Apache-2.0 | |
| Docker / Compose | Deployment | Apache-2.0 | |

## Backend (Node/TypeScript) — to be confirmed

Fastify (MIT), `@fastify/websocket` (MIT), `@fastify/rate-limit` (MIT), `@fastify/helmet` (MIT),
`node-pg-migrate` (MIT), `pg` (MIT), `argon2` (MIT), `jose` (MIT), `otplib` (MIT), `zod`/`ajv` (MIT),
`pino` (MIT), Vitest (MIT), Testcontainers (MIT).

## Desktop Agent (.NET) — to be confirmed

.NET 8 runtime (MIT), `Microsoft.Extensions.Hosting.WindowsServices` (MIT), Serilog (Apache-2.0),
`System.Management` (MIT), NSec or `libsodium` bindings for Ed25519 (MIT/ISC), NVML via NVIDIA driver
(not redistributed). LibreHardwareMonitor (MPL-2.0) **not used by default** (kernel driver; see R7).

## Wake Agent (Go) — to be confirmed

Go stdlib (BSD-3), `nhooyr.io/websocket` or `gorilla/websocket` (ISC/BSD-2), `golang.org/x/crypto` (BSD-3).

## Client (Electron) — to be confirmed

Electron (MIT), React (MIT), Vite (MIT), electron-builder (MIT), Playwright (Apache-2.0).

## Our own license

Project license not yet chosen (decision Q4 in architecture notes).

## Obligations checklist

- [ ] Ship full AGPL-3.0 text and RustDesk source/version link if RustDesk binaries are bundled in any installer
- [ ] Publish source of any *modified* AGPL component (none planned)
- [ ] Do not use RustDesk trademarks as our product branding
- [ ] Regenerate this file from tooling at each release
