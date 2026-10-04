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

Used in Phase 2: Fastify (MIT), `@fastify/websocket` (MIT), `@fastify/rate-limit` (MIT), `@fastify/helmet` (MIT),
`pg` (MIT), `argon2` (MIT), `jose` (MIT), `otplib` (MIT), `ws` (MIT), `zod` (MIT); dev/test: Vitest, fast-check, tsup, tsx, TypeScript (MIT/Apache-2.0).
(Planned but not used: `node-pg-migrate`, Testcontainers — replaced by a small SQL migrator and a real local PostgreSQL.)

## Desktop Agent (.NET) — used in Phase 3 (verify at release)

.NET 8 runtime and `Microsoft.Extensions.*`, `System.Security.Cryptography.ProtectedData`, `System.Diagnostics.PerformanceCounter` (MIT);
Serilog + `Serilog.Sinks.File/Console` + `Serilog.Formatting.Compact` (Apache-2.0);
**BouncyCastle.Cryptography** (Ed25519; Bouncy Castle License, MIT-style); xUnit (Apache-2.0, tests only).
`nvidia-smi.exe` is invoked if the user's NVIDIA driver provides it (not redistributed). Ed25519 via BouncyCastle replaced the earlier NSec/libsodium idea so the agent has no native dependency.
LibreHardwareMonitor (MPL-2.0) is **not used** (kernel driver; see R7).
A self-contained publish bundles the .NET runtime (MIT) — ship its license notices with the installer.

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
