# Phased Implementation Plan

Rule (spec §58): per component — explain → risks → dependencies → implement → test → run → fix → document.
Gate between phases: your approval + green tests.

## Phase 0 — De-risk before any coding (you, ~1 evening, no code)

These can invalidate the plan, so do them first.

1. **WoL hardware test** (R1): BIOS WoL on, NIC "Wake on Magic Packet", Fast Startup **off**, PC on
   Ethernet. From another LAN device (phone app e.g. "Wake On Lan") try: Sleep→wake, Shutdown→wake.
   Record which works. *If sleep-wake fails, we fix that before Phase 4.*
2. Note PC: Windows edition/build, NIC model, GPU model (NVIDIA? for NVML), monitor count, ISP + whether you get a public IP (CGNAT likely).
3. Confirm employer policy on remote-access software and Autodesk licence off-site use (§12 gate).
4. Pick hosting (Q1) and a domain/subdomain for TLS.
5. Raspberry Pi (or any always-on LAN device) available, on Ethernet.

## Phase 1 — Architecture ✅ (this PR)
Deliverables: architecture.md, rustdesk.md, database-schema.md, api-spec.md, implementation-plan.md,
THIRD_PARTY_LICENSES.md (draft). **Awaiting approval.**

## Phase 2 — Backend (Fastify/TS/Postgres)
2a monorepo scaffold (pnpm, TS strict, lint, CI) · 2b `packages/protocol` (schemas, envelope
sign/verify, test vectors) · 2c DB migrations · 2d auth (Argon2id, JWT, refresh rotation, TOTP, lockout)
· 2e devices + pairing · 2f WS gateway + presence + state machine · 2g command broker + audit · 2h Docker Compose (backend+postgres+Caddy; hbbs/hbbr stubbed until Phase 5).
Tests: unit (auth, pairing limits, token expiry/reuse, state machine property tests, envelope signing), integration with real Postgres (Testcontainers) and fake agent over WS.
Exit: scripted "fake agent" pairs, heartbeats, goes offline, receives signed commands; invalid auth ⇒ `ACCESS_DENIED`.

## Phase 3 — Desktop Agent (.NET 8)
Identity+DPAPI · WS client + backoff · heartbeat/status · power events (`GOING_TO_SLEEP`) · metrics ·
SLEEP/RESTART/SHUTDOWN handlers · emergency flag + pause · logging w/ redaction · tray (basic).
Dev needs a Windows machine (your PC); CI uses `windows-latest` for build/unit tests. Unit tests mock the OS layer.
Exit: install as service, reboot PC → shows ONLINE in server without login; kill network → recovers.

## Phase 4 — Wake-on-LAN
Magic-packet library + vectors · Wake Agent (Go, systemd) · wake_requests + state tracking · diagnostics
(ARP probe, per-power-state test log) · timeout→ERROR with reasons.
Exit: repeated Sleep→Wake→Online cycles (≥20) logged with success rate; Wake Agent offline ⇒ `WAKE_AGENT_UNREACHABLE`.

## Phase 5 — Remote desktop (RustDesk)
Step 0: verification checklist in rustdesk.md. Then hbbs/hbbr in Compose, `RustDeskProvider`
(host: install/config/rotate password; client: launch), connect flow, reconnect logic.
Tests: LAN, other network, CGNAT, relay-forced, lock screen/UAC, multi-monitor, **Revit orbit on a real model**, Wi-Fi↔hotspot switch.

## Phase 6 — Electron client
Login+TOTP · pairing · dashboard · wake/connect · power dialogs (confirm) · metrics · logs · WoL settings · setup wizard. Playwright E2E against the real backend with fake agents.

## Phase 7 — Security hardening
Authn/authz test matrix, rate-limit, token expiry, revocation, invalid commands, replay, fuzz WS schemas, ZAP/nmap of VPS, `npm audit`/`dotnet list package --vulnerable`/`govulncheck`, threat-table review, secret scanning.

## Phase 8 — Packaging
Windows installer (WiX or Inno Setup: service install, no unrelated settings changed, uninstall,
pairing launch) · signed release manifest (update notice, no silent update) · Pi `.deb`/install script · Compose + deployment guide · optional web dashboard.

## Phase 9 (post-MVP) — Polish & extras
UI polish, restricted file-transfer inbox, adaptive-quality surfacing, :443 tunnelling for hostile networks.

## MVP acceptance = spec §60 workflow, end to end.
