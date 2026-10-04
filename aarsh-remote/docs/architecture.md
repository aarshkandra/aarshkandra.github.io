# Aarsh Remote — Architecture (Phase 1)

Status: **DRAFT FOR APPROVAL** — no implementation code exists yet.
Version: 0.1 · Date: 2026-10-04

Companion documents: [rustdesk.md](rustdesk.md) · [database-schema.md](database-schema.md) ·
[api-spec.md](api-spec.md) · [implementation-plan.md](implementation-plan.md) ·
[../THIRD_PARTY_LICENSES.md](../THIRD_PARTY_LICENSES.md)

---

## 1. Goal and scope

Personal, single-owner system to wake and remotely use a Windows Home desktop (Nagpur) from a
low-spec laptop (anywhere), including GPU-heavy Revit/BIM work.

**The core idea: we do not build a remote-desktop engine.** RustDesk (self-hosted `hbbs`/`hbbr` +
the stock RustDesk client) moves pixels and input. We build the *control plane* around it:
identity, wake, power, presence, monitoring, audit.

Out of scope: a TeamViewer replacement, multi-tenant SaaS, covert/stealth features, any bypass of
corporate IT controls (spec §51–52).

## 2. Key decisions (summary)

| # | Decision | Why |
|---|----------|-----|
| D1 | **Launch** RustDesk as a separate process; do not embed or fork it | AGPL-3.0 boundary stays clean; we get upstream security fixes by updating a binary. See [rustdesk.md](rustdesk.md). |
| D2 | Control server is **public** (VPS), home side is **outbound-only** | Home ISP (India) is commonly CGNAT; no inbound ports, no DDNS needed. |
| D3 | Control server + `hbbs` + `hbbr` run on **one small VPS** via Docker Compose | One host, one domain, minimal ops. Free-tier VPS is viable (decision Q1). |
| D4 | Wake is done by a **Wake Agent on the home LAN** (Raspberry Pi, Go binary) | The only reliable way to send a LAN broadcast. |
| D5 | Desktop Agent is a **.NET 8 Worker Service running as LocalSystem**, plus a separate optional **tray app** in the user session | Service must work with nobody logged in; tray cannot live in Session 0. |
| D6 | The agent **rotates the RustDesk password per connect** and delivers it over our authenticated channel | Removes the long-lived static RustDesk password as the single point of failure. |
| D7 | Device auth = **Ed25519 keypair, challenge-response**, key sealed with DPAPI (machine scope) | Device ID alone is never a credential (spec §7, §24). |
| D8 | Commands are a **closed enum**, wrapped in **server-signed, expiring, nonce'd envelopes** | No shell, no `EXECUTE_COMMAND`; a MITM/compromised proxy cannot forge commands. |
| D9 | Postgres only; **no Redis** in v1 | Single server instance; presence held in memory, persisted to Postgres. Add Redis only when scaling past one instance. |
| D10 | Fastify (not NestJS) | Smaller surface, first-class JSON-schema validation, WS plugin; fits a one-person project. |

## 3. Component diagram

```text
                                   INTERNET
 ┌───────────────────────┐                                  ┌──────────────────────────┐
 │ Laptop (anywhere)     │                                  │ VPS (public, TLS)        │
 │ ┌───────────────────┐ │   HTTPS + WSS (user JWT)         │ ┌──────────────────────┐ │
 │ │ Aarsh Remote      │─┼─────────────────────────────────►│ │ Caddy (TLS, :443)    │ │
 │ │ Electron client   │ │                                  │ └─────────┬────────────┘ │
 │ └────────┬──────────┘ │                                  │           ▼              │
 │          │ spawns     │                                  │ ┌──────────────────────┐ │
 │ ┌────────▼──────────┐ │   RustDesk protocol (E2E-enc.)   │ │ Control Server       │ │
 │ │ RustDesk client   │─┼───────────┐                      │ │ Fastify + TS + WS    │ │
 │ └───────────────────┘ │           │                      │ └─────────┬────────────┘ │
 └───────────────────────┘           │                      │           ▼              │
                                     │                      │ ┌──────────────────────┐ │
                                     │ rendezvous / relay   │ │ PostgreSQL           │ │
                                     └─────────────────────►│ └──────────────────────┘ │
                                        (P2P if possible)   │ ┌──────────┐┌──────────┐ │
 ┌──────────────────────────────────────────────────────────┼►│ hbbs     ││ hbbr     │ │
 │  HOME NETWORK, NAGPUR  (NAT/CGNAT, outbound only)        │ └──────────┘└──────────┘ │
 │                                                          └──────────────────────────┘
 │  ┌─────────────────────┐   WSS (device key auth)  ▲
 │  │ Wake Agent (Pi, Go) │──────────────────────────┘ outbound
 │  │  • ARP/ICMP probe   │
 │  │  • Magic packet     │── UDP :9 broadcast ──┐
 │  └─────────────────────┘                      ▼
 │  ┌──────────────────────────────────────────────────────────┐
 │  │ Windows 11/10 Home desktop                               │
 │  │  Desktop Agent (Windows Service, LocalSystem)  ──WSS────►│ (outbound to server)
 │  │  RustDesk (Windows Service, unattended) ──────────────────► hbbs/hbbr (outbound)
 │  │  Tray app (user session) ◄─named pipe─► Agent            │
 │  │  Revit / BIM                                             │
 │  └──────────────────────────────────────────────────────────┘
 └──────────────────────────────────────────────────────────────
```

**Two separate planes, deliberately:**

* **Control plane (ours):** laptop ⇄ server ⇄ {desktop agent, wake agent}. Auth, wake, power, status.
* **Media plane (RustDesk):** laptop RustDesk ⇄ (P2P or `hbbr`) ⇄ home RustDesk. Our server never
  sees pixels. If our control server is down, an existing RustDesk session keeps working.

## 4. Components

### 4.1 Control Server (`apps/backend`) — Node 22 LTS, TypeScript, Fastify, PostgreSQL

Modules: `auth`, `users`, `devices`, `pairing`, `presence`, `commands`, `wake`, `sessions`,
`audit`, `ws-gateway`, `rustdesk-bridge`, `updates`.

* **Two WebSocket endpoints:** `/ws/client` (user JWT) and `/ws/agent` (device challenge-response).
  Wake Agents use `/ws/agent` with `kind=wake`.
* **Presence:** in-memory map keyed by device, backed by `devices.status/last_seen` in Postgres.
  Heartbeat 15 s; a silent connection is terminated after 45 s. A *closed* socket changes state immediately
  (`SLEEPING` if the agent sent `GOING_TO_SLEEP` first, else `OFFLINE`); a re-connect replaces the old socket without flapping. All state transitions go through the single
  state-machine module (§6) so they are testable.
* **Command broker:** validates user + device ownership + device not revoked/paused, writes audit
  row, signs envelope, routes to the right agent, awaits ack with timeout.
* **rustdesk-bridge:** on `CONNECT`, asks desktop agent to set a one-time RustDesk password, and
  returns `{rustdeskId, password, serverConfig}` to the authenticated client only.

### 4.2 Desktop Agent (`apps/desktop-agent`) — C# / .NET 8 Worker Service

Runs as a Windows Service (`AarshRemoteAgent`, start type Automatic (Delayed), recovery: restart on failure).

* **Identity:** Ed25519 keypair generated on first run. Private key sealed with DPAPI
  `LocalMachine` scope into `C:\ProgramData\AarshRemote\identity.bin` (ACL: SYSTEM + Administrators).
  Never in config, never logged.
* **Connection:** outbound WSS to server. On connect: challenge → signed response → session.
  Reconnect with exponential backoff + jitter (1 s → 60 s cap). Network-change events
  (`NetworkChange.NetworkAvailabilityChanged`) trigger immediate retry.
* **Power events:** subscribes to `PowerBroadcast`. On suspend, sends `GOING_TO_SLEEP` *before*
  sleeping (this is what lets the server show SLEEPING rather than OFFLINE). On resume, reconnects.
* **Commands (closed enum):** `SLEEP`, `RESTART`, `SHUTDOWN`, `GET_STATUS`, `GET_METRICS`,
  `PREPARE_CONNECT`, `DISCONNECT`, `PAUSE_REMOTE`/`RESUME_REMOTE` (server-side revocation also
  enforced). Each maps to a hard-coded handler; arguments are typed and validated. No process
  spawning from payload data.
* **Metrics (only what the spec lists):** CPU/RAM/disk via PDH/WMI; NVIDIA GPU via NVML (optional,
  degrades to "n/a"); temperature only where exposed without a third-party kernel driver
  (otherwise "n/a" — see risk R7); uptime, Windows version, interactive session state.
* **Local safety switches:** emergency-disable flag file
  `C:\Program Files\AarshRemote\disable_remote_access.flag` (checked on every command and
  before every `PREPARE_CONNECT`; wins over any remote instruction), plus `sc stop`.
  When active: agent stays up, reports `REMOTE_DISABLED`, refuses all commands, and also stops the
  RustDesk service.
* **Tray app (`AarshRemote.Tray`)**: separate per-user process; talks to the service over a named
  pipe restricted to local interactive users; shows status, Pause/Resume, open logs. Optional;
  service never depends on it.
* **Logging:** Serilog, structured JSON, `C:\ProgramData\AarshRemote\Logs\`, rolling, with a
  redaction enricher that drops fields named `token|password|key|secret`.

### 4.3 Wake Agent (`apps/wake-agent`) — Go, single static binary, systemd unit on Raspberry Pi

* Outbound WSS only; **no listening sockets** (no inbound port, nothing for Internet scanners).
* Receives signed `WAKE{deviceId, mac, broadcast}` envelopes; verifies the server signature,
  expiry, nonce, and that the MAC is in its **local allow-list** (configured on the Pi), so a
  compromised server still cannot make the Pi poke arbitrary LAN hosts.
* Sends magic packet (6×`FF` + 16×MAC) as UDP broadcast on port 9 (and 7), repeated 3× over 3 s,
  optionally also directed to the subnet broadcast; ethernet strongly recommended for the Pi.
* Reports LAN reachability of the PC (ARP/ICMP) — gives the server a "router/ISP is up and PC is
  *physically* off vs. asleep" signal, and drives WAKING → ONLINE diagnostics.
* Same identity scheme as desktop agent (Ed25519; key file mode 0600 on the Pi).

### 4.4 Desktop Client (`apps/desktop-client`) — Electron + React + TypeScript + Vite

* Login (+TOTP), device list, pairing, wake/connect/power controls, metrics, audit/log viewer,
  WoL settings, setup diagnostics.
* Tokens in OS keychain via Electron `safeStorage`; renderer is sandboxed, `contextIsolation: true`,
  no `nodeIntegration`; all server I/O in the main process behind a typed IPC.
* **Connect flow:** gets `{id, password, serverConfig}` → spawns the RustDesk client with those
  parameters (never written to disk/log, passed via process args/stdin where supported) → watches
  the process and the control channel, auto-relaunches on drop (§8).
* Display: the RustDesk window is a **separate native window** (we do not embed it — D1). Our
  app shows a compact "session HUD" (device, latency from control channel, Disconnect, Power).
  The spec's in-app status bar (1080p/60FPS/monitor picker) is therefore delegated to RustDesk's
  own toolbar in v1. See open question Q3.
* Packaged with electron-builder (NSIS for Windows; macOS/Linux dmg/AppImage later).

### 4.5 Web Dashboard (`apps/web-dashboard`) — optional, Phase 8+

React admin UI served by the backend: devices, users, sessions, wake requests, audit, revoke/disable.
Same API, admin scope, no server-side command execution.

### 4.6 RustDesk infrastructure — see [rustdesk.md](rustdesk.md)

`hbbs` (rendezvous) + `hbbr` (relay) from the official `rustdesk/rustdesk-server` image, run with
`-k _` so only clients holding our public key can use them.

## 5. Provider abstraction

```ts
// packages/protocol  (TypeScript)  — mirrored in desktop-agent (C#)
interface IRemoteDesktopProvider {
  readonly name: string;                                   // "rustdesk"
  detect(): Promise<ProviderStatus>;                       // installed? version? service running?
  // Host side (runs in Desktop Agent)
  prepareHost(opts: { ttlSeconds: number }): Promise<HostTicket>;   // one-time credential
  revokeHost(ticketId: string): Promise<void>;
  // Client side (runs in Electron main)
  launch(ticket: ClientTicket): Promise<ProviderSession>;  // spawns viewer
  // ProviderSession: onClosed, onQuality?, close()
}
```

`RustDeskProvider` is the only v1 implementation. Tickets are opaque to the control server except
for routing. `RDPProvider` / `SunshineProvider` can be added by implementing the same interface.

## 6. State machine (server-authoritative)

```text
UNKNOWN ──(first agent contact)──► ONLINE
ONLINE ──(agent: GOING_TO_SLEEP, then WS closes)──► SLEEPING
ONLINE ──(WS closes without GOING_TO_SLEEP, >45 s)──► OFFLINE
SLEEPING|OFFLINE ──(user WAKE)──► WAKE_REQUESTED ──(wake agent ack)──► WAKING
WAKING ──(desktop agent authenticates)──► ONLINE
WAKING ──(timeout, default 180 s)──► ERROR{reason}
ONLINE ──(user CONNECT)──► CONNECTING ──(client reports RustDesk up)──► CONNECTED
CONNECTED ──(control or media drop)──► DISCONNECTED ──(retry ok)──► CONNECTED
                                       DISCONNECTED ──(retries exhausted)──► ONLINE | OFFLINE
any ──(repeated protocol failure)──► ERROR
```

Notes:
* `CONNECTING/CONNECTED/DISCONNECTED` are per-**session** states layered over the per-**device**
  presence states (ONLINE etc.). A device can be ONLINE with zero sessions.
* Wake nuance (Phase 2): if the Wake Agent is offline the request is rejected up-front with `503 WAKE_AGENT_UNREACHABLE`,
  recorded as a FAILED wake request, and the device **stays** SLEEPING/OFFLINE (it is not pushed into ERROR).
* `ERROR.reason` ∈ `WAKE_AGENT_UNREACHABLE`, `WAKE_NO_RESPONSE` (PC did not appear; likely WoL
  disabled in BIOS/NIC, or S5), `AGENT_AUTH_FAILED`, `REMOTE_DISABLED_LOCALLY`, `RUSTDESK_UNAVAILABLE`.
* Pure function `(state, event) → state | IllegalTransition`; property-tested.

## 7. Wake-on-LAN honesty

* **Supported:** S3 Sleep (and Modern Standby where NIC stays armed). Requires: BIOS "Wake on
  LAN/PCIe" on, NIC driver "Wake on Magic Packet" on, "Allow this device to wake the computer" on,
  Windows **Fast Startup off** (it breaks WoL from shutdown), ethernet (not Wi-Fi) on the PC.
* **S5 / full shutdown:** best-effort, hardware-dependent, never promised. The first-run wizard
  has a "Test Wake" that records the result per power state, so you *know* before travelling.
* **Wake Agent must be on the same L2 segment** as the PC (same subnet; no VLAN isolation).
* **Home power/ISP/router outage cannot be fixed in software.** Mitigations documented in
  troubleshooting: UPS for router + Pi, router auto-restart, optional smart plug (out of scope v1).
* The PC's sleep-vs-off distinction comes from `GOING_TO_SLEEP` + Wake Agent ARP probe.

## 8. Reconnection

| Layer | Behaviour |
|-------|-----------|
| Agent ⇄ server WS | Exp. backoff 1→60 s ±20 % jitter; immediate retry on network-change event; re-auth every reconnect. |
| Client ⇄ server WS | Same; UI banner "Reconnecting…". |
| Media (RustDesk) | RustDesk handles transient loss internally. If the viewer process exits unexpectedly while session intent = active, client asks for a **fresh ticket** (new one-time password) and relaunches, up to N=5 with backoff, then surfaces a diagnostic panel (§ failure matrix). |
| After remote RESTART | Client keeps "auto-reconnect when online" intent; waits for ONLINE (agent re-registers), then CONNECT. |

## 9. Security model

### 9.1 Trust boundaries & assets
Assets: the PC and company data on it (highest), user account, device keys, RustDesk key/password.
Boundaries: Internet↔VPS, VPS↔agents, agent↔OS (SYSTEM), laptop (untrusted-ish: low-spec,
travelling, possibly hotel Wi-Fi).

### 9.2 Authentication
* **Users:** Argon2id (memory-hard params, per-user salt, server pepper from env), min 12 chars
  (zxcvbn ≥3 — *Phase 2 implements length ≥12, a small denylist, no email-name and a repetition check; zxcvbn is a later improvement*),
  TOTP (RFC 6238) with encrypted-at-rest secret (AES-256-GCM, key from env), 10 single-use recovery codes (HMAC-hashed).
  **TOTP policy (`REQUIRE_TOTP_FOR_COMMANDS`, default on):** pairing, WAKE, SLEEP and CONNECT require a session that was
  established with a TOTP-verified login (JWT claim `tv`); RESTART and SHUTDOWN additionally require a **fresh, single-use
  TOTP code** in the request. A user who has not enrolled TOTP gets `403 TOTP_ENROLLMENT_REQUIRED`, so first-run order is:
  register → enroll TOTP → log in again → pair devices.
* **Tokens:** access JWT (EdDSA, 10 min), refresh token opaque 256-bit, stored **hashed**, rotated
  every use with **reuse detection** (reuse ⇒ revoke whole family + audit alert), 30-day absolute.
* **Devices/Wake Agents:** Ed25519 challenge-response on each WS connect
  (`nonce` from server, signature over `nonce‖deviceUuid‖serverOrigin‖ts`), so replay and
  cross-server relay fail. Server stores **public key only**.
* **Authorization check for every command:**
  `valid user session ∧ user owns device ∧ device.status ∉ {revoked, disabled} ∧
  device credential valid ∧ not paused ∧ command ∈ allow-list ∧ rate-limit ok`.

### 9.3 Pairing (spec §9)
1. Installer finishes → agent generates keypair, creates **pairing request** at server
   (anonymous, strictly rate-limited per IP), receives a request id.
2. Agent displays 6-digit code (CSPRNG). Server stores **only a hash** (HMAC).
3. User, logged in on laptop, enters code. Constraints: **10-min expiry, single-use, 5 attempts
   then the request is burned**, per-IP + per-user throttles.
4. Success binds `device.owner_id = user`, stores public key, marks trusted, audit-logged.
   The agent then receives its first signed credential and begins heartbeats.
Codes are 6 digits only because they are short-lived, attempt-limited, *and* require an
authenticated user; they are never accepted unauthenticated.

### 9.4 Transport
TLS 1.2+ (Caddy/ACME, HSTS) for HTTPS/WSS. RustDesk media is end-to-end encrypted (NaCl/libsodium
per RustDesk); `hbbs/hbbr` locked with `-k _`. Optional: agents pin the server's TLS SPKI.

### 9.5 Server hardening
Fastify schema validation on every route, `@fastify/rate-limit` (per IP, per account, per device),
account lockout with exponential delay, helmet headers, strict CORS (Electron origin only),
parameterised SQL only, request size caps, WS message schema validation + size caps, audit rows
are append-only (DB role without UPDATE/DELETE), secrets via env/Docker secrets, `npm audit` +
dependency pinning in CI.

### 9.6 Threat table

| # | Threat | Mitigation |
|---|--------|-----------|
| T1 | Stolen password | Argon2id, mandatory TOTP, lockout, audit + new-login alert |
| T2 | Stolen refresh token | Rotation + reuse detection; hashed at rest; OS keychain on client |
| T3 | Forged command to agent | Server-signed envelope with nonce+expiry; agent verifies; closed enum |
| T4 | Compromised VPS | Agents cannot run arbitrary code; Wake Agent local MAC allow-list; local emergency-disable flag; RustDesk password is per-connect and requested via signed envelope; PC still needs the one-time pw **and** hbbs key |
| T5 | Brute-forced pairing code | 5 attempts, 10 min, requires auth user |
| T6 | Static RustDesk password leak | D6: per-session rotation; permanent password never stored by us |
| T7 | Exposed ports on home | None. Outbound only. No RDP 3389 |
| T8 | Lost laptop | Revoke refresh family + device-client binding from web/another client |
| T9 | Malicious agent impersonation | Public-key identity, challenge-response |
| T10 | Replay | nonce + `exp` on envelopes; WS challenge includes server origin |
| T11 | Log leakage | Redaction enricher; secrets are typed `Secret<T>` with no `toString` |
| T12 | Insider/IT policy | Documented network connections; pause + emergency disable; no stealth (see §12) |

### 9.7 Audit
`audit_logs`: `ts, user, device, action, result, ip, user_agent, detail(json, redacted)`.
Written in the same transaction as the action; append-only; viewable in client/web.

## 10. Network & firewall

Every connection the software makes (spec §52 — "document every network connection"):

| From | To | Proto/Port | Purpose |
|------|----|-----------|---------|
| Laptop client | VPS `:443` | HTTPS, WSS | API, real-time state |
| Desktop Agent | VPS `:443` | WSS | Control channel, heartbeat |
| Wake Agent | VPS `:443` | WSS | Wake commands |
| Wake Agent | LAN broadcast | UDP 9 (7) | Magic packet only |
| Wake Agent | PC | ARP/ICMP | Reachability probe |
| RustDesk (both ends) | VPS | TCP 21115, 21116 TCP+UDP, 21117 | Rendezvous / relay (outbound) |
| RustDesk laptop⇄PC | each other | UDP hole-punched high ports | Direct P2P (outbound-initiated) |
| Update check (client/agent) | VPS `:443` | HTTPS | Version manifest |

VPS inbound firewall: 22 (restricted/key-only), 80/443, **21115–21117 (+21116/udp)**. Everything
else denied. Windows PC: **no inbound rules created by our installer.** RustDesk's own installer
adds its own rules; these are documented in `docs/networking.md` (Phase 5) and reviewed rather
than assumed. Laptop on a restrictive network (hotel/corporate) that blocks 21116/21117: fallback
is hbbr over TCP; if even that is blocked, v2 option = tunnel RustDesk through :443 (stream proxy) —
noted, not v1.

## 11. Repository layout

```text
aarsh-remote/
├── apps/
│   ├── backend/            Fastify + TS         (Phase 2)
│   ├── desktop-agent/      .NET 8 (+ Tray)      (Phase 3)
│   ├── wake-agent/         Go                   (Phase 4)
│   ├── desktop-client/     Electron/React       (Phase 6)
│   └── web-dashboard/      React                (Phase 8)
├── packages/
│   ├── shared-types/       TS types generated from protocol schemas
│   ├── protocol/           JSON-Schema message defs + envelope sign/verify + test vectors
│   ├── authentication/     argon2/jwt/totp helpers
│   ├── logging/            redacting logger
│   └── configuration/      zod env schema
├── infrastructure/
│   ├── docker/             docker-compose.yml, Caddyfile, .env.example
│   ├── postgres/           migrations (node-pg-migrate), roles
│   └── server/             VPS bootstrap + backup scripts
├── docs/  scripts/  tests/
├── README.md  SECURITY.md  LICENSE  THIRD_PARTY_LICENSES.md
```

Tooling: pnpm workspaces + Turborepo for TS; `dotnet` solution and `go` module live beside them;
`packages/protocol` JSON Schemas are the **single source of truth** and C#/Go types are generated
or validated against shared **test vectors** (signature + envelope fixtures) in CI.

## 12. Ethics / corporate boundary (spec §51–52)

* Transparent: visible service name, tray icon, installed via normal installer/uninstaller, logs
  readable by the owner, no stealth, no AV evasion, no keylogging, no screen recording.
* **The PC holds company data and Revit is company-licensed.** Before Phase 5, confirm your
  employer's policy allows remote-access software and off-site use of the licence (Autodesk
  licensing/concurrent-use rules and BIM data-handling clauses may apply). This is a *project
  gate*, not a technical item — see Q2.
* Remote access can be paused (tray/API) or killed locally (flag file) and the remote side can't
  override either.

## 13. Risks

| ID | Risk | Likelihood | Impact | Mitigation |
|----|------|-----------|--------|-----------|
| R1 | WoL doesn't work on your hardware from S3/S5 | Med | **Fatal to MVP** | Hardware test **before** Phase 4 coding (§ plan P0). Fallback: smart plug + BIOS "restore on AC", or keep PC asleep not off |
| R2 | ISP CGNAT blocks P2P | High | Med | hbbr relay (works, higher latency); VPS in India region (Mumbai) to limit RTT |
| R3 | Relay latency/bandwidth hurts Revit orbit | Med | High | VPS region choice; test early (Phase 5 spike); hardware encoding; tune RustDesk codec/FPS |
| R4 | RustDesk CLI/config surface changes between versions | Med | Med | Pin version; wrap in provider; verify against docs at Phase 5 (my knowledge here is from memory — **not yet verified**) |
| R5 | AGPL obligations | Low | Med | Unmodified binaries launched, source offer for any modified server; repo stays compatible (see THIRD_PARTY_LICENSES) |
| R6 | RustDesk service blocked at Windows login screen/UAC prompts | Med | Med | Run as service (supports secure desktop); test lock screen + UAC in Phase 5 |
| R7 | GPU temp requires 3rd-party kernel driver (LibreHardwareMonitor/WinRing0) — AV flags / corp policy | Med | Low | Off by default; NVML only; temp "n/a" otherwise |
| R8 | Home outage (power/ISP) | Med | High | Documented; UPS; out of software scope |
| R9 | Single VPS = single point of failure for *control* | Low | Med | Media sessions survive; backups; restore runbook |
| R10 | Mandatory 2FA friction | Low | Low | Configurable; recovery codes |
| R11 | Wake Agent on LAN is a pivot point | Low | Med | Outbound-only, local MAC allow-list, no shell, minimal OS (read-only root optional) |

## 14. Deliberately NOT in v1

Redis, Kubernetes, multi-user/org features, silent auto-update, session recording, arbitrary file
browsing (v1.x: one-way drop into `C:\ProgramData\AarshRemote\Inbox`, size/extension limited, via
RustDesk's own file transfer or our signed upload — decided in Phase 11), mobile clients,
embedding RustDesk.
