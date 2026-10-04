# Windows Desktop Agent (Phase 3)

`apps/desktop-agent` — C# / .NET 8 Worker Service. Runs as the Windows service **AarshRemoteAgent** (LocalSystem, automatic-delayed start, restarts itself on failure). It makes **outbound connections only**.

> **Honesty box.** Everything below marked ✅ was tested here (Linux, .NET 8) — including a real agent process against the real backend and PostgreSQL. Everything marked ⚠ is Windows-only code that **compiles and publishes but has never executed on Windows**; the checklist at the end is what you run on the PC to close that gap.

## Layout

```text
apps/desktop-agent/
├── src/AarshRemote.Agent/        the service + CLI (pair, status, run)
│   ├── Protocol/                 canonical JSON, Ed25519, signed-envelope verification   ✅ byte-identical to the TypeScript reference
│   ├── Identity/                 device key + UUID; DPAPI (LocalMachine) + ACL storage    ⚠ DPAPI/ACL; ✅ logic
│   ├── Pairing/                  pair CLI: pins the server's command key, signed polling  ✅
│   ├── Connection/               session (challenge→hello→ready), reconnect loop, watchdog ✅
│   ├── Commands/                 the only command interpreter (closed allow-list)         ✅
│   ├── Safety/                   emergency flag, local/remote pause                        ✅
│   ├── Power/ Metrics/ Remote/   interfaces + dev stand-ins                               ✅
│   ├── Windows/                  shutdown.exe, SetSuspendState, perf counters, WTS, power events, tray pipe   ⚠
│   └── Logging/                  redacting Serilog enricher                                ✅
├── src/AarshRemote.Tray/         optional WinForms tray icon (talks to the service via a named pipe)   ⚠ not even compiled here
├── tests/AarshRemote.Agent.Tests 76 tests (incl. cross-language vectors, in-process fake server)
└── scripts/install-agent.ps1, uninstall-agent.ps1                                         ⚠
```

## What the agent does

```text
Windows starts → service starts → loads identity (DPAPI) + config.json
→ wss://<server>/ws/agent → server challenge → signs (nonce, uuid, server origin, ts) with its Ed25519 key → "ready"
→ heartbeat 15 s (server answers heartbeat.ack), metrics 15 s, commands as they arrive
→ connection lost → exponential backoff 1 s … 60 s (±20 %), cut short on network-change / resume-from-sleep
```

| Behaviour | Detail |
|---|---|
| **Identity** | Random UUID (an identifier, not a credential) + Ed25519 key. Only the **public** key ever leaves the PC. The private seed is sealed with DPAPI `LocalMachine` scope in `C:\ProgramData\AarshRemote\identity.bin`, ACL-restricted to SYSTEM + Administrators. *Trade-off:* LocalMachine scope is what lets the admin-run pairing and the SYSTEM service share the key; it relies on the ACL, not on per-user DPAPI. |
| **Server pinning** | At pairing the agent fetches `/api/v1/server-info` over TLS and stores the server's command-signing public key. Every command is verified against it (Ed25519, expiry ≤ 60 s, bound to this device, replay-cached). A compromised network path or proxy cannot forge commands. |
| **Origin binding** | The hello signature covers the server origin from the challenge; the agent refuses to sign if that origin differs from the configured URL. |
| **TLS** | `https://` mandatory. `http://` only for loopback **and** `AARSH_ALLOW_INSECURE_HTTP=1` (development). |
| **Commands** | `SLEEP RESTART SHUTDOWN PREPARE_CONNECT DISCONNECT GET_STATUS GET_METRICS PAUSE_REMOTE RESUME_REMOTE`. `WAKE`/`CONNECT` are not for this agent. Arguments are typed integers/UUIDs; nothing from the network becomes a command line, path or shell string. |
| **Ack before action** | `SLEEP`/`RESTART`/`SHUTDOWN` are acknowledged first, then executed — the server never waits on a machine that just went away. `SLEEP` additionally sends `GOING_TO_SLEEP` so the dashboard shows *Sleeping*, not *Offline*. |
| **Restart/shutdown never force-close apps** | `shutdown.exe /r|/s /t N` without `/f`, so unsaved Revit/BIM work is never destroyed. Windows may then wait for apps; you'll see that over the remote session. Set `"forcePowerActions": true` in `config.json` to add `/f`. |
| **Emergency disable** | While `C:\Program Files\AarshRemote\disable_remote_access.flag` exists the agent refuses **every** command (including `RESUME_REMOTE`), stops the remote engine, stops sending metrics, and tells the server (`remoteDisabled`). Removing the file restores normal operation. Nothing remote can create/remove it. |
| **Two pauses** | `RemotePaused` (owner, via the app) and `LocallyPaused` (someone at the PC, via the tray). Remote resume can **never** lift the local pause. Both persist across restarts; an unreadable state file fails *closed*. |
| **Dead-link detection** | .NET 8 has no pong timeout, so the server acks each heartbeat and the agent drops the connection after 3 silent heartbeat periods (≈ 45 s). Regression-tested. |
| **Close codes** | `4401` bad credentials → wait 60 s; `4403` revoked → wait 5 min and log it; `4426` outdated → wait 5 min; `4409` replaced → 2 s. No retry storms. |
| **Logging** | `C:\ProgramData\AarshRemote\Logs\agent-YYYYMMDD.log`, 14 days. A redacting enricher blanks any property named like `password/token/secret/key/seed/sig/otp`; command acks (which carry the one-time password) are never logged. ✅ asserted in tests, including the end-to-end run. |
| **Remote engine** | `IRemoteDesktopProvider` exists; the agent currently ships a *null* provider, so `CONNECT` fails with `REMOTE_ENGINE_UNAVAILABLE` until Phase 5 plugs in RustDesk. |

## Pairing screen

```text
> AarshRemote.Agent.exe pair --server https://remote.example.com --name NGP-WORKSTATION

Device Pairing
Device: NGP-WORKSTATION
Request ID:  <uuid>
Pairing Code: 847291
Enter both in Aarsh Remote on your laptop (while logged in with two-factor). Expires 14:40.
Waiting for pairing…
```
You need your account to have TOTP enabled and to be logged in with it (see the TOTP policy in `architecture.md` §9.2). The code is single-use, expires in 10 minutes and burns after 5 wrong attempts. *UX note for Phase 6:* the laptop app will accept the Request ID and code as one pasted string.

## Build, publish, install

```bash
# On any machine with the .NET 8 SDK (tested on Linux, produces a Windows exe):
cd apps/desktop-agent
dotnet publish src/AarshRemote.Agent -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish   # ≈ 78 MB, no .NET install needed on the PC
```
On the PC (elevated PowerShell):
```powershell
.\scripts\install-agent.ps1 -Source .\publish -Server https://remote.example.com -Name NGP-WORKSTATION
```
The script copies files to `C:\Program Files\AarshRemote`, runs the pairing screen, registers and starts the service. It changes **nothing else**: no firewall rules, no Defender exclusions, no power settings. Remove with `.\scripts\uninstall-agent.ps1 [-RemoveData]`, then revoke the device in the app.

`C:\ProgramData\AarshRemote\config.json` (non-secret): `serverUrl, deviceName, serverCommandPublicKey, paired, heartbeatSeconds, metricsSeconds, forcePowerActions`.

## Firewall / network (spec §32, §52)

**No inbound rules are needed or created.** The agent's only connections:

| To | Port | Purpose |
|---|---|---|
| your server | 443 (HTTPS/WSS) | pairing (once), control channel, heartbeats |
| *(nothing else)* | | no telemetry, no update check yet |

RustDesk (Phase 5) adds its own connections, documented in `rustdesk.md`/`networking.md`.

## Tray

`AarshRemote.Tray.exe` (per user, optional): shows state, **Pause/Resume remote access** (local pause), **View logs**. The service never depends on it. The spec's "Open Dashboard / Settings / Restart Agent" entries are deferred (no dashboard yet; restarting a service needs elevation). ⚠ The WinForms project could not even be compiled in this sandbox (its SDK lacks the Windows Desktop workload); the Windows CI job builds it.

## Metrics (only what the dashboard shows)

CPU (`Processor Information\% Processor Utility`), RAM, system-drive %, NIC throughput, uptime, console-session state (`active/disconnected/none` — **lock screen is not detected**), and — only if `nvidia-smi.exe` exists in System32 — GPU load and temperature (fixed arguments, strict parsing). CPU temperature is **not** collected (needs a third-party kernel driver; see risk R7). A probe that fails is logged once and omitted.

## Known limitations

* Replay protection is in memory: a command captured and replayed within its ≤ 60 s lifetime *across an agent restart* would be accepted once. Low risk (TLS + signature + device binding); noted.
* The server's command key is pinned at pairing; rotating it needs `pair --force`. No key-rotation protocol yet.
* No auto-update / update notice yet (Phase 8).
* A service cannot show UI; anything interactive goes through the tray.
* Modern Standby (S0ix) PCs behave differently from classic S3 sleep for Wake-on-LAN — Phase 4's diagnostics will check this.

## ⚠ Verification checklist — run on the Windows PC

1. Install; reboot; confirm the service is *Running* and the dashboard shows **Online** with nobody logged in.
2. `sc qc AarshRemoteAgent` → `AUTO_START (DELAYED)`; `sc qfailure` → restart actions. Kill the process in Task Manager → it comes back in ~5 s.
3. `icacls C:\ProgramData\AarshRemote\identity.bin` → only SYSTEM and Administrators. Open it in a text editor → no readable key.
4. From the app: **Sleep** → PC sleeps (dashboard: *Sleeping*), wakes by Wake-on-LAN (Phase 4). Check it truly sleeps rather than hibernates.
5. From the app: **Restart** with Revit open and unsaved → Windows asks to close apps (expected, not forced). **Shutdown** likewise.
6. Put the PC to sleep **locally** (Start → Sleep): dashboard should say *Sleeping* (needs the power-event window, ⚠). If it says *Offline*, that component failed — the log will say "Power event monitoring is unavailable".
7. Create `C:\Program Files\AarshRemote\disable_remote_access.flag`: within ~2 s the dashboard shows "disabled on the PC" and every command is refused. Delete it: back to normal.
8. Tray: pause → commands refused even from the owner; resume.
9. Pull the network cable for a minute: agent reconnects by itself (log shows backoff then "Connected").
10. Check `Logs\` contains no tokens/passwords; Task Manager shows the agent idle (<1 % CPU).
11. Metrics on the dashboard: CPU/RAM/disk/network plausible; GPU only if NVIDIA.
