# RustDesk Research & Integration Plan

> **Verification status:** The facts below are from my existing knowledge of RustDesk OSS and are
> **not yet checked against the current docs/source** in this session (no network research was
> performed). Per spec §58 ("do not invent APIs"), **every item marked ⚠ VERIFY must be confirmed
> against rustdesk.com/docs and the pinned release's source before Phase 5 code is written.**
> Nothing in Phases 2–4 depends on unverified RustDesk details.

## 1. What RustDesk consists of

| Piece | Repo | License | Role |
|-------|------|---------|------|
| RustDesk client (Rust core + Flutter UI) | `rustdesk/rustdesk` | **AGPL-3.0** | Host service on the PC; viewer on the laptop |
| `hbbs` (ID/rendezvous server) | `rustdesk/rustdesk-server` | **AGPL-3.0** | ID registry, NAT-type test, hole-punch coordination, key distribution |
| `hbbr` (relay server) | `rustdesk/rustdesk-server` | **AGPL-3.0** | Relays encrypted streams when P2P fails |
| RustDesk Server **Pro** (API, address book, web console, OIDC…) | proprietary | Commercial | **Not used.** We replace its role with our control server. |

## 2. How hbbs / hbbr work (⚠ VERIFY ports/flags for pinned version)

* Each client, on start, registers with `hbbs` (UDP/TCP **21116**) and gets/keeps a numeric ID.
* To connect: viewer asks `hbbs` for the target → `hbbs` coordinates UDP hole punching; NAT-type
  test uses TCP **21115**. If direct fails → both sides connect out to `hbbr` TCP **21117**, which
  relays opaque encrypted bytes. Web-client ports 21118/21119 are **not needed** (we don't use the web client; keep them closed).
* `hbbs` generates `id_ed25519` / `id_ed25519.pub`. Clients configured with the server public key
  verify and encrypt to it. Running `hbbs -k _` rejects clients that don't have the key, so random
  Internet clients can't register or relay through our server.
* Official Docker image `rustdesk/rustdesk-server` runs `hbbs` and `hbbr` as two containers
  (host networking or published ports; persistent volume for the key pair).
* Session payload is end-to-end encrypted between peers (libsodium/NaCl) — the relay cannot read it.

## 3. Client configuration for self-hosting (⚠ VERIFY exact keys/CLI)

Clients need: ID server (`host:21116`), relay server, API server (unused), and the **public key**.
Supported methods (to be confirmed for the pinned version): GUI "Network" settings, a config
string import, and an installer/executable-name config convention. Plan: our installer/agent writes
the settings through a documented mechanism rather than editing internal files by guess.

## 4. Unattended access on Windows Home (⚠ VERIFY)

* RustDesk installs as a Windows **service** ("Install service" option); this lets it run before
  login and handle the lock screen/UAC secure desktop. Windows Home has **no built-in RDP host**,
  which is a non-issue here — RustDesk replaces it, and it means **port 3389 is never involved.**
* Unattended = a **permanent password** set on the host, no accept dialog. The RustDesk CLI has a
  `--password` option for setting it (⚠ confirm it needs the service/elevated context).
* **Our design (D6):** the Desktop Agent (SYSTEM) sets a fresh random one-time password at
  `PREPARE_CONNECT` and re-randomises it after the session ends or after a short TTL. The password
  is sent only to the authenticated client in the `CONNECT` response. Result: there is **no
  long-lived RustDesk credential** to leak. Failure mode: if the agent/server is down, you cannot
  connect (acceptable; the alternative is a standing secret). Optional break-glass: a separate
  strong permanent password in your password manager, *off by default*.
* RustDesk's access-control settings (⚠ VERIFY names): disable file transfer / clipboard /
  audio / keyboard, "approve mode = password only", and optional "only allow connections from IPs"
  — we will map our policy (clipboard on/off, file transfer off) onto them.

## 5. Integration options

| Option | Pros | Cons | Verdict |
|--------|------|------|---------|
| **A. Launch stock RustDesk binaries as separate processes** | AGPL boundary clear; upstream security updates; least code | Separate viewer window; depends on CLI/URI surface | **Chosen (v1)** |
| B. Embed RustDesk core (Rust crate / Flutter module) in Electron/agent | Single window, full control of HUD | Pulls AGPL into our code (our client would have to be AGPL-compatible and published); big build burden; tracks internal APIs that change | Rejected for v1 |
| C. Fork RustDesk | Max control | Own security patching forever; AGPL source duties | Rejected |
| D. Write own engine | — | Explicitly forbidden by spec §2 | Rejected |

Launch mechanics to verify: viewer launch by ID + password (CLI flag and/or `rustdesk://` URI
scheme) and whether the password can be passed without appearing in the process list (stdin/env/
URI vs. argv). If only argv is possible, the **one-time, short-TTL** password (D6) keeps the
exposure window tiny — another reason D6 exists.

## 6. Legal / licensing implications

* We **do not copy RustDesk source** into this repo. We run its official, unmodified binaries and
  Docker images and download them from official release channels at install/deploy time (pinned
  version + checksum).
* AGPL-3.0 §13 (network use ⇒ offer source) applies to *modified* versions. Unmodified hbbs/hbbr
  need no change from us; we will still link the upstream source and the exact version in docs.
* Our own code is a separate work communicating over a process boundary/CLI, not linking — so it
  can be licensed independently (project license decision Q4 — default proposal: **AGPL-3.0**
  for simplicity if we ever bundle, or MIT/Apache if strictly separate. Not legal advice.)
* The RustDesk name/logo are their trademarks; our UI uses its own branding and says
  "powered by RustDesk" only in the About/licenses screen.
* Redistribution: if the installer **bundles** RustDesk, `THIRD_PARTY_LICENSES.md` ships with the
  full AGPL text + source offer. Safer v1 alternative: installer **downloads** the official
  release and verifies its checksum.

## 7. Verification checklist (Phase 5, step 0 — before writing the provider)

- [ ] Pin a RustDesk release; record version + SHA-256
- [ ] Confirm ports and `-k _` behaviour for `rustdesk-server` at that version
- [ ] Confirm headless config mechanism for custom server + key
- [ ] Confirm CLI to set password and whether it works as SYSTEM service
- [ ] Confirm viewer launch syntax (ID, password, fullscreen, display selection)
- [ ] Confirm behaviour on lock screen and UAC prompt in service mode
- [ ] Confirm codec/hardware-encode options and what's tunable for Revit (FPS, quality, codec)
- [ ] Confirm multi-monitor selection and clipboard/file-transfer policy switches
- [ ] Measure latency/bandwidth: LAN, P2P over Internet, relay (VPS region comparison)
- [ ] Record all outbound connections observed (Wireshark/Resource Monitor) into `networking.md`
