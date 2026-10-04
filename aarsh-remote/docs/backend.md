# Backend (Phase 2)

`apps/backend` — Fastify 5 + TypeScript + PostgreSQL 16. Shared contract in `packages/protocol`.

## What exists
* **Auth:** register-first-owner, Argon2id (+ server pepper), JWT (EdDSA, 10 min), rotating refresh tokens with reuse detection, TOTP + recovery codes, lockout with backoff, per-IP rate limits.
* **Devices:** list/detail/update/revoke/soft-delete/pause/resume, ownership-scoped (404 for others).
* **Pairing:** agent-initiated, 6-digit HMAC-stored code, 10 min expiry, single use, 5 attempts, per-IP limits; works for PCs and Wake Agents.
* **Gateways:** `/ws/agent` (Ed25519 challenge-response bound to nonce+uuid+server origin+timestamp), `/ws/client` (JWT, closes on logout/expiry).
* **Presence + state machine** (`state-machine.ts`, pure and property-tested), heartbeat reaping, sleep-vs-offline.
* **Command broker:** closed allow-list, strict arg schemas, server-signed ≤60 s envelopes, ack matching (only the addressed agent can ack).
* **Wake:** request → Wake Agent → WAKING → ONLINE / timeout → ERROR with reasons; persisted in `wake_requests`.
* **Connect:** `PREPARE_CONNECT` → one-time RustDesk ticket to the caller; session rows; client-reported quality.
* **Audit:** every command attempt (success/denied/failure), append-only by DB trigger, secrets filtered.

## Run locally
```bash
pnpm install
node scripts/gen-secrets.mjs            # prints keys; export them (plus DATABASE_URL, SERVER_ORIGIN) or put in a .env loader of your choice
pnpm --filter @aarsh/backend migrate    # or let the server migrate on start
pnpm --filter @aarsh/backend dev
```
Required env: `DATABASE_URL SERVER_ORIGIN JWT_PRIVATE_KEY COMMAND_SIGNING_KEY TOTP_ENC_KEY PEPPER`. Everything else has a default (see `src/config.ts`; `infrastructure/docker/.env.example` lists the common ones).

## Tests
Integration tests use a **real PostgreSQL** (no mocks) and fake agents that speak the real protocol and verify the signed envelopes.
```bash
export TEST_ADMIN_DATABASE_URL=postgres://postgres@localhost:5433/postgres   # any superuser URL; the suite (re)creates DB `aarsh_test`
pnpm test
```
Coverage by spec §49/§50 scenario: sleeping→wake→online (×5), wake agent unavailable, invalid auth → `ACCESS_DENIED`, agent reconnect/replace, revocation, pause/local-disable, token expiry + reuse, pairing limits, rate limits, command validation, audit integrity. Agent-restart and laptop-network-change scenarios are exercised at the control-plane level (drop → OFFLINE → reconnect → ONLINE); the real Windows service/client behaviour is tested in Phases 3 and 6.

## Deploy (Docker Compose — **not yet exercised**: no Docker daemon was available while building Phase 2)
```bash
cd infrastructure/docker && cp .env.example .env   # fill with gen-secrets output; set DOMAIN + SERVER_ORIGIN
docker compose --env-file .env up -d --build
```
Postgres and the backend publish no ports; only Caddy listens (80/443, automatic TLS for your domain). The built bundle itself was smoke-tested with `node dist/server.js` against Postgres. Treat the Compose/Dockerfile as unverified until the first real deploy.

## Restart behaviour
Presence is in memory, so on startup the server clears stale statuses (`ONLINE → OFFLINE`, interrupted `WAKING → ERROR WAKE_INTERRUPTED`, open wake requests `FAILED SERVER_RESTARTED`; `SLEEPING` is kept). Agents reconnect within seconds and flip back to ONLINE. This was found by the end-to-end test: without it a restarted server showed devices ONLINE that nobody had reconnected.

## Known limitations / follow-ups
* Single server instance only (in-memory presence/hub, per-instance rate-limit store). Fine for one owner.
* WebSocket upgrade requests aren't individually rate-limited (they authenticate in-protocol within 5–10 s and are payload-capped at 64 KB).
* Password policy is length + denylist, not zxcvbn.
* No `/updates/latest` yet (Phase 8). No admin web dashboard yet.
* `pnpm audit --prod` (no known vulnerabilities) and `dotnet list package --vulnerable` (none) were run during Phase 3 and are wired into CI; the full Phase 7 review is still to come.
