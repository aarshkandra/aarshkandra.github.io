# Database Schema (PostgreSQL 16)

**Source of truth: [`infrastructure/postgres/migrations/001_init.sql`](../infrastructure/postgres/migrations/001_init.sql)** (applied by the built-in forward-only SQL migrator, `pnpm --filter @aarsh/backend migrate`; also runs on server start unless `AUTO_MIGRATE=false`). The SQL block below was the Phase 1 draft; the differences are listed after it. All timestamps `timestamptz` (UTC). IDs are UUIDv7/`gen_random_uuid()`.
Secrets are never stored in plaintext: passwords → Argon2id hash; refresh tokens, pairing codes,
recovery codes → HMAC/SHA-256 hash; TOTP secret → AES-256-GCM ciphertext; devices → **public key only**.

DB roles: `app_rw` (CRUD, but **INSERT/SELECT only on `audit_logs`**), `app_migrate` (DDL), `backup_ro`.

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TYPE device_status AS ENUM
  ('UNKNOWN','OFFLINE','SLEEPING','WAKE_REQUESTED','WAKING','ONLINE','ERROR');
  -- CONNECTING/CONNECTED/DISCONNECTED are session states (remote_sessions.state)

CREATE TYPE session_state AS ENUM ('CONNECTING','CONNECTED','DISCONNECTED','ENDED','FAILED');
CREATE TYPE wake_status  AS ENUM ('REQUESTED','SENT','WAKING','SUCCEEDED','FAILED','TIMED_OUT');
CREATE TYPE agent_kind   AS ENUM ('DESKTOP','WAKE');
CREATE TYPE credential_state AS ENUM ('ACTIVE','REVOKED');

CREATE TABLE users (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email           citext NOT NULL UNIQUE,
  display_name    text   NOT NULL,
  password_hash   text   NOT NULL,                 -- argon2id encoded string
  totp_secret_enc bytea,                           -- AES-256-GCM(nonce||ct||tag); NULL = not enrolled
  totp_enabled    boolean NOT NULL DEFAULT false,
  recovery_codes  text[]  NOT NULL DEFAULT '{}',   -- hashed, single-use (removed when used)
  role            text    NOT NULL DEFAULT 'owner' CHECK (role IN ('owner','admin','viewer')),
  failed_logins   int     NOT NULL DEFAULT 0,
  locked_until    timestamptz,
  disabled        boolean NOT NULL DEFAULT false,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE devices (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_uuid   uuid NOT NULL UNIQUE,              -- random, agent-generated; NOT a credential
  name          text NOT NULL,                     -- e.g. "NGP-WORKSTATION"
  owner_id      uuid REFERENCES users(id) ON DELETE RESTRICT,  -- NULL until paired
  status        device_status NOT NULL DEFAULT 'UNKNOWN',
  status_reason text,                              -- ERROR diagnostics
  last_seen     timestamptz,
  mac_address   macaddr,
  local_ip      inet,
  broadcast_ip  inet,
  net_interface text,
  os            text,
  agent_version text,
  remote_paused boolean NOT NULL DEFAULT false,    -- user-level pause
  remote_disabled_locally boolean NOT NULL DEFAULT false, -- reported by agent (flag file)
  revoked_at    timestamptz,                       -- device revocation (spec §3)
  rustdesk_id   text,                              -- reported by agent
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX devices_owner_idx ON devices(owner_id);

CREATE TABLE device_credentials (          -- one active row per agent; rotatable
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id     uuid REFERENCES devices(id) ON DELETE CASCADE,
  network_agent_id uuid,                           -- set instead of device_id for Wake Agents
  public_key    bytea NOT NULL,                    -- Ed25519 (32 bytes)
  key_fingerprint text NOT NULL UNIQUE,
  state         credential_state NOT NULL DEFAULT 'ACTIVE',
  created_at    timestamptz NOT NULL DEFAULT now(),
  revoked_at    timestamptz,
  last_used_at  timestamptz,
  CHECK ((device_id IS NOT NULL) <> (network_agent_id IS NOT NULL))
);

CREATE TABLE device_pairings (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_uuid   uuid NOT NULL,
  device_name   text NOT NULL,
  public_key    bytea NOT NULL,
  code_hash     bytea NOT NULL,                    -- HMAC(pepper, code)
  attempts      int  NOT NULL DEFAULT 0,
  max_attempts  int  NOT NULL DEFAULT 5,
  expires_at    timestamptz NOT NULL,              -- now()+10min
  consumed_at   timestamptz,                       -- single use
  consumed_by   uuid REFERENCES users(id),
  requester_ip  inet,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX device_pairings_open_idx ON device_pairings(expires_at) WHERE consumed_at IS NULL;

CREATE TABLE network_agents (               -- Wake Agents
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_uuid    uuid NOT NULL UNIQUE,
  name          text NOT NULL,                     -- "Nagpur Wake Agent"
  owner_id      uuid NOT NULL REFERENCES users(id),
  status        text NOT NULL DEFAULT 'OFFLINE' CHECK (status IN ('ONLINE','OFFLINE')),
  last_seen     timestamptz,
  lan_cidr      cidr,
  agent_version text,
  revoked_at    timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE device_credentials
  ADD FOREIGN KEY (network_agent_id) REFERENCES network_agents(id) ON DELETE CASCADE;

-- Which wake agent serves which device
CREATE TABLE device_wake_routes (
  device_id        uuid REFERENCES devices(id) ON DELETE CASCADE,
  network_agent_id uuid REFERENCES network_agents(id) ON DELETE CASCADE,
  PRIMARY KEY (device_id, network_agent_id)
);

CREATE TABLE refresh_tokens (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  family_id     uuid NOT NULL,                     -- rotation family (reuse ⇒ revoke family)
  token_hash    bytea NOT NULL UNIQUE,             -- SHA-256 of opaque token
  client_label  text,                              -- "Laptop Pune"
  ip            inet,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  used_at       timestamptz,
  revoked_at    timestamptz
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens(family_id);

CREATE TABLE wake_requests (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id      uuid NOT NULL REFERENCES devices(id),
  network_agent_id uuid REFERENCES network_agents(id),
  requested_by   uuid NOT NULL REFERENCES users(id),
  requested_at   timestamptz NOT NULL DEFAULT now(),
  sent_at        timestamptz,
  completed_at   timestamptz,
  status         wake_status NOT NULL DEFAULT 'REQUESTED',
  failure_reason text,                             -- WAKE_AGENT_UNREACHABLE | WAKE_NO_RESPONSE | …
  prior_state    device_status                     -- SLEEPING vs OFFLINE; for success-rate stats
);
CREATE INDEX wake_requests_device_idx ON wake_requests(device_id, requested_at DESC);

CREATE TABLE remote_sessions (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id      uuid NOT NULL REFERENCES devices(id),
  user_id        uuid NOT NULL REFERENCES users(id),
  state          session_state NOT NULL DEFAULT 'CONNECTING',
  started_at     timestamptz NOT NULL DEFAULT now(),
  ended_at       timestamptz,
  client_ip      inet,
  connection_type text CHECK (connection_type IN ('P2P','RELAY','UNKNOWN')),
  provider       text NOT NULL DEFAULT 'rustdesk',
  latency_ms_avg int,
  reconnect_count int NOT NULL DEFAULT 0,
  end_reason     text
);
CREATE INDEX remote_sessions_device_idx ON remote_sessions(device_id, started_at DESC);

CREATE TABLE audit_logs (                   -- append-only (no UPDATE/DELETE grants)
  id          bigserial PRIMARY KEY,
  ts          timestamptz NOT NULL DEFAULT now(),
  user_id     uuid REFERENCES users(id),
  device_id   uuid REFERENCES devices(id),
  action      text NOT NULL,                       -- LOGIN, WAKE, SLEEP, RESTART, SHUTDOWN, CONNECT, PAIR, REVOKE …
  result      text NOT NULL CHECK (result IN ('SUCCESS','FAILURE','DENIED')),
  ip          inet,
  user_agent  text,
  detail      jsonb NOT NULL DEFAULT '{}'          -- redacted; never tokens/passwords/keys
);
CREATE INDEX audit_logs_ts_idx ON audit_logs(ts DESC);
CREATE INDEX audit_logs_device_idx ON audit_logs(device_id, ts DESC);

-- Replay protection for signed command envelopes & agent challenges
CREATE TABLE used_nonces (
  nonce       bytea PRIMARY KEY,
  expires_at  timestamptz NOT NULL
);
CREATE INDEX used_nonces_exp_idx ON used_nonces(expires_at);   -- pruned periodically

-- Optional: coarse metrics history (retention 7 days). Off unless enabled.
CREATE TABLE device_metrics (
  device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  ts        timestamptz NOT NULL,
  cpu_pct real, ram_pct real, gpu_pct real, disk_pct real, temp_c real,
  net_rx_kbps int, net_tx_kbps int, latency_ms int, packet_loss_pct real,
  PRIMARY KEY (device_id, ts)
);
```

Changes vs. spec's minimum list: added `device_wake_routes`, `used_nonces`, `device_metrics`
(optional), and revocation/pause columns on `devices`. `device_credentials` also serves Wake Agents.

## Phase 2 deviations from the draft above (implemented in 001_init.sql)

| Change | Reason |
|---|---|
| Plain SQL migrator instead of `node-pg-migrate` | One fewer dependency; we only need forward-only, transactional, advisory-locked migrations |
| `devices.owner_id` is `NOT NULL`; devices are created **at pairing claim**, not at agent install | An unclaimed agent has no owner; the pending state lives in `device_pairings` |
| `device_pairings.kind` (`DESKTOP`/`WAKE`) and `paired_id` added | Same pairing flow for PCs and Wake Agents; lets the agent poll for completion |
| `devices.deleted_at` added | `DELETE /devices/:id` is a soft delete (revokes + hides, keeps audit history) |
| `users.totp_last_step` added | TOTP replay protection (a code is single-use per 30 s step) |
| `refresh_tokens.totp_verified` added | The session's TOTP status survives refresh (JWT claim `tv`) |
| `device_wake_routes` has `PRIMARY KEY (device_id)` | One wake agent per device in v1 |
| `audit_logs` append-only via **triggers** on UPDATE/DELETE/TRUNCATE (any role) | Works even though the app connects as a single DB role |
| `used_nonces` and `device_metrics` **not created** | Challenge nonces are per-connection and in-memory; command replay protection is the agent's job (signed, ≤60 s expiry, unique id); latest metrics are held in memory. Both can be added if history/replay storage is wanted |
