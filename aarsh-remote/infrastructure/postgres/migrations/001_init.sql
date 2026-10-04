CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TYPE device_status AS ENUM ('UNKNOWN','OFFLINE','SLEEPING','WAKE_REQUESTED','WAKING','ONLINE','ERROR');
CREATE TYPE session_state AS ENUM ('CONNECTING','CONNECTED','DISCONNECTED','ENDED','FAILED');
CREATE TYPE wake_status   AS ENUM ('REQUESTED','SENT','WAKING','SUCCEEDED','FAILED','TIMED_OUT');
CREATE TYPE agent_kind    AS ENUM ('DESKTOP','WAKE');
CREATE TYPE credential_state AS ENUM ('ACTIVE','REVOKED');

CREATE TABLE users (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email           citext NOT NULL UNIQUE,
  display_name    text   NOT NULL,
  password_hash   text   NOT NULL,
  totp_secret_enc bytea,
  totp_enabled    boolean NOT NULL DEFAULT false,
  totp_last_step  bigint,
  recovery_codes  text[]  NOT NULL DEFAULT '{}',
  role            text    NOT NULL DEFAULT 'owner' CHECK (role IN ('owner','admin','viewer')),
  failed_logins   int     NOT NULL DEFAULT 0,
  locked_until    timestamptz,
  disabled        boolean NOT NULL DEFAULT false,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE devices (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_uuid   uuid NOT NULL UNIQUE,
  name          text NOT NULL,
  owner_id      uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  status        device_status NOT NULL DEFAULT 'UNKNOWN',
  status_reason text,
  last_seen     timestamptz,
  mac_address   macaddr,
  local_ip      inet,
  broadcast_ip  inet,
  net_interface text,
  os            text,
  agent_version text,
  remote_paused boolean NOT NULL DEFAULT false,
  remote_disabled_locally boolean NOT NULL DEFAULT false,
  revoked_at    timestamptz,
  deleted_at    timestamptz,
  rustdesk_id   text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX devices_owner_idx ON devices(owner_id);

CREATE TABLE network_agents (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_uuid    uuid NOT NULL UNIQUE,
  name          text NOT NULL,
  owner_id      uuid NOT NULL REFERENCES users(id),
  status        text NOT NULL DEFAULT 'OFFLINE' CHECK (status IN ('ONLINE','OFFLINE')),
  last_seen     timestamptz,
  lan_cidr      cidr,
  agent_version text,
  revoked_at    timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE device_credentials (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id        uuid REFERENCES devices(id) ON DELETE CASCADE,
  network_agent_id uuid REFERENCES network_agents(id) ON DELETE CASCADE,
  public_key       bytea NOT NULL CHECK (octet_length(public_key) = 32),
  key_fingerprint  text NOT NULL UNIQUE,
  state            credential_state NOT NULL DEFAULT 'ACTIVE',
  created_at       timestamptz NOT NULL DEFAULT now(),
  revoked_at       timestamptz,
  last_used_at     timestamptz,
  CHECK ((device_id IS NOT NULL) <> (network_agent_id IS NOT NULL))
);

CREATE TABLE device_pairings (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind          agent_kind NOT NULL,
  device_uuid   uuid NOT NULL,
  device_name   text NOT NULL,
  public_key    bytea NOT NULL CHECK (octet_length(public_key) = 32),
  code_hash     bytea NOT NULL,
  attempts      int  NOT NULL DEFAULT 0,
  max_attempts  int  NOT NULL DEFAULT 5,
  expires_at    timestamptz NOT NULL,
  consumed_at   timestamptz,
  consumed_by   uuid REFERENCES users(id),
  paired_id     uuid,
  requester_ip  inet,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX device_pairings_open_idx ON device_pairings(expires_at) WHERE consumed_at IS NULL;

CREATE TABLE device_wake_routes (
  device_id        uuid REFERENCES devices(id) ON DELETE CASCADE,
  network_agent_id uuid REFERENCES network_agents(id) ON DELETE CASCADE,
  PRIMARY KEY (device_id)
);

CREATE TABLE refresh_tokens (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  family_id     uuid NOT NULL,
  token_hash    bytea NOT NULL UNIQUE,
  client_label  text,
  ip            inet,
  totp_verified boolean NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  used_at       timestamptz,
  revoked_at    timestamptz
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens(family_id);

CREATE TABLE wake_requests (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id        uuid NOT NULL REFERENCES devices(id),
  network_agent_id uuid REFERENCES network_agents(id),
  requested_by     uuid NOT NULL REFERENCES users(id),
  requested_at     timestamptz NOT NULL DEFAULT now(),
  sent_at          timestamptz,
  completed_at     timestamptz,
  status           wake_status NOT NULL DEFAULT 'REQUESTED',
  failure_reason   text,
  prior_state      device_status
);
CREATE INDEX wake_requests_device_idx ON wake_requests(device_id, requested_at DESC);

CREATE TABLE remote_sessions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id       uuid NOT NULL REFERENCES devices(id),
  user_id         uuid NOT NULL REFERENCES users(id),
  state           session_state NOT NULL DEFAULT 'CONNECTING',
  started_at      timestamptz NOT NULL DEFAULT now(),
  ended_at        timestamptz,
  client_ip       inet,
  connection_type text CHECK (connection_type IN ('P2P','RELAY','UNKNOWN')),
  provider        text NOT NULL DEFAULT 'rustdesk',
  latency_ms_avg  int,
  reconnect_count int NOT NULL DEFAULT 0,
  end_reason      text
);
CREATE INDEX remote_sessions_device_idx ON remote_sessions(device_id, started_at DESC);

CREATE TABLE audit_logs (
  id          bigserial PRIMARY KEY,
  ts          timestamptz NOT NULL DEFAULT now(),
  user_id     uuid REFERENCES users(id),
  device_id   uuid REFERENCES devices(id),
  action      text NOT NULL,
  result      text NOT NULL CHECK (result IN ('SUCCESS','FAILURE','DENIED')),
  ip          inet,
  user_agent  text,
  detail      jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_logs_ts_idx ON audit_logs(ts DESC);
CREATE INDEX audit_logs_device_idx ON audit_logs(device_id, ts DESC);

-- Append-only: enforced for every role (including the app role) by trigger.
CREATE FUNCTION audit_logs_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END $$;
CREATE TRIGGER audit_logs_no_update BEFORE UPDATE OR DELETE ON audit_logs FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();
CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_immutable();
