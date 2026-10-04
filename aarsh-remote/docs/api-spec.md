# API Specification (draft v0.1)

Base: `https://<server>/api/v1`. JSON only. Errors: `{ "error": { "code": "ACCESS_DENIED", "message": "…" } }`.
This document is the contract. Request bodies are validated with strict zod schemas (unknown fields → `400 VALIDATION`). An OpenAPI export is deferred to Phase 6, when the client needs generated types.

Auth: `Authorization: Bearer <access JWT>` for user routes. Agents use WebSocket challenge-response (§WS).
Global limits (defaults): 100 req/min/IP; auth routes 5/min/IP + per-account lockout.

## Auth
| Method | Path | Notes |
|---|---|---|
| POST | `/auth/register` | `{email,password,displayName}` → `201`; only the **first** user, unless `REGISTRATION_ENABLED=true` |
| POST | `/auth/login` | `{email,password,totp?}` → `{accessToken,refreshToken,expiresIn}`; 401 `ACCESS_DENIED` generic message; `TOTP_REQUIRED` step-up |
| POST | `/auth/refresh` | `{refreshToken}` → rotated pair; reuse ⇒ family revoked |
| POST | `/auth/logout` | revoke current family |
| POST | `/auth/totp/enroll` · `/auth/totp/verify` | enrol / confirm TOTP, returns recovery codes once |
| POST | `/auth/password` | change password (re-auth), revokes other families |

## Devices
| Method | Path | Notes |
|---|---|---|
| GET | `/devices` | owned devices + status summary |
| GET | `/devices/:id` | detail |
| PATCH | `/devices/:id` | rename, WoL settings (`mac`, `broadcast`, `wakeAgentId`) |
| DELETE | `/devices/:id` | remove (soft; keeps audit) |
| POST | `/devices/:id/revoke` | revoke device credential — forces agent disconnect |
| POST | `/devices/:id/pause` · `/resume` | pause/resume remote access (server-side) |
| POST | `/devices/:id/pair` | `{code}` — user claims a pairing request (see below) |
| POST | `/devices/:id/wake` | body `{}` → `202 {wakeRequestId}`; progress via WS (`device.state`, `wake.progress`); `503 WAKE_AGENT_UNREACHABLE`, `409` if already online/waking, `400` if MAC/wake agent not configured |
| POST | `/devices/:id/connect` | → `{sessionId, provider:"rustdesk", rustdeskId, oneTimePassword, serverConfig}`; **TOTP step-up** |
| POST | `/devices/:id/disconnect` | `{sessionId}` |
| POST | `/devices/:id/sleep` · `/restart` · `/shutdown` | body `{confirm:true, totp?, delaySeconds?}`; `restart`/`shutdown` need a fresh `totp`; unknown fields rejected |
| GET | `/devices/:id/status` | state + diagnostics (`reasons[]`) |
| GET | `/devices/:id/metrics` | latest snapshot (+ optional `?range=` if history enabled) |
| GET | `/wake-requests?deviceId=` | history |

## Pairing (agent side, unauthenticated but heavily limited)
| Method | Path | Notes |
|---|---|---|
| POST | `/pairing/requests` | agent sends `{deviceUuid,name,publicKey}` → `{requestId, code, expiresAt}`; 3/hour/IP |
| GET | `/pairing/requests/:requestId` | agent polls (signed with its key) until `paired` |

User claims with `POST /devices/:id/pair` where `:id` is the requestId; wrong code increments `attempts`, 5th failure burns the request.

## Wake agents
`GET/POST/DELETE /network-agents`, `POST /network-agents/:id/pair` (same code flow), `PUT /devices/:id/wake-route`.

## Sessions, audit, admin
| Method | Path | Notes |
|---|---|---|
| GET | `/sessions` | paged, filter by device/user/date |
| GET | `/audit-logs` | paged, filter; read-only |
| GET | `/updates/latest?component=…` | **Not implemented yet** (Phase 8). Agents are already rejected below `MIN_AGENT_VERSION` (close code 4426) |
| GET | `/healthz` | liveness only, no data |

## WebSocket

### `/ws/client` (user)
Auth: first message `{type:"auth", accessToken}` within 5 s (token never in URL).
Server → client events:
`device.state {deviceId,status,reason?,lastSeen}`, `device.metrics {…}`,
`wake.progress {wakeRequestId,stage,pct?}`, `command.result {commandId,ok,error?}`,
`session.state {sessionId,state}`, `notice {level,text}`.
Client → server: `ping`, `subscribe {deviceIds[]}`, `session.heartbeat {sessionId, rttMs}`.

### `/ws/agent` (desktop agent & wake agent)
1. Server → `{type:"challenge", nonce, serverOrigin, ts}`
2. Agent → `{type:"hello", deviceUuid, kind, version, sig}` where `sig = Ed25519(nonce‖deviceUuid‖serverOrigin‖ts)`
3. Server verifies against `device_credentials` (ACTIVE, not revoked) → `{type:"ready", heartbeatSec:15}`; otherwise close `4401`.

Agent → server: `heartbeat {uptime,sessionState,remoteDisabled}`, `metrics {…}`,
`event {GOING_TO_SLEEP|RESUMED|NETWORK_CHANGED|REMOTE_DISABLED|…}`, `ack {commandId,ok,error?}`,
wake agent: `wake.sent {commandId}`, `lan.probe {deviceUuid, reachable, ms}`.

Server → agent: **command envelope**

```json
{
  "type": "command",
  "id": "uuid",
  "cmd": "SLEEP",                 // closed enum
  "args": {},                     // typed per cmd; schema-validated; no free-form strings executed
  "issuedAt": 1790000000,
  "expiresAt": 1790000030,        // ≤30 s
  "nonce": "base64-16B",
  "deviceUuid": "uuid",
  "sig": "base64 Ed25519(server signing key over canonical JSON of the fields above)"
}
```

## Command allow-list (single source of truth in `packages/protocol`)
`WAKE` (→ wake agent) · `SLEEP` · `RESTART` · `SHUTDOWN` · `PREPARE_CONNECT` · `CONNECT`(client-side orchestration) ·
`DISCONNECT` · `GET_STATUS` · `GET_METRICS` · `PAUSE_REMOTE` · `RESUME_REMOTE`.
Anything else → `400 UNKNOWN_COMMAND`, audited as DENIED. There is **no** generic execute/shell command.

## Error codes
`ACCESS_DENIED`, `TOTP_REQUIRED`, `RATE_LIMITED`, `DEVICE_REVOKED`, `REMOTE_PAUSED`, `REMOTE_DISABLED_LOCALLY`,
`DEVICE_OFFLINE`, `WAKE_AGENT_UNREACHABLE`, `WAKE_NO_RESPONSE`, `COMMAND_TIMEOUT`, `UNKNOWN_COMMAND`,
`AGENT_OUTDATED`, `PAIRING_EXPIRED`, `PAIRING_ATTEMPTS_EXCEEDED`.

## Implementation notes (Phase 2)
* Base path is `/api/v1`; WebSockets are at `/ws/client` and `/ws/agent`; `/healthz` is unauthenticated and returns `{ok:true}` only.
* Not-owner and not-found are both `404` (no device enumeration).
* WebSocket close codes: `4400` malformed, `4401` auth failed/expired, `4403` revoked, `4408` handshake timeout, `4409` replaced by a newer connection, `4426` agent outdated.
* `ack` messages may carry `data`; `PREPARE_CONNECT` must return `{rustdeskId, oneTimePassword(≥8 chars)}` — it is passed to the caller once and never stored or logged.
* Client → server `session.report {sessionId,state,connectionType?,rttMs?}` updates the caller's own session row (counts reconnects).
* Other WS pushes: `network-agent.state`, `lan.probe`.
* Added: `GET /network-agents`, `GET /wake-requests`, `POST /devices/:id/pause|resume`, `DELETE /devices/:id` (soft delete).
* `PATCH /devices/:id` accepts `{name, macAddress, broadcastIp, localIp, netInterface, wakeAgentId}`.
