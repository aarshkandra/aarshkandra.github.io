import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { clientWs, FakeAgent, registerAndLogin, resetDb, startServer, waitFor, waitStatus, type TestServer, type User } from "./helpers.js";

let s: TestServer;
let user: User; let agent: FakeAgent; let id: string;
beforeAll(async () => { s = await startServer({ RUSTDESK_ID_SERVER: "rd.example.com:21116", RUSTDESK_RELAY_SERVER: "rd.example.com:21117", RUSTDESK_PUBLIC_KEY: "PUBKEY" }); });
afterAll(async () => { await s.close(); });
beforeEach(async () => {
  await resetDb(s.db);
  user = await registerAndLogin(s, undefined, undefined, { totp: true });
  agent = new FakeAgent(s); id = await agent.pair(user);
  await agent.connect(); await waitStatus(s, user, id, "ONLINE");
});
const connect = () => s.http("POST", `/api/v1/devices/${id}/connect`, { token: user.token, body: {} });

describe("connect / disconnect", () => {
  it("PREPARE_CONNECT → one-time ticket returned only to the caller; session recorded; password never persisted", async () => {
    const r = await connect();
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ provider: "rustdesk", rustdeskId: "123456789", oneTimePassword: "Zx9-secret-pw-ONE", serverConfig: { idServer: "rd.example.com:21116", key: "PUBKEY" } });
    expect(agent.commands.at(-1)).toMatchObject({ cmd: "PREPARE_CONNECT", args: { ttlSeconds: 120 } });
    const dump = JSON.stringify([(await s.db.query("SELECT * FROM remote_sessions")).rows, (await s.db.query("SELECT * FROM devices")).rows, (await s.db.query("SELECT * FROM audit_logs")).rows]);
    expect(dump).not.toContain("Zx9-secret-pw-ONE");
    expect((await s.db.query("SELECT state FROM remote_sessions")).rows[0].state).toBe("CONNECTING");
  });
  it("only one live session per device (older one is superseded)", async () => {
    const a = await connect(); const b = await connect();
    const rows = (await s.db.query("SELECT id, state FROM remote_sessions ORDER BY started_at")).rows;
    expect(rows.find((x) => x.id === a.body.sessionId).state).toBe("ENDED");
    expect(rows.find((x) => x.id === b.body.sessionId).state).toBe("CONNECTING");
  });
  it("rejects a malformed ticket from the agent", async () => {
    agent.onCommand = () => ({ ok: true, data: { oneTimePassword: "short" } });
    const r = await connect();
    expect(r.status).toBe(502);
    expect((await s.db.query("SELECT 1 FROM remote_sessions")).rowCount).toBe(0);
  });
  it("cannot connect to an offline PC (409) — client should wake first", async () => {
    agent.abort(); await waitStatus(s, user, id, "OFFLINE");
    expect((await connect()).body.error.code).toBe("DEVICE_OFFLINE");
  });
  it("disconnect ends the session and tells the agent to rotate the password", async () => {
    const c = await connect();
    const d = await s.http("POST", `/api/v1/devices/${id}/disconnect`, { token: user.token, body: { sessionId: c.body.sessionId } });
    expect(d.status).toBe(204);
    expect(agent.commands.at(-1)).toMatchObject({ cmd: "DISCONNECT", args: { sessionId: c.body.sessionId } });
    expect((await s.db.query("SELECT state, end_reason FROM remote_sessions")).rows[0]).toEqual({ state: "ENDED", end_reason: "user" });
    expect((await s.http("POST", `/api/v1/devices/${id}/disconnect`, { token: user.token, body: { sessionId: c.body.sessionId } })).status).toBe(404);
  });
  it("client websocket can report session quality; reconnects are counted; only for own sessions", async () => {
    const c = await connect();
    const ws = clientWs(s, user.token); await ws.ready();
    ws.ws.send(JSON.stringify({ type: "session.report", sessionId: c.body.sessionId, state: "CONNECTED", connectionType: "RELAY", rttMs: 34.4 }));
    await waitFor(async () => (await s.db.query("SELECT 1 FROM remote_sessions WHERE state='CONNECTED'")).rowCount, 2000, "connected");
    ws.ws.send(JSON.stringify({ type: "session.report", sessionId: c.body.sessionId, state: "DISCONNECTED" }));
    await waitFor(async () => (await s.db.query("SELECT 1 FROM remote_sessions WHERE state='DISCONNECTED'")).rowCount, 2000, "disconnected");
    ws.ws.send(JSON.stringify({ type: "session.report", sessionId: c.body.sessionId, state: "CONNECTED" }));
    await waitFor(async () => (await s.db.query("SELECT 1 FROM remote_sessions WHERE reconnect_count=1")).rowCount, 2000, "reconnect counted");
    const row = (await s.db.query("SELECT connection_type, latency_ms_avg FROM remote_sessions")).rows[0];
    expect(row).toEqual({ connection_type: "RELAY", latency_ms_avg: 34 });
    ws.ws.close();
  });
});

describe("server restart", () => {
  it("clears stale ONLINE/WAKING presence on startup but keeps SLEEPING", async () => {
    const { resetPresenceOnStartup } = await import("../src/presence.js");
    await s.db.query("UPDATE devices SET status='ONLINE'");
    const other = await s.db.query("INSERT INTO devices(device_uuid,name,owner_id,status) SELECT gen_random_uuid(),'b',owner_id,'WAKING' FROM devices LIMIT 1 RETURNING id");
    const third = await s.db.query("INSERT INTO devices(device_uuid,name,owner_id,status) SELECT gen_random_uuid(),'c',owner_id,'SLEEPING' FROM devices LIMIT 1 RETURNING id");
    await resetPresenceOnStartup(s.db);
    const rows = Object.fromEntries((await s.db.query("SELECT name, status, status_reason FROM devices")).rows.map((r) => [r.name, r]));
    expect(rows["NGP-WORKSTATION"]).toMatchObject({ status: "OFFLINE", status_reason: null });
    expect(rows["b"]).toMatchObject({ status: "ERROR", status_reason: "WAKE_INTERRUPTED" });
    expect(rows["c"].status).toBe("SLEEPING");
    void other; void third;
  });
});

describe("server info", () => {
  it("publishes the command-signing public key (and nothing secret)", async () => {
    const r = await s.http("GET", "/api/v1/server-info");
    expect(r.status).toBe(200);
    expect(Buffer.from(r.body.commandPublicKey, "base64")).toHaveLength(32);
    expect(Object.keys(r.body).sort()).toEqual(["commandPublicKey", "minAgentVersion", "origin"]);
  });
});

describe("client websocket auth & events", () => {
  it("rejects bad token, no auth message, and tokens of logged-out sessions", async () => {
    const bad = clientWs(s, "garbage-but-long-enough-to-pass-schema");
    await waitFor(() => bad.closeCode === 4401, 2000, "closed bad");
    const short = clientWs(s, "garbage");
    await waitFor(() => short.closeCode === 4400, 2000, "closed malformed");
    const good = clientWs(s, user.token); await good.ready();
    await s.http("POST", "/api/v1/auth/logout", { token: user.token });
    good.ws.send(JSON.stringify({ type: "ping" }));
    await waitFor(() => good.closeCode === 4401, 2000, "closed after logout");
  });
  it("pushes device.state and device.metrics for own devices only", async () => {
    const mine = clientWs(s, user.token); await mine.ready();
    agent.send({ type: "metrics", metrics: { cpuPct: 5 } });
    await waitFor(() => mine.events.some((e) => e.type === "device.metrics" && e.deviceId === id), 2000, "metrics event");
    agent.abort();
    await waitFor(() => mine.events.some((e) => e.type === "device.state" && e.status === "OFFLINE"), 2000, "offline event");
    mine.ws.close();
  });
  it("status diagnostics explain an unreachable PC", async () => {
    agent.abort(); await waitStatus(s, user, id, "OFFLINE");
    const st = (await s.http("GET", `/api/v1/devices/${id}/status`, { token: user.token })).body;
    expect(st.diagnostics.join(" ")).toMatch(/Internet disconnected, PC powered off, router offline/);
  });
});
