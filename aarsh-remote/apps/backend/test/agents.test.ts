import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { FakeAgent, deviceStatus, registerAndLogin, resetDb, startServer, waitFor, waitStatus, type TestServer, type User } from "./helpers.js";

let s: TestServer;
let user: User;
beforeAll(async () => { s = await startServer({ MIN_AGENT_VERSION: "0.1.0", HEARTBEAT_TIMEOUT_MS: "400" }); });
afterAll(async () => { await s.close(); });
beforeEach(async () => { await resetDb(s.db); user = await registerAndLogin(s, undefined, undefined, { totp: true }); });

describe("agent connection auth", () => {
  it("accepts a paired agent and reports ONLINE", async () => {
    const a = new FakeAgent(s); const id = await a.pair(user);
    expect(await deviceStatus(s, user, id)).toBe("OFFLINE");
    expect(await a.connect()).toBe("ready");
    await waitStatus(s, user, id, "ONLINE");
    const d = (await s.http("GET", `/api/v1/devices/${id}`, { token: user.token })).body;
    expect(d.online).toBe(true); expect(d.os).toBe("Windows 11 Home"); expect(d.agentVersion).toBe("0.1.0");
    await a.close();
  });
  it("rejects a bad signature (ACCESS DENIED) and audits it", async () => {
    const a = new FakeAgent(s); await a.pair(user);
    expect(await a.connect({ sign: false })).toBe("closed");
    expect(a.closeCode).toBe(4401);
    expect((await s.db.query("SELECT 1 FROM audit_logs WHERE action='AGENT_AUTH' AND result='DENIED'")).rowCount).toBe(1);
  });
  it("device UUID alone is not a credential: a different key claiming a known uuid is refused", async () => {
    const real = new FakeAgent(s); await real.pair(user);
    const impostor = new FakeAgent(s); (impostor as any).uuid = real.uuid; // knows the uuid, not the key
    expect(await impostor.connect()).toBe("closed");
    expect(impostor.closeCode).toBe(4401);
  });
  it("rejects unknown devices", async () => {
    const a = new FakeAgent(s);
    expect(await a.connect()).toBe("closed");
    expect(a.closeCode).toBe(4401);
  });
  it("rejects wake-agent identity presented as a desktop (kind confusion)", async () => {
    const w = new FakeAgent(s, "WAKE"); await w.pair(user);
    (w as any).kind = "DESKTOP";
    expect(await w.connect()).toBe("closed");
  });
  it("rejects outdated agents", async () => {
    const strict = await startServer({ MIN_AGENT_VERSION: "1.0.0" });
    const u = await registerAndLogin(strict, undefined, undefined, { totp: true });
    const a = new FakeAgent(strict, "DESKTOP", "x", "0.9.0"); await a.pair(u);
    expect(await a.connect()).toBe("closed");
    expect(a.closeCode).toBe(4426);
    expect(a.messages.some((m) => m.type === "error" && m.code === "AGENT_OUTDATED")).toBe(true);
    await strict.close();
  });
  it("a hello that never arrives is closed", async () => {
    const { default: WebSocket } = await import("ws");
    const ws = new WebSocket(`${s.wsBase}/ws/agent`);
    ws.on("message", () => ws.send("not json"));
    const code = await new Promise((r) => ws.on("close", r));
    expect(code).toBe(4400);
  });
});

describe("presence", () => {
  it("clean drop without sleep notice → OFFLINE; with GOING_TO_SLEEP → SLEEPING", async () => {
    const a = new FakeAgent(s); const id = await a.pair(user);
    await a.connect(); await waitStatus(s, user, id, "ONLINE");
    a.abort(); await waitStatus(s, user, id, "OFFLINE");
    await a.connect(); await waitStatus(s, user, id, "ONLINE");
    a.send({ type: "event", name: "GOING_TO_SLEEP" });
    await new Promise((r) => setTimeout(r, 50));
    a.abort(); await waitStatus(s, user, id, "SLEEPING");
  });
  it("silent (half-open) connection is reaped by the heartbeat timeout", async () => {
    const a = new FakeAgent(s); const id = await a.pair(user);
    await a.connect(); await waitStatus(s, user, id, "ONLINE");
    await waitStatus(s, user, id, "OFFLINE", 3000);
    expect(a.closeCode).not.toBeNull();
  });
  it("heartbeats keep the device online", async () => {
    const a = new FakeAgent(s); const id = await a.pair(user);
    await a.connect(); await waitStatus(s, user, id, "ONLINE");
    const t = setInterval(() => a.heartbeat(), 100);
    await new Promise((r) => setTimeout(r, 1000));
    clearInterval(t);
    expect(await deviceStatus(s, user, id)).toBe("ONLINE");
    a.abort();
  });
  it("reconnect after a network drop returns to ONLINE and replaces a stale connection", async () => {
    const a = new FakeAgent(s); const id = await a.pair(user);
    await a.connect(); await waitStatus(s, user, id, "ONLINE");
    const old = a.ws;
    expect(await a.connect()).toBe("ready"); // second connection while first is still open
    await waitFor(() => old.readyState === 3, 2000, "old closed");
    await new Promise((r) => setTimeout(r, 100));
    expect(await deviceStatus(s, user, id)).toBe("ONLINE"); // replacing must not flap to OFFLINE
    a.abort();
  });
  it("metrics are validated and exposed; junk is ignored", async () => {
    const a = new FakeAgent(s); const id = await a.pair(user);
    await a.connect(); await waitStatus(s, user, id, "ONLINE");
    a.send({ type: "metrics", metrics: { cpuPct: 150 } });
    a.send({ type: "metrics", metrics: { cpuPct: 18, ramPct: 42, uptimeSec: 100 } });
    const m = await waitFor(async () => (await s.http("GET", `/api/v1/devices/${id}/metrics`, { token: user.token })).body.metrics, 3000, "metrics");
    expect(m).toMatchObject({ cpuPct: 18, ramPct: 42 });
    a.abort();
  });
  it("a device cannot ack a command that was sent to another device", async () => {
    const a = new FakeAgent(s, "DESKTOP", "A"); const b = new FakeAgent(s, "DESKTOP", "B");
    const ia = await a.pair(user); await b.pair(user);
    a.onCommand = () => null; // A stays silent
    await a.connect(); await b.connect(); await waitStatus(s, user, ia, "ONLINE");
    const beat = setInterval(() => { a.heartbeat(); b.heartbeat(); }, 100); // keep both alive; A just never acks
    const pending = s.http("POST", `/api/v1/devices/${ia}/sleep`, { token: user.token, body: { confirm: true } });
    const cmd = await waitFor(() => a.commands[0], 2000, "command at A");
    b.send({ type: "ack", commandId: cmd.id, ok: true }); // B tries to complete A's command
    const res = await pending;
    clearInterval(beat);
    expect(res.status).toBe(504);
    a.abort(); b.abort();
  });
});
