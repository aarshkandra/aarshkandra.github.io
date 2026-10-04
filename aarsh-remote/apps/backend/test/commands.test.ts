import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { clearTotpStep, FakeAgent, deviceStatus, registerAndLogin, resetDb, startServer, totpCode, waitFor, waitStatus, type TestServer, type User } from "./helpers.js";

let s: TestServer;
let user: User;
let agent: FakeAgent;
let id: string;
beforeAll(async () => { s = await startServer({ REGISTRATION_ENABLED: "true" }); });
afterAll(async () => { await s.close(); });
beforeEach(async () => {
  await resetDb(s.db);
  user = await registerAndLogin(s, undefined, undefined, { totp: true });
  agent = new FakeAgent(s); id = await agent.pair(user);
  await agent.connect(); await waitStatus(s, user, id, "ONLINE");
});
const post = (path: string, body: unknown = { confirm: true }, u = user) => s.http("POST", `/api/v1/devices/${id}/${path}`, { token: u.token, body });

describe("power commands", () => {
  it("SLEEP delivers a verifiable signed envelope; subsequent drop → SLEEPING", async () => {
    const r = await post("sleep");
    expect(r.status).toBe(200);
    expect(agent.commands).toHaveLength(1);
    expect(agent.commands[0]).toMatchObject({ cmd: "SLEEP", args: {}, deviceUuid: agent.uuid });
    expect(agent.verifyFailures).toEqual([]); // FakeAgent verified signature, expiry, device binding
    agent.abort();
    await waitStatus(s, user, id, "SLEEPING");
  });
  it("RESTART and SHUTDOWN need a fresh TOTP and are single-use per step", async () => {
    expect((await post("restart")).body.error.code).toBe("TOTP_REQUIRED");
    expect((await post("restart", { confirm: true, totp: "000000" })).status).toBe(401);
    await clearTotpStep(s);
    expect((await post("restart", { confirm: true, totp: totpCode(user.totpSecret!, 0) })).status).toBe(200);
    expect((await post("shutdown", { confirm: true, totp: totpCode(user.totpSecret!, 0) })).status).toBe(401); // replay of same step
    await clearTotpStep(s);
    expect((await post("shutdown", { confirm: true, totp: totpCode(user.totpSecret!, 0), delaySeconds: 5 })).status).toBe(200);
    expect(agent.commands.map((c) => [c.cmd, c.args])).toEqual([["RESTART", { delaySeconds: 0 }], ["SHUTDOWN", { delaySeconds: 5 }]]);
  });
  it("confirmation is mandatory (no accidental shutdown)", async () => {
    expect((await post("shutdown", {})).status).toBe(400);
    expect((await post("shutdown", { confirm: false })).status).toBe(400);
    expect(agent.commands).toHaveLength(0);
  });
  it("rejects extra/unknown body fields — no way to smuggle a command or arguments", async () => {
    expect((await post("sleep", { confirm: true, cmd: "calc.exe" })).status).toBe(400);
    expect((await post("restart", { confirm: true, delaySeconds: 9999, totp: "1" })).status).toBe(400);
    expect(agent.commands).toHaveLength(0);
  });
  it("there is no generic execute endpoint", async () => {
    for (const p of ["exec", "execute", "shell", "run", "command"]) expect((await post(p, { cmd: "whoami" })).status).toBe(404);
  });
  it("agent failure is reported as 502 COMMAND_FAILED; timeout as 504", async () => {
    agent.onCommand = () => ({ ok: false, error: "access denied by OS" });
    const bad = await post("sleep");
    expect(bad.status).toBe(502); expect(bad.body.error.code).toBe("COMMAND_FAILED");
    agent.onCommand = () => null;
    const beat = setInterval(() => agent.heartbeat(), 200);
    const slow = await post("sleep");
    clearInterval(beat);
    expect(slow.status).toBe(504); expect(slow.body.error.code).toBe("COMMAND_TIMEOUT");
  }, 10_000);
  it("a failed SLEEP does not leave the device marked as going to sleep", async () => {
    agent.onCommand = () => ({ ok: false, error: "x" });
    await post("sleep");
    agent.abort();
    await waitStatus(s, user, id, "OFFLINE");
  });
  it("offline device → 409 DEVICE_OFFLINE", async () => {
    agent.abort(); await waitStatus(s, user, id, "OFFLINE");
    const r = await post("sleep");
    expect(r.status).toBe(409); expect(r.body.error.code).toBe("DEVICE_OFFLINE");
  });
});

describe("authorization", () => {
  it("unauthenticated and foreign users cannot see or command a device (404, not 403)", async () => {
    expect((await s.http("POST", `/api/v1/devices/${id}/sleep`, { body: { confirm: true } })).status).toBe(401);
    // second user
    const other = await (async () => {
      const reg = await s.http("POST", "/api/v1/auth/register", { body: { email: "other@example.com", password: "purple monkey dishwasher", displayName: "O" } });
      expect(reg.status).toBe(201);
      const l = await s.http("POST", "/api/v1/auth/login", { body: { email: "other@example.com", password: "purple monkey dishwasher" } });
      return { token: l.body.accessToken, refresh: l.body.refreshToken } as User;
    })();
    expect((await s.http("GET", `/api/v1/devices/${id}`, { token: other.token })).status).toBe(404);
    expect((await s.http("POST", `/api/v1/devices/${id}/sleep`, { token: other.token, body: { confirm: true } })).status).toBe(404);
    expect((await s.http("POST", `/api/v1/devices/${id}/revoke`, { token: other.token })).status).toBe(404);
    expect((await s.http("PATCH", `/api/v1/devices/${id}`, { token: other.token, body: { name: "pwned" } })).status).toBe(404);
    expect((await s.http("GET", "/api/v1/devices", { token: other.token })).body.devices).toEqual([]);
    expect((await s.http("GET", "/api/v1/audit-logs", { token: other.token })).body.auditLogs.filter((a: any) => a.device_id === id)).toEqual([]);
    expect(agent.commands).toHaveLength(0);
  });
  it("session without TOTP login cannot run power commands when enforcement is on", async () => {
    const plain = await startServer();
    const u = await registerAndLogin(plain);
    const a = new FakeAgent(plain);
    // pairing itself needs TOTP, so insert the device directly
    const d = await plain.db.query("INSERT INTO devices(device_uuid,name,owner_id,status) VALUES (gen_random_uuid(),'x',$1,'OFFLINE') RETURNING id", [u.id]);
    const r = await plain.http("POST", `/api/v1/devices/${d.rows[0].id}/sleep`, { token: u.token, body: { confirm: true } });
    expect(r.status).toBe(403); expect(r.body.error.code).toBe("TOTP_ENROLLMENT_REQUIRED");
    void a;
    await plain.close();
  });
  it("pause blocks every command server-side and survives reconnects; resume restores", async () => {
    expect((await s.http("POST", `/api/v1/devices/${id}/pause`, { token: user.token })).status).toBe(204);
    const r = await post("sleep");
    expect(r.status).toBe(403); expect(r.body.error.code).toBe("REMOTE_PAUSED");
    expect((await post("connect", {})).body.error.code).toBe("REMOTE_PAUSED");
    expect((await s.http("POST", `/api/v1/devices/${id}/resume`, { token: user.token })).status).toBe(204);
    expect((await post("sleep")).status).toBe(200);
  });
  it("local emergency disable (reported by the agent) cannot be overridden remotely", async () => {
    agent.send({ type: "event", name: "REMOTE_DISABLED" });
    await waitFor(async () => (await s.http("GET", `/api/v1/devices/${id}`, { token: user.token })).body.remoteDisabledLocally, 3000, "flag");
    expect((await post("sleep")).body.error.code).toBe("REMOTE_DISABLED_LOCALLY");
    expect((await post("connect", {})).body.error.code).toBe("REMOTE_DISABLED_LOCALLY");
    expect((await s.http("POST", `/api/v1/devices/${id}/resume`, { token: user.token })).status).toBe(204);
    expect((await post("sleep")).body.error.code).toBe("REMOTE_DISABLED_LOCALLY"); // resume does not clear the local flag
    agent.send({ type: "event", name: "REMOTE_ENABLED" });
    await waitFor(async () => !(await s.http("GET", `/api/v1/devices/${id}`, { token: user.token })).body.remoteDisabledLocally, 3000, "flag cleared");
    expect((await post("sleep")).status).toBe(200);
  });
  it("revoking a device disconnects it immediately, blocks reconnect and commands", async () => {
    expect((await s.http("POST", `/api/v1/devices/${id}/revoke`, { token: user.token })).status).toBe(204);
    await waitFor(() => agent.closeCode !== null, 2000, "agent closed");
    expect(agent.closeCode).toBe(4403);
    expect(await agent.connect()).toBe("closed");
    expect(agent.closeCode).toBe(4401);
    expect((await post("sleep")).body.error.code).toBe("DEVICE_REVOKED");
    expect(await deviceStatus(s, user, id)).toBe("OFFLINE");
    expect((await s.db.query("SELECT state FROM device_credentials")).rows[0].state).toBe("REVOKED");
  });
  it("device settings validate MAC/IP and wake-agent ownership", async () => {
    const patch = (b: unknown) => s.http("PATCH", `/api/v1/devices/${id}`, { token: user.token, body: b });
    expect((await patch({ macAddress: "nope" })).status).toBe(400);
    expect((await patch({ broadcastIp: "999.1.1.1" })).status).toBe(400);
    expect((await patch({ wakeAgentId: "00000000-0000-4000-8000-000000000000" })).status).toBe(400);
    const ok = await patch({ macAddress: "AA:BB:CC:DD:EE:FF", broadcastIp: "192.168.1.255", name: "NGP WORKSTATION" });
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ macAddress: "aa:bb:cc:dd:ee:ff", broadcastIp: "192.168.1.255", name: "NGP WORKSTATION" });
  });
});

describe("audit trail", () => {
  it("records user, device, action, result, ip for success, denial and failure", async () => {
    await post("sleep"); // success
    await post("restart"); // denied (TOTP_REQUIRED, 401)
    agent.onCommand = () => ({ ok: false, error: "x" });
    await post("sleep"); // failure (502)
    const rows = (await s.http("GET", "/api/v1/audit-logs", { token: user.token, })).body.auditLogs.filter((a: any) => a.device_id === id && ["SLEEP", "RESTART"].includes(a.action));
    expect(rows.map((r: any) => `${r.action}:${r.result}`).sort()).toEqual(["RESTART:DENIED", "SLEEP:FAILURE", "SLEEP:SUCCESS"]);
    for (const r of rows) { expect(r.user_id).toBe(user.id); expect(r.ip).toBeTruthy(); }
  });
  it("is append-only at the database level", async () => {
    await post("sleep");
    await expect(s.db.query("UPDATE audit_logs SET result='SUCCESS'")).rejects.toThrow(/append-only/);
    await expect(s.db.query("DELETE FROM audit_logs")).rejects.toThrow(/append-only/);
    await expect(s.db.query("TRUNCATE audit_logs CASCADE")).rejects.toThrow(/append-only/);
  });
  it("never contains passwords, tokens, TOTP codes or one-time passwords", async () => {
    await post("connect", {});
    await post("restart", { confirm: true, totp: totpCode(user.totpSecret!, -1) });
    const all = JSON.stringify((await s.db.query("SELECT * FROM audit_logs")).rows);
    for (const secret of [user.token, user.refresh, user.totpSecret!, "correct horse battery staple", "Zx9-secret-pw-ONE"]) expect(all).not.toContain(secret);
  });
});
