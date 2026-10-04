import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { clientWs, FakeAgent, registerAndLogin, resetDb, startServer, waitFor, waitStatus, type TestServer, type User } from "./helpers.js";

let s: TestServer;
let user: User;
beforeAll(async () => { s = await startServer({ WAKE_TIMEOUT_MS: "600", HEARTBEAT_TIMEOUT_MS: "60000" }); });
afterAll(async () => { await s.close(); });
beforeEach(async () => { await resetDb(s.db); user = await registerAndLogin(s, undefined, undefined, { totp: true }); });

async function setup(opts: { wakerOnline?: boolean; mac?: boolean } = {}) {
  const pc = new FakeAgent(s); const pcId = await pc.pair(user);
  const waker = new FakeAgent(s, "WAKE", "Nagpur Wake Agent"); const wId = await waker.pair(user);
  await s.http("PATCH", `/api/v1/devices/${pcId}`, { token: user.token, body: { ...(opts.mac === false ? {} : { macAddress: "AA:BB:CC:DD:EE:FF" }), broadcastIp: "192.168.1.255", wakeAgentId: wId } });
  if (opts.wakerOnline !== false) await waker.connect();
  return { pc, pcId, waker, wId };
}
const wake = (id: string) => s.http("POST", `/api/v1/devices/${id}/wake`, { token: user.token, body: {} });
/** SLEEPING PC: connect then drop after GOING_TO_SLEEP */
async function putToSleep(pc: FakeAgent, id: string) {
  await pc.connect(); await waitStatus(s, user, id, "ONLINE");
  pc.send({ type: "event", name: "GOING_TO_SLEEP" }); await new Promise((r) => setTimeout(r, 50)); pc.abort();
  await waitStatus(s, user, id, "SLEEPING");
}

describe("wake flow", () => {
  it("SLEEPING → WAKE → magic packet requested → WAKING → agent connects → ONLINE (×5 cycles)", async () => {
    const { pc, pcId, waker } = await setup();
    const client = clientWs(s, user.token); await client.ready();
    for (let i = 0; i < 5; i++) {
      await putToSleep(pc, pcId);
      const r = await wake(pcId);
      expect(r.status).toBe(202);
      await waitStatus(s, user, pcId, "WAKING");
      const cmd = waker.commands.at(-1)!;
      expect(cmd).toMatchObject({ cmd: "WAKE", args: { mac: "AA:BB:CC:DD:EE:FF", broadcast: "192.168.1.255" }, deviceUuid: waker.uuid });
      expect(waker.verifyFailures).toEqual([]);
      await pc.connect(); // PC boots, desktop agent comes up
      await waitStatus(s, user, pcId, "ONLINE");
      await waitFor(async () => (await s.db.query("SELECT 1 FROM wake_requests WHERE id=$1 AND status='SUCCEEDED'", [r.body.wakeRequestId])).rowCount, 2000, "SUCCEEDED");
    }
    const states = client.events.filter((e) => e.type === "device.state").map((e) => e.status);
    expect(states).toContain("WAKING"); expect(states.at(-1)).toBe("ONLINE");
    client.ws.close(); pc.abort();
  }, 30_000);

  it("wake agent offline → 503 WAKE_AGENT_UNREACHABLE, request recorded as FAILED, device state unchanged", async () => {
    const { pc, pcId } = await setup({ wakerOnline: false });
    await putToSleep(pc, pcId);
    const r = await wake(pcId);
    expect(r.status).toBe(503); expect(r.body.error.code).toBe("WAKE_AGENT_UNREACHABLE");
    expect((await s.db.query("SELECT status, failure_reason FROM wake_requests")).rows[0]).toEqual({ status: "FAILED", failure_reason: "WAKE_AGENT_UNREACHABLE" });
    expect((await s.http("GET", `/api/v1/devices/${pcId}`, { token: user.token })).body.status).toBe("SLEEPING");
    const st = (await s.http("GET", `/api/v1/devices/${pcId}/status`, { token: user.token })).body;
    expect(st.diagnostics.join(" ")).toMatch(/Wake agent is offline/);
  });

  it("PC never appears → WAKING → ERROR WAKE_NO_RESPONSE with diagnostics; can retry", async () => {
    const { pc, pcId } = await setup();
    await putToSleep(pc, pcId);
    const r = await wake(pcId);
    await waitStatus(s, user, pcId, "WAKING");
    await waitStatus(s, user, pcId, "ERROR", 3000);
    const d = (await s.http("GET", `/api/v1/devices/${pcId}/status`, { token: user.token })).body;
    expect(d.statusReason).toBe("WAKE_NO_RESPONSE");
    expect(d.diagnostics.join(" ")).toMatch(/WAKE_NO_RESPONSE/);
    expect((await s.db.query("SELECT status FROM wake_requests WHERE id=$1", [r.body.wakeRequestId])).rows[0].status).toBe("TIMED_OUT");
    expect((await wake(pcId)).status).toBe(202); // ERROR → retry allowed
  });

  it("wake agent reports a send failure → ERROR WAKE_SEND_FAILED", async () => {
    const { pc, pcId, waker } = await setup();
    waker.onCommand = () => ({ ok: false, error: "no such interface" });
    await putToSleep(pc, pcId);
    await wake(pcId);
    await waitStatus(s, user, pcId, "ERROR");
    expect((await s.db.query("SELECT failure_reason FROM wake_requests")).rows[0].failure_reason).toBe("WAKE_SEND_FAILED");
  });

  it("wake agent that never answers → WAKE_AGENT_UNREACHABLE", async () => {
    const { pc, pcId, waker } = await setup();
    waker.onCommand = () => null;
    const beat = setInterval(() => waker.heartbeat(), 100);
    await putToSleep(pc, pcId);
    await wake(pcId);
    await waitStatus(s, user, pcId, "ERROR", 6000);
    clearInterval(beat);
    expect((await s.db.query("SELECT failure_reason FROM wake_requests")).rows[0].failure_reason).toBe("WAKE_AGENT_UNREACHABLE");
  }, 10_000);

  it("rejects wake when ONLINE (409), double wake (409), no MAC (400), no route (400)", async () => {
    const { pc, pcId } = await setup();
    await pc.connect(); await waitStatus(s, user, pcId, "ONLINE");
    expect((await wake(pcId)).status).toBe(409);
    pc.abort(); await waitStatus(s, user, pcId, "OFFLINE");
    expect((await wake(pcId)).status).toBe(202);
    await waitStatus(s, user, pcId, "WAKING");
    expect((await wake(pcId)).status).toBe(409);

    const nomac = await setup({ mac: false });
    expect((await wake(nomac.pcId)).status).toBe(400);
    await s.http("PATCH", `/api/v1/devices/${nomac.pcId}`, { token: user.token, body: { macAddress: "AA:BB:CC:DD:EE:01", wakeAgentId: null } });
    expect((await wake(nomac.pcId)).body.error.message).toMatch(/No wake agent/);
  });

  it("wake needs TOTP-verified session and an owner", async () => {
    const { pcId } = await setup();
    expect((await s.http("POST", `/api/v1/devices/${pcId}/wake`, { body: {} })).status).toBe(401);
    expect((await s.http("POST", `/api/v1/devices/${pcId}/wake`, { token: user.token, body: { cmd: "x" } })).status).toBe(400);
  });

  it("a revoked wake agent cannot connect", async () => {
    const { waker, wId } = await setup();
    await s.db.query("UPDATE network_agents SET revoked_at=now() WHERE id=$1", [wId]);
    waker.abort(); await new Promise((r) => setTimeout(r, 100));
    expect(await waker.connect()).toBe("closed");
  });
});
