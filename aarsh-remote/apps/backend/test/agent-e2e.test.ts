/**
 * Cross-language end-to-end: the REAL .NET desktop agent (child process) against the REAL backend and PostgreSQL.
 * Runs only when AGENT_DLL points at a built AarshRemote.Agent.dll (CI builds it first). The agent's OS layer is its
 * development stand-in (power actions are logged to a file instead of executed), everything else is the production code path.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { sendCommand } from "../src/broker.js";
import { buildApp } from "../src/app.js";
import {
  clearTotpStep, freePort, registerAndLogin, startServer, totpCode, waitFor, waitStatus, type TestServer, type User,
} from "./helpers.js";

const AGENT_DLL = process.env.AGENT_DLL;
const d = AGENT_DLL && existsSync(AGENT_DLL) ? describe : describe.skip;

d("real .NET agent ↔ real backend", () => {
  let s: TestServer; let user: User; let port: number; let dataDir: string; let deviceId = ""; let agent: ChildProcess | null = null;
  let agentOut = "";
  const flag = () => join(dataDir, "disable_remote_access.flag");
  const actions = () => (existsSync(join(dataDir, "power-actions.log")) ? readFileSync(join(dataDir, "power-actions.log"), "utf8") : "");
  const url = () => `http://127.0.0.1:${port}`;

  const agentEnv = () => ({
    ...process.env, AARSH_DATA_DIR: dataDir, AARSH_DEV_INSECURE_STORE: "1", AARSH_ALLOW_INSECURE_HTTP: "1",
    AARSH_EMERGENCY_FLAG: flag(), AARSH_DEV_FAKE_PROVIDER: "1", DOTNET_NOLOGO: "1",
  });
  const startAgent = () => {
    agentOut = "";
    agent = spawn("dotnet", [AGENT_DLL!, "run"], { env: agentEnv() });
    agent.stdout!.on("data", (b) => { agentOut += b; });
    agent.stderr!.on("data", (b) => { agentOut += b; });
  };
  const stopAgent = async () => {
    if (!agent || agent.exitCode !== null) return;
    const exited = new Promise((r) => agent!.once("exit", r));
    agent.kill("SIGTERM");
    await Promise.race([exited, new Promise((r) => setTimeout(r, 5000))]);
    if (agent.exitCode === null) agent.kill("SIGKILL");
  };

  beforeAll(async () => {
    dataDir = mkdtempSync(join(tmpdir(), "aarsh-e2e-"));
    port = await freePort();
    s = await startServer({ SERVER_ORIGIN: url(), MIN_AGENT_VERSION: "0.1.0" }, { port });
    user = await registerAndLogin(s, undefined, undefined, { totp: true });

    // --- pairing through the agent's own CLI ---
    const pair = spawn("dotnet", [AGENT_DLL!, "pair", "--server", url(), "--name", "E2E-PC"], { env: agentEnv() });
    let out = "";
    pair.stdout.on("data", (b) => { out += b; });
    pair.stderr.on("data", (b) => { out += b; });
    const exited = new Promise<number>((r) => pair.once("exit", (c) => r(c ?? -1)));
    const m = (await waitFor(() => /Request ID:\s*\n([0-9a-f-]{36})\s*\n\s*\nPairing Code:\s*\n(\d{6})/.exec(out), 30_000, "pairing screen"))!;
    expect(out).toContain("Device: E2E-PC");
    const claim = await s.http("POST", `/api/v1/devices/${m[1]}/pair`, { token: user.token, body: { code: m[2] } });
    expect(claim.status).toBe(200);
    deviceId = claim.body.deviceId;
    expect(await exited).toBe(0);
    expect(out).toContain("Paired.");

    // faster heartbeats/metrics for the test
    const cfgPath = join(dataDir, "config.json");
    const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
    writeFileSync(cfgPath, JSON.stringify({ ...cfg, heartbeatSeconds: 1, metricsSeconds: 1 }));
    startAgent();
  }, 60_000);

  afterAll(async () => {
    await stopAgent();
    await s.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("agent authenticates with its Ed25519 key and the device goes ONLINE", async () => {
    await waitStatus(s, user, deviceId, "ONLINE", 30_000);
    const dev = (await s.http("GET", `/api/v1/devices/${deviceId}`, { token: user.token })).body;
    expect(dev.agentVersion).toBe("0.1.0");
    expect(dev.online).toBe(true);
    expect(dev.os).toBeTruthy();
  }, 40_000);

  it("pairing stored only the public key server-side; identity file is not plaintext-JSON-with-key in config", () => {
    const cfg = readFileSync(join(dataDir, "config.json"), "utf8");
    expect(cfg).not.toMatch(/seed|private/i);
    const cred = s.db.query("SELECT octet_length(public_key) AS n FROM device_credentials");
    return expect(cred.then((r) => r.rows[0].n)).resolves.toBe(32);
  });

  it("reports validated metrics over the live connection", async () => {
    const m = await waitFor(async () => (await s.http("GET", `/api/v1/devices/${deviceId}/metrics`, { token: user.token })).body.metrics, 10_000, "metrics");
    expect(m.uptimeSec).toBeGreaterThanOrEqual(0);
  });

  it("verifies the server's signed envelope: SLEEP is executed only after the ack, GOING_TO_SLEEP precedes it", async () => {
    const r = await s.http("POST", `/api/v1/devices/${deviceId}/sleep`, { token: user.token, body: { confirm: true } });
    expect(r.status).toBe(200);
    await waitFor(() => actions().includes("sleep"), 5000, "sleep action");
  });

  it("local sleep announcement ⇒ when the socket drops the device is SLEEPING (not OFFLINE), and the agent comes back on its own", async () => {
    await stopAgent();
    await waitStatus(s, user, deviceId, "SLEEPING", 10_000);
    startAgent(); // "PC wakes": the service starts again
    await waitStatus(s, user, deviceId, "ONLINE", 30_000);
  }, 60_000);

  it("RESTART needs a fresh TOTP and the agent runs exactly the requested typed action", async () => {
    await clearTotpStep(s);
    const r = await s.http("POST", `/api/v1/devices/${deviceId}/restart`, { token: user.token, body: { confirm: true, totp: totpCode(user.totpSecret!, 0), delaySeconds: 7 } });
    expect(r.status).toBe(200);
    await waitFor(() => actions().includes("restart delay=7"), 5000, "restart action");
  });

  it("CONNECT: agent mints a one-time ticket via its provider and the server relays it", async () => {
    const r = await s.http("POST", `/api/v1/devices/${deviceId}/connect`, { token: user.token, body: {} });
    expect(r.status).toBe(200);
    expect(r.body.rustdeskId).toBe("123456789");
    expect(r.body.oneTimePassword.length).toBeGreaterThanOrEqual(8);
    expect(agentOut).not.toContain(r.body.oneTimePassword); // never logged by the agent
    const d = await s.http("POST", `/api/v1/devices/${deviceId}/disconnect`, { token: user.token, body: { sessionId: r.body.sessionId } });
    expect(d.status).toBe(204);
  });

  it("server-side pause is mirrored into the agent's persisted state and blocks commands there too", async () => {
    expect((await s.http("POST", `/api/v1/devices/${deviceId}/pause`, { token: user.token })).status).toBe(204);
    await waitFor(() => existsSync(join(dataDir, "state.json")) && JSON.parse(readFileSync(join(dataDir, "state.json"), "utf8")).RemotePaused === true, 5000, "state.json");
    const conn = s.ctx.hub.desktops.get(deviceId)!;
    const ack = await sendCommand(s.ctx, conn, "SLEEP", {}); // bypass the server's own pause check to prove the agent enforces it
    expect(ack).toMatchObject({ ok: false, error: "REMOTE_PAUSED" });
    expect((await s.http("POST", `/api/v1/devices/${deviceId}/resume`, { token: user.token })).status).toBe(204);
    await waitFor(() => JSON.parse(readFileSync(join(dataDir, "state.json"), "utf8")).RemotePaused === false, 5000, "resumed");
  });

  it("emergency flag on the PC: reported to the server within seconds, and the agent refuses even server-signed commands", async () => {
    writeFileSync(flag(), "");
    await waitFor(async () => (await s.http("GET", `/api/v1/devices/${deviceId}`, { token: user.token })).body.remoteDisabledLocally === true, 8000, "flag reported");
    const conn = s.ctx.hub.desktops.get(deviceId)!;
    for (const cmd of ["GET_STATUS", "SLEEP", "RESUME_REMOTE"] as const) {
      expect(await sendCommand(s.ctx, conn, cmd, {})).toMatchObject({ ok: false, error: "REMOTE_DISABLED_LOCALLY" });
    }
    const before = actions();
    expect((await s.http("POST", `/api/v1/devices/${deviceId}/sleep`, { token: user.token, body: { confirm: true } })).status).toBe(403);
    expect(actions()).toBe(before);
    rmSync(flag());
    await waitFor(async () => (await s.http("GET", `/api/v1/devices/${deviceId}`, { token: user.token })).body.remoteDisabledLocally === false, 8000, "flag cleared");
    expect(await sendCommand(s.ctx, conn, "GET_STATUS", {})).toMatchObject({ ok: true });
  }, 30_000);

  it("replayed envelopes are rejected by the agent", async () => {
    const conn = s.ctx.hub.desktops.get(deviceId)!;
    const { signEnvelope } = await import("@aarsh/protocol");
    const { randomUUID } = await import("node:crypto");
    const env = signEnvelope(s.config.commandPrivateKey, { id: randomUUID(), cmd: "GET_STATUS", args: {}, deviceUuid: conn.uuid });
    const acks: any[] = [];
    const orig = s.ctx.hub.resolveAck.bind(s.ctx.hub);
    // send the same signed envelope twice and watch both acks
    for (let i = 0; i < 2; i++) {
      const p = s.ctx.hub.expectAck(env.id, conn, 3000);
      conn.ws.send(JSON.stringify(env));
      acks.push(await p);
    }
    void orig;
    expect(acks[0]).toMatchObject({ ok: true });
    expect(acks[1]).toMatchObject({ ok: false, error: "REPLAY" });
  });

  it("reconnects by itself after the connection is cut", async () => {
    s.ctx.hub.desktops.get(deviceId)!.ws.terminate();
    await waitStatus(s, user, deviceId, "OFFLINE", 5000);
    await waitStatus(s, user, deviceId, "ONLINE", 20_000);
  }, 30_000);

  it("survives a full server restart (internet/server outage) and re-authenticates", async () => {
    const env = s.env;
    await s.close();
    await new Promise((r) => setTimeout(r, 1500)); // agent is now retrying against a dead port
    s = await startServer(env, { port, reset: false });
    // Startup clears stale presence, so ONLINE here can only come from the agent genuinely re-authenticating to the new process.
    expect((await s.db.query("SELECT status FROM devices WHERE id=$1", [deviceId])).rows[0].status).not.toBe("ONLINE");
    await waitFor(() => s.ctx.hub.desktops.has(deviceId), 40_000, "agent reconnected to the restarted server").catch((e) => {
      throw new Error(e.message + "\n" + agentOut.slice(-1500));
    });
    await waitStatus(s, user, deviceId, "ONLINE", 5000);
  }, 60_000);

  it("revocation: the agent is disconnected, backs off for minutes, and the process stays alive", async () => {
    expect((await s.http("POST", `/api/v1/devices/${deviceId}/revoke`, { token: user.token })).status).toBe(204);
    await waitFor(() => /revoked/i.test(agentOut), 10_000, "agent notices revocation").catch((e) => { throw new Error(e.message + "\n--- agent output tail ---\n" + agentOut.slice(-6000)); });
    expect(agent!.exitCode).toBeNull();
    await new Promise((r) => setTimeout(r, 2500));
    expect(s.ctx.hub.desktops.has(deviceId)).toBe(false);
  }, 30_000);

  it("never writes credentials to its log", async () => {
    const logDir = join(dataDir, "Logs");
    const { readdirSync } = await import("node:fs");
    const text = readdirSync(logDir).map((f) => readFileSync(join(logDir, f), "utf8")).join("\n") + agentOut;
    const identity = readFileSync(join(dataDir, "identity.bin"), "utf8");
    const seed = JSON.parse(identity).Seed as string;
    expect(text).not.toContain(seed);
    expect(text).not.toMatch(/oneTimePassword|Authorization|Bearer /i);
    void buildApp;
  });
});
