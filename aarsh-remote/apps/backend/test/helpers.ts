import { generateKeyPairSync, randomUUID } from "node:crypto";
import { authenticator } from "otplib";
import WebSocket from "ws";
import {
  b64, generateEd25519, pairingPollInput, publicKeyFromRaw, signBytes, signHello, verifyEnvelope, type AgentKind, type CommandEnvelope,
} from "@aarsh/protocol";
import { buildApp } from "../src/app.js";
import { loadConfig, type Config } from "../src/config.js";
import { createDb, type Db } from "../src/db.js";

const pkcs8 = () => generateKeyPairSync("ed25519").privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");

export const PASSWORD = "correct horse battery staple";
export const EMAIL = "owner@example.com";

export function envFor(over: Record<string, string> = {}): Record<string, string> {
  return {
    NODE_ENV: "test", DATABASE_URL: process.env.TEST_DATABASE_URL!, SERVER_ORIGIN: "https://remote.test",
    JWT_PRIVATE_KEY: pkcs8(), COMMAND_SIGNING_KEY: pkcs8(),
    TOTP_ENC_KEY: Buffer.alloc(32, 7).toString("base64"), PEPPER: Buffer.alloc(32, 9).toString("base64"),
    RATE_LIMIT_GLOBAL_PER_MIN: "10000", RATE_LIMIT_LOGIN_PER_MIN: "10000", RATE_LIMIT_PAIRING_PER_HOUR: "10000", RATE_LIMIT_CLAIM_PER_MIN: "10000",
    COMMAND_TIMEOUT_MS: "3000", HEARTBEAT_SWEEP_MS: "50", ...over,
  };
}

export interface TestServer {
  config: Config; db: Db; ctx: Awaited<ReturnType<typeof buildApp>>["ctx"]; base: string; wsBase: string; close(): Promise<void>;
  http(method: string, path: string, opts?: { token?: string; body?: unknown; headers?: Record<string, string> }): Promise<{ status: number; body: any }>;
}

export async function startServer(over: Record<string, string> = {}): Promise<TestServer> {
  const config = loadConfig(envFor(over));
  const db = createDb(config.DATABASE_URL);
  await resetDb(db);
  const { app, ctx } = await buildApp(config, db, { logger: false });
  await app.listen({ port: 0, host: "127.0.0.1" });
  const port = (app.server.address() as { port: number }).port;
  const base = `http://127.0.0.1:${port}`;
  return {
    config, db, ctx, base, wsBase: `ws://127.0.0.1:${port}`,
    async close() { await app.close(); await db.end(); },
    async http(method, path, opts = {}) {
      const res = await fetch(base + path, {
        method,
        headers: { ...(opts.body !== undefined ? { "content-type": "application/json" } : {}), ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}), ...opts.headers },
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      });
      const text = await res.text();
      return { status: res.status, body: text ? JSON.parse(text) : null };
    },
  };
}

export async function resetDb(db: Db) {
  const c = await db.connect();
  try {
    await c.query("BEGIN");
    await c.query("SET LOCAL session_replication_role = replica"); // bypass the append-only audit triggers for test cleanup only
    await c.query("TRUNCATE users, devices, network_agents, device_credentials, device_pairings, device_wake_routes, refresh_tokens, wake_requests, remote_sessions, audit_logs CASCADE");
    await c.query("COMMIT");
  } finally { c.release(); }
}

/** TOTP code `offset` steps from now (server accepts -1..+1). Distinct offsets give distinct single-use codes. */
export function totpCode(secret: string, offset = 0): string {
  const prev = authenticator.options;
  authenticator.options = { ...prev, epoch: Date.now() + offset * 30_000 };
  try { return authenticator.generate(secret); } finally { authenticator.options = prev; }
}

export interface User { token: string; refresh: string; totpSecret?: string; id?: string }

export async function registerAndLogin(s: TestServer, email = EMAIL, password = PASSWORD, opts: { totp?: boolean } = {}): Promise<User> {
  const reg = await s.http("POST", "/api/v1/auth/register", { body: { email, password, displayName: "Owner" } });
  if (reg.status !== 201) throw new Error(`register failed ${reg.status} ${JSON.stringify(reg.body)}`);
  let login = await s.http("POST", "/api/v1/auth/login", { body: { email, password } });
  let user: User = { token: login.body.accessToken, refresh: login.body.refreshToken, id: reg.body.id };
  if (opts.totp) {
    const enr = await s.http("POST", "/api/v1/auth/totp/enroll", { token: user.token });
    const ver = await s.http("POST", "/api/v1/auth/totp/verify", { token: user.token, body: { code: totpCode(enr.body.secret, 0) } });
    if (ver.status !== 200) throw new Error("totp verify failed");
    // totp_verified is now set on the family; refresh to get a tv=true access token without needing a fresh code
    const r = await s.http("POST", "/api/v1/auth/refresh", { body: { refreshToken: user.refresh } });
    user = { token: r.body.accessToken, refresh: r.body.refreshToken, totpSecret: enr.body.secret, id: reg.body.id };
  }
  return user;
}

/** Lets tests issue another fresh-TOTP command inside the same 30s window. */
export async function clearTotpStep(s: TestServer) { await s.db.query("UPDATE users SET totp_last_step=0"); }

// ---------------------------------------------------------------------------------------------------
export class FakeAgent {
  readonly key = generateEd25519();
  readonly uuid = randomUUID();
  ws!: WebSocket;
  commands: CommandEnvelope[] = [];
  verifyFailures: string[] = [];
  closeCode: number | null = null;
  messages: any[] = [];
  /** id assigned by the server on pairing */
  serverId = "";
  onCommand: (env: CommandEnvelope) => { ok: boolean; error?: string; data?: Record<string, unknown> } | null = (env) =>
    env.cmd === "PREPARE_CONNECT" ? { ok: true, data: { rustdeskId: "123456789", oneTimePassword: "Zx9-secret-pw-ONE" } } : { ok: true };

  constructor(readonly s: TestServer, readonly kind: AgentKind = "DESKTOP", public name = "NGP-WORKSTATION", public version = "0.1.0") {}

  async pair(user: User): Promise<string> {
    const req = await this.s.http("POST", "/api/v1/pairing/requests", { body: { deviceUuid: this.uuid, name: this.name, kind: this.kind, publicKey: b64(this.key.publicKeyRaw) } });
    if (req.status !== 201) throw new Error(`pairing request failed ${req.status}`);
    const claim = await this.s.http("POST", `/api/v1/devices/${req.body.requestId}/pair`, { token: user.token, body: { code: req.body.code } });
    if (claim.status !== 200) throw new Error(`claim failed ${claim.status} ${JSON.stringify(claim.body)}`);
    this.serverId = claim.body.deviceId ?? claim.body.networkAgentId;
    return this.serverId;
  }

  connect(opts: { sign?: boolean; uuid?: string; version?: string } = {}): Promise<"ready" | "closed"> {
    this.closeCode = null;
    this.ws = new WebSocket(`${this.s.wsBase}/ws/agent`);
    return new Promise((resolve) => {
      this.ws.on("close", (code) => { this.closeCode = code; resolve("closed"); });
      this.ws.on("error", () => {});
      this.ws.on("message", (raw) => {
        const m = JSON.parse(raw.toString());
        this.messages.push(m);
        if (m.type === "challenge") {
          const uuid = opts.uuid ?? this.uuid;
          const sig = opts.sign === false ? b64(Buffer.alloc(64)) : signHello(this.key.privateKey, { nonce: m.nonce, deviceUuid: uuid, serverOrigin: m.serverOrigin, ts: m.ts });
          this.ws.send(JSON.stringify({ type: "hello", deviceUuid: uuid, kind: this.kind, version: opts.version ?? this.version, sig, info: { os: "Windows 11 Home", localIp: "192.168.1.20" } }));
        } else if (m.type === "ready") resolve("ready");
        else if (m.type === "command") this.handleCommand(m);
      });
    });
  }

  private handleCommand(m: CommandEnvelope) {
    const v = verifyEnvelope(this.s.config.commandPublicKey, m, { expectedDeviceUuid: this.uuid });
    this.commands.push(m);
    if (!v.ok) { this.verifyFailures.push(v.reason); return; }
    const r = this.onCommand(m);
    if (r) this.send({ type: "ack", commandId: m.id, ...r });
  }

  send(m: unknown) { this.ws.send(JSON.stringify(m)); }
  heartbeat() { this.send({ type: "heartbeat", uptimeSec: 5 }); }
  async close() { if (this.ws.readyState === WebSocket.OPEN) { this.ws.close(); await new Promise((r) => this.ws.once("close", r)); } }
  abort() { this.ws.terminate(); }
}

export async function waitFor<T>(fn: () => Promise<T | undefined | false> | T | undefined | false, timeoutMs = 5000, what = "condition"): Promise<T> {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const r = await fn();
    if (r) return r;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 25));
  }
}

export const deviceStatus = async (s: TestServer, user: User, id: string) => (await s.http("GET", `/api/v1/devices/${id}`, { token: user.token })).body.status as string;
export const waitStatus = (s: TestServer, user: User, id: string, status: string, ms = 5000) =>
  waitFor(async () => (await deviceStatus(s, user, id)) === status, ms, `status ${status}`);

export function clientWs(s: TestServer, token: string) {
  const ws = new WebSocket(`${s.wsBase}/ws/client`);
  const events: any[] = [];
  let closeCode: number | null = null;
  ws.on("open", () => ws.send(JSON.stringify({ type: "auth", accessToken: token })));
  ws.on("message", (raw) => events.push(JSON.parse(raw.toString())));
  ws.on("close", (c) => { closeCode = c; });
  ws.on("error", () => {});
  return { ws, events, get closeCode() { return closeCode; }, ready: () => waitFor(() => events.some((e) => e.type === "ready"), 3000, "client ready") };
}

export { signBytes, pairingPollInput, publicKeyFromRaw };
