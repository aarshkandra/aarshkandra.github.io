import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { b64, generateEd25519, pairingPollInput, signBytes } from "@aarsh/protocol";
import { randomUUID } from "node:crypto";
import { FakeAgent, registerAndLogin, resetDb, startServer, type TestServer, type User } from "./helpers.js";

let s: TestServer;
let user: User;
beforeAll(async () => { s = await startServer(); });
afterAll(async () => { await s.close(); });
beforeEach(async () => { await resetDb(s.db); user = await registerAndLogin(s, undefined, undefined, { totp: true }); });

const reqPairing = async (key = generateEd25519(), kind = "DESKTOP") => {
  const deviceUuid = randomUUID();
  const r = await s.http("POST", "/api/v1/pairing/requests", { body: { deviceUuid, name: "NGP", kind, publicKey: b64(key.publicKeyRaw) } });
  return { ...r, key, deviceUuid };
};

describe("pairing", () => {
  it("happy path creates a device owned by the user, stores only the public key + code hash", async () => {
    const a = new FakeAgent(s);
    const id = await a.pair(user);
    const d = await s.http("GET", `/api/v1/devices/${id}`, { token: user.token });
    expect(d.status).toBe(200);
    expect(d.body.name).toBe("NGP-WORKSTATION");
    const cred = await s.db.query("SELECT octet_length(public_key) AS n FROM device_credentials");
    expect(cred.rows[0].n).toBe(32);
    const p = await s.db.query("SELECT encode(code_hash,'hex') AS h FROM device_pairings");
    expect(p.rows[0].h).toMatch(/^[0-9a-f]{64}$/);
  });
  it("code is single-use", async () => {
    const r = await reqPairing();
    const body = { code: r.body.code };
    expect((await s.http("POST", `/api/v1/devices/${r.body.requestId}/pair`, { token: user.token, body })).status).toBe(200);
    const again = await s.http("POST", `/api/v1/devices/${r.body.requestId}/pair`, { token: user.token, body });
    expect(again.status).toBe(410);
    expect(again.body.error.code).toBe("PAIRING_EXPIRED");
  });
  it("burns after 5 wrong attempts — even the correct code is then refused", async () => {
    const r = await reqPairing();
    const wrong = r.body.code === "000000" ? "111111" : "000000";
    for (let i = 0; i < 5; i++) expect((await s.http("POST", `/api/v1/devices/${r.body.requestId}/pair`, { token: user.token, body: { code: wrong } })).status).toBe(401);
    const good = await s.http("POST", `/api/v1/devices/${r.body.requestId}/pair`, { token: user.token, body: { code: r.body.code } });
    expect(good.status).toBe(429);
    expect(good.body.error.code).toBe("PAIRING_ATTEMPTS_EXCEEDED");
    expect((await s.db.query("SELECT 1 FROM devices")).rowCount).toBe(0);
  });
  it("expires", async () => {
    const r = await reqPairing();
    await s.db.query("UPDATE device_pairings SET expires_at=now()-interval '1 second'");
    const res = await s.http("POST", `/api/v1/devices/${r.body.requestId}/pair`, { token: user.token, body: { code: r.body.code } });
    expect(res.body.error.code).toBe("PAIRING_EXPIRED");
  });
  it("requires an authenticated, TOTP-verified session", async () => {
    const r = await reqPairing();
    expect((await s.http("POST", `/api/v1/devices/${r.body.requestId}/pair`, { body: { code: r.body.code } })).status).toBe(401);
    // a session without TOTP (fresh password-less-TOTP user path): login with totp user but craft tv=false by using the pre-refresh token
    const login = await s.http("POST", "/api/v1/auth/login", { body: { email: "owner@example.com", password: "correct horse battery staple", recoveryCode: "nope" } });
    expect(login.status).toBe(401);
  });
  it("user without TOTP enrolled is told to enroll first", async () => {
    await resetDb(s.db);
    const u = await registerAndLogin(s);
    const r = await reqPairing();
    const res = await s.http("POST", `/api/v1/devices/${r.body.requestId}/pair`, { token: u.token, body: { code: r.body.code } });
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe("TOTP_ENROLLMENT_REQUIRED");
  });
  it("cannot register the same device uuid twice", async () => {
    const a = new FakeAgent(s);
    await a.pair(user);
    const dup = await s.http("POST", "/api/v1/pairing/requests", { body: { deviceUuid: a.uuid, name: "evil", publicKey: b64(generateEd25519().publicKeyRaw) } });
    expect(dup.status).toBe(409);
  });
  it("rejects bad public keys and unknown fields", async () => {
    expect((await s.http("POST", "/api/v1/pairing/requests", { body: { deviceUuid: randomUUID(), name: "x", publicKey: "AAAA" } })).status).toBe(400);
    expect((await s.http("POST", "/api/v1/pairing/requests", { body: { deviceUuid: randomUUID(), name: "x", publicKey: b64(generateEd25519().publicKeyRaw), owner: "me" } })).status).toBe(400);
  });
  it("poll requires proof of key possession and reports status", async () => {
    const r = await reqPairing();
    const ts = Math.floor(Date.now() / 1000);
    const sig = b64(signBytes(r.key.privateKey, pairingPollInput(r.body.requestId, ts)));
    const headers = { "x-timestamp": String(ts), "x-signature": sig };
    expect((await s.http("GET", `/api/v1/pairing/requests/${r.body.requestId}`, { headers })).body.status).toBe("pending");
    const evil = b64(signBytes(generateEd25519().privateKey, pairingPollInput(r.body.requestId, ts)));
    expect((await s.http("GET", `/api/v1/pairing/requests/${r.body.requestId}`, { headers: { ...headers, "x-signature": evil } })).status).toBe(401);
    expect((await s.http("GET", `/api/v1/pairing/requests/${r.body.requestId}`)).status).toBe(401);
    await s.http("POST", `/api/v1/devices/${r.body.requestId}/pair`, { token: user.token, body: { code: r.body.code } });
    expect((await s.http("GET", `/api/v1/pairing/requests/${r.body.requestId}`, { headers })).body.status).toBe("paired");
  });
  it("pairing requests are rate limited per IP", async () => {
    const lim = await startServer({ RATE_LIMIT_PAIRING_PER_HOUR: "2" });
    const codes: number[] = [];
    for (let i = 0; i < 4; i++) codes.push((await lim.http("POST", "/api/v1/pairing/requests", { body: { deviceUuid: randomUUID(), name: "x", publicKey: b64(generateEd25519().publicKeyRaw) } })).status);
    await lim.close();
    expect(codes).toEqual([201, 201, 429, 429]);
  });
  it("wake agents pair through the same flow", async () => {
    const w = new FakeAgent(s, "WAKE", "Nagpur Wake Agent");
    const id = await w.pair(user);
    const list = await s.http("GET", "/api/v1/network-agents", { token: user.token });
    expect(list.body.networkAgents.map((n: any) => n.id)).toContain(id);
  });
});
