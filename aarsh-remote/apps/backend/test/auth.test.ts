import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { EMAIL, PASSWORD, registerAndLogin, resetDb, startServer, totpCode, clearTotpStep, type TestServer } from "./helpers.js";

let s: TestServer;
beforeAll(async () => { s = await startServer(); });
afterAll(async () => { await s.close(); });

describe("registration", () => {
  it("first user becomes owner; further registration is closed by default", async () => {
    await resetDb(s.db);
    expect((await s.http("POST", "/api/v1/auth/register", { body: { email: EMAIL, password: PASSWORD, displayName: "A" } })).status).toBe(201);
    const second = await s.http("POST", "/api/v1/auth/register", { body: { email: "x@example.com", password: PASSWORD, displayName: "B" } });
    expect(second.status).toBe(403);
  });
  it("rejects weak passwords and unknown fields", async () => {
    await resetDb(s.db);
    expect((await s.http("POST", "/api/v1/auth/register", { body: { email: EMAIL, password: "short", displayName: "A" } })).status).toBe(400);
    expect((await s.http("POST", "/api/v1/auth/register", { body: { email: EMAIL, password: PASSWORD, displayName: "A", role: "admin" } })).status).toBe(400);
  });
});

describe("login", () => {
  it("returns generic ACCESS_DENIED for unknown user and wrong password alike", async () => {
    await resetDb(s.db);
    await registerAndLogin(s);
    const a = await s.http("POST", "/api/v1/auth/login", { body: { email: "nobody@example.com", password: PASSWORD } });
    const b = await s.http("POST", "/api/v1/auth/login", { body: { email: EMAIL, password: "wrong wrong wrong" } });
    expect(a.status).toBe(401); expect(b.status).toBe(401);
    expect(a.body).toEqual(b.body);
    expect(a.body.error.code).toBe("ACCESS_DENIED");
  });
  it("locks the account after 5 failures, even for the right password", async () => {
    await resetDb(s.db);
    await registerAndLogin(s);
    for (let i = 0; i < 5; i++) await s.http("POST", "/api/v1/auth/login", { body: { email: EMAIL, password: "wrong wrong wrong" } });
    const r = await s.http("POST", "/api/v1/auth/login", { body: { email: EMAIL, password: PASSWORD } });
    expect(r.status).toBe(401);
    await s.db.query("UPDATE users SET locked_until=now()-interval '1 second'");
    expect((await s.http("POST", "/api/v1/auth/login", { body: { email: EMAIL, password: PASSWORD } })).status).toBe(200);
  });
  it("is rate limited per IP", async () => {
    const lim = await startServer({ RATE_LIMIT_LOGIN_PER_MIN: "3" });
    const codes: number[] = [];
    for (let i = 0; i < 5; i++) codes.push((await lim.http("POST", "/api/v1/auth/login", { body: { email: EMAIL, password: "wrong wrong wrong" } })).status);
    await lim.close();
    expect(codes.slice(0, 3)).toEqual([401, 401, 401]);
    expect(codes.slice(3)).toEqual([429, 429]);
  });
  it("protected routes reject missing, garbage and foreign-signed tokens", async () => {
    expect((await s.http("GET", "/api/v1/devices")).status).toBe(401);
    expect((await s.http("GET", "/api/v1/devices", { token: "garbage" })).status).toBe(401);
    const other = await startServer(); // different JWT key
    await resetDb(other.db);
    const u = await registerAndLogin(other);
    await other.close();
    expect((await s.http("GET", "/api/v1/devices", { token: u.token })).status).toBe(401);
  });
});

describe("tokens", () => {
  it("access token expires", async () => {
    const short = await startServer({ ACCESS_TOKEN_TTL_S: "1" });
    const u = await registerAndLogin(short);
    expect((await short.http("GET", "/api/v1/devices", { token: u.token })).status).toBe(200);
    await new Promise((r) => setTimeout(r, 2200));
    expect((await short.http("GET", "/api/v1/devices", { token: u.token })).status).toBe(401);
    await short.close();
  });
  it("refresh rotates; reuse of an old token revokes the whole family", async () => {
    await resetDb(s.db);
    const u = await registerAndLogin(s);
    const r1 = await s.http("POST", "/api/v1/auth/refresh", { body: { refreshToken: u.refresh } });
    expect(r1.status).toBe(200);
    expect(r1.body.refreshToken).not.toBe(u.refresh);
    const reuse = await s.http("POST", "/api/v1/auth/refresh", { body: { refreshToken: u.refresh } });
    expect(reuse.status).toBe(401);
    // the legitimate (newer) token and its access token are dead too
    expect((await s.http("POST", "/api/v1/auth/refresh", { body: { refreshToken: r1.body.refreshToken } })).status).toBe(401);
    expect((await s.http("GET", "/api/v1/devices", { token: r1.body.accessToken })).status).toBe(401);
    const a = await s.db.query("SELECT 1 FROM audit_logs WHERE action='REFRESH_REUSE'");
    expect(a.rowCount).toBeGreaterThanOrEqual(1);
  });
  it("refresh token expiry is absolute", async () => {
    await resetDb(s.db);
    const u = await registerAndLogin(s);
    await s.db.query("UPDATE refresh_tokens SET expires_at=now()-interval '1 second'");
    expect((await s.http("POST", "/api/v1/auth/refresh", { body: { refreshToken: u.refresh } })).status).toBe(401);
  });
  it("logout kills the access token immediately", async () => {
    await resetDb(s.db);
    const u = await registerAndLogin(s);
    expect((await s.http("POST", "/api/v1/auth/logout", { token: u.token })).status).toBe(204);
    expect((await s.http("GET", "/api/v1/devices", { token: u.token })).status).toBe(401);
  });
  it("refresh tokens are stored hashed", async () => {
    await resetDb(s.db);
    const u = await registerAndLogin(s);
    const r = await s.db.query("SELECT encode(token_hash,'base64') AS h FROM refresh_tokens");
    for (const row of r.rows) expect(row.h).not.toContain(u.refresh);
    expect((await s.db.query("SELECT 1 FROM refresh_tokens WHERE token_hash=$1", [Buffer.from(u.refresh)])).rowCount).toBe(0);
  });
});

describe("TOTP", () => {
  it("enroll → login requires code; replayed code rejected; recovery code is single-use", async () => {
    await resetDb(s.db);
    const u = await registerAndLogin(s, EMAIL, PASSWORD, { totp: true });
    expect(u.totpSecret).toBeTruthy();
    const noCode = await s.http("POST", "/api/v1/auth/login", { body: { email: EMAIL, password: PASSWORD } });
    expect(noCode.status).toBe(401); expect(noCode.body.error.code).toBe("TOTP_REQUIRED");
    const wrong = await s.http("POST", "/api/v1/auth/login", { body: { email: EMAIL, password: PASSWORD, totp: "000000" } });
    expect(wrong.status).toBe(401); expect(wrong.body.error.code).toBe("ACCESS_DENIED");
    const code = totpCode(u.totpSecret!, 1);
    expect((await s.http("POST", "/api/v1/auth/login", { body: { email: EMAIL, password: PASSWORD, totp: code } })).status).toBe(200);
    expect((await s.http("POST", "/api/v1/auth/login", { body: { email: EMAIL, password: PASSWORD, totp: code } })).status).toBe(401); // replay
  });
  it("recovery codes work exactly once", async () => {
    await resetDb(s.db);
    const reg = await s.http("POST", "/api/v1/auth/register", { body: { email: EMAIL, password: PASSWORD, displayName: "A" } });
    expect(reg.status).toBe(201);
    const login = await s.http("POST", "/api/v1/auth/login", { body: { email: EMAIL, password: PASSWORD } });
    const enr = await s.http("POST", "/api/v1/auth/totp/enroll", { token: login.body.accessToken });
    const ver = await s.http("POST", "/api/v1/auth/totp/verify", { token: login.body.accessToken, body: { code: totpCode(enr.body.secret, 0) } });
    const rc = ver.body.recoveryCodes[0];
    expect(ver.body.recoveryCodes).toHaveLength(10);
    expect((await s.http("POST", "/api/v1/auth/login", { body: { email: EMAIL, password: PASSWORD, recoveryCode: rc } })).status).toBe(200);
    expect((await s.http("POST", "/api/v1/auth/login", { body: { email: EMAIL, password: PASSWORD, recoveryCode: rc } })).status).toBe(401);
    const stored = await s.db.query("SELECT recovery_codes FROM users");
    expect(JSON.stringify(stored.rows)).not.toContain(rc);
    void clearTotpStep;
  });
  it("secret is encrypted at rest", async () => {
    await resetDb(s.db);
    const u = await registerAndLogin(s, EMAIL, PASSWORD, { totp: true });
    const r = await s.db.query("SELECT totp_secret_enc FROM users");
    expect(Buffer.from(r.rows[0].totp_secret_enc).toString("latin1")).not.toContain(u.totpSecret!);
  });
});
