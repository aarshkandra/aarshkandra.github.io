import { randomUUID } from "node:crypto";
import type pg from "pg";
import type { Ctx } from "../ctx.js";
import { AppError, accessDenied } from "../errors.js";
import { audit } from "../audit.js";
import { tx } from "../db.js";
import { encrypt, hashPassword, hmac, randomToken, sha256, verifyPassword } from "../crypto.js";
import { signAccess } from "./tokens.js";
import { checkTotp, newSecret, otpauthUrl } from "./totp.js";

export interface UserRow {
  id: string; email: string; display_name: string; password_hash: string; totp_secret_enc: Buffer | null;
  totp_enabled: boolean; totp_last_step: string | null; recovery_codes: string[]; failed_logins: number;
  locked_until: Date | null; disabled: boolean;
}
export interface ReqInfo { ip?: string; userAgent?: string }

const COMMON = new Set(["password1234", "123456789012", "qwertyuiop12", "letmein12345", "administrator", "welcome12345"]);
export function validatePassword(pw: string, email: string): string | null {
  if (pw.length < 12) return "Password must be at least 12 characters";
  if (pw.length > 128) return "Password too long";
  if (COMMON.has(pw.toLowerCase())) return "Password is too common";
  const local = email.split("@")[0]?.toLowerCase() ?? "";
  if (local.length >= 4 && pw.toLowerCase().includes(local)) return "Password must not contain your email name";
  if (new Set(pw).size < 5) return "Password is too repetitive";
  return null;
}

// A valid hash of a random string, to equalise timing when the user does not exist.
let dummyHash: Promise<string> | undefined;

export async function register(ctx: Ctx, b: { email: string; password: string; displayName: string }, info: ReqInfo) {
  const bad = validatePassword(b.password, b.email);
  if (bad) throw new AppError(400, "VALIDATION", bad);
  const hash = await hashPassword(b.password, ctx.config.pepper);
  const user = await tx(ctx.db, async (c) => {
    await c.query("SELECT pg_advisory_xact_lock(727275)");
    const n = await c.query<{ n: string }>("SELECT count(*) AS n FROM users");
    if (n.rows[0]!.n !== "0" && !ctx.config.REGISTRATION_ENABLED) throw new AppError(403, "ACCESS_DENIED", "Registration is closed");
    const ex = await c.query("SELECT 1 FROM users WHERE email=$1", [b.email]);
    if (ex.rowCount) throw new AppError(409, "CONFLICT", "Email already registered");
    const r = await c.query<{ id: string }>("INSERT INTO users(email,display_name,password_hash,role) VALUES ($1,$2,$3,$4) RETURNING id",
      [b.email, b.displayName, hash, n.rows[0]!.n === "0" ? "owner" : "viewer"]);
    await audit(c, { userId: r.rows[0]!.id, action: "REGISTER", result: "SUCCESS", ...info });
    return r.rows[0]!;
  });
  return { id: user.id };
}

export interface TokenPair { accessToken: string; refreshToken: string; expiresIn: number }

async function issuePair(ctx: Ctx, c: pg.PoolClient, p: { userId: string; familyId: string; totpVerified: boolean; expiresAt: Date; label?: string; ip?: string }): Promise<TokenPair> {
  const refreshToken = randomToken(32);
  await c.query(
    "INSERT INTO refresh_tokens(user_id,family_id,token_hash,client_label,ip,totp_verified,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    [p.userId, p.familyId, sha256(refreshToken), p.label ?? null, p.ip ?? null, p.totpVerified, p.expiresAt]);
  const accessToken = await signAccess(ctx.config, { userId: p.userId, sid: p.familyId, tv: p.totpVerified });
  return { accessToken, refreshToken, expiresIn: ctx.config.ACCESS_TOKEN_TTL_S };
}

export async function login(ctx: Ctx, b: { email: string; password: string; totp?: string; recoveryCode?: string; clientLabel?: string }, info: ReqInfo): Promise<TokenPair> {
  const deny = async (userId: string | null, why: string) => {
    await audit(ctx.db, { userId, action: "LOGIN", result: "DENIED", detail: { why }, ...info });
    return accessDenied();
  };
  const found = await ctx.db.query<UserRow>("SELECT * FROM users WHERE email=$1", [b.email]);
  const u = found.rows[0];
  if (!u) {
    dummyHash ??= hashPassword(randomToken(), ctx.config.pepper);
    await verifyPassword(await dummyHash, b.password, ctx.config.pepper);
    throw await deny(null, "unknown_user");
  }
  const pwOk = await verifyPassword(u.password_hash, b.password, ctx.config.pepper);
  const locked = u.locked_until !== null && u.locked_until > new Date();
  if (locked || u.disabled) throw await deny(u.id, locked ? "locked" : "disabled");

  const fail = async (why: string) => {
    const n = u.failed_logins + 1;
    const lockSec = n >= 5 ? Math.min(900, 30 * 2 ** (n - 5)) : 0;
    await ctx.db.query("UPDATE users SET failed_logins=$2, locked_until=CASE WHEN $3>0 THEN now()+make_interval(secs=>$3) ELSE locked_until END WHERE id=$1", [u.id, n, lockSec]);
    return deny(u.id, why);
  };
  if (!pwOk) throw await fail("bad_password");

  let totpVerified = false;
  if (u.totp_enabled && u.totp_secret_enc) {
    if (!b.totp && !b.recoveryCode) throw new AppError(401, "TOTP_REQUIRED", "Two-factor code required");
    if (b.totp) {
      const step = checkTotp(ctx.config, u.totp_secret_enc, b.totp);
      if (step === null || (u.totp_last_step !== null && step <= Number(u.totp_last_step))) throw await fail("bad_totp");
      await ctx.db.query("UPDATE users SET totp_last_step=$2 WHERE id=$1", [u.id, step]);
    } else {
      const h = hmac(ctx.config.pepper, "recovery", u.id, b.recoveryCode!.trim().toLowerCase()).toString("hex");
      const used = await ctx.db.query("UPDATE users SET recovery_codes=array_remove(recovery_codes,$2) WHERE id=$1 AND $2=ANY(recovery_codes)", [u.id, h]);
      if (!used.rowCount) throw await fail("bad_recovery_code");
    }
    totpVerified = true;
  }

  const pair = await tx(ctx.db, async (c) => {
    await c.query("UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=$1", [u.id]);
    const p = await issuePair(ctx, c, { userId: u.id, familyId: randomUUID(), totpVerified, expiresAt: new Date(Date.now() + ctx.config.REFRESH_TOKEN_TTL_S * 1000), label: b.clientLabel, ip: info.ip });
    await audit(c, { userId: u.id, action: "LOGIN", result: "SUCCESS", detail: { totp: totpVerified }, ...info });
    return p;
  });
  return pair;
}

export async function refresh(ctx: Ctx, token: string, info: ReqInfo): Promise<TokenPair> {
  type R = { id: string; user_id: string; family_id: string; totp_verified: boolean; expires_at: Date; used_at: Date | null; revoked_at: Date | null; client_label: string | null };
  let reuse: { userId: string } | null = null;
  const pair = await tx(ctx.db, async (c) => {
    const r = await c.query<R>("SELECT * FROM refresh_tokens WHERE token_hash=$1 FOR UPDATE", [sha256(token)]);
    const t = r.rows[0];
    if (!t) return null;
    if (t.used_at || t.revoked_at) {
      await c.query("UPDATE refresh_tokens SET revoked_at=now() WHERE family_id=$1 AND revoked_at IS NULL", [t.family_id]);
      reuse = { userId: t.user_id };
      return null;
    }
    if (t.expires_at <= new Date()) return null;
    const u = await c.query<{ disabled: boolean }>("SELECT disabled FROM users WHERE id=$1", [t.user_id]);
    if (u.rows[0]?.disabled) return null;
    await c.query("UPDATE refresh_tokens SET used_at=now() WHERE id=$1", [t.id]);
    return issuePair(ctx, c, { userId: t.user_id, familyId: t.family_id, totpVerified: t.totp_verified, expiresAt: t.expires_at, label: t.client_label ?? undefined, ip: info.ip });
  });
  if (reuse) await audit(ctx.db, { userId: (reuse as { userId: string }).userId, action: "REFRESH_REUSE", result: "DENIED", ...info });
  if (!pair) throw accessDenied();
  return pair;
}

export async function logout(ctx: Ctx, userId: string, familyId: string, info: ReqInfo) {
  await ctx.db.query("UPDATE refresh_tokens SET revoked_at=now() WHERE family_id=$1 AND revoked_at IS NULL", [familyId]);
  await audit(ctx.db, { userId, action: "LOGOUT", result: "SUCCESS", ...info });
}

export async function sessionActive(ctx: Ctx, userId: string, familyId: string): Promise<boolean> {
  const r = await ctx.db.query(
    "SELECT 1 FROM refresh_tokens rt JOIN users u ON u.id=rt.user_id WHERE rt.family_id=$1 AND rt.user_id=$2 AND rt.revoked_at IS NULL AND rt.expires_at>now() AND NOT u.disabled LIMIT 1", [familyId, userId]);
  return (r.rowCount ?? 0) > 0;
}

export async function totpEnroll(ctx: Ctx, userId: string, info: ReqInfo) {
  const u = await ctx.db.query<{ email: string; totp_enabled: boolean }>("SELECT email, totp_enabled FROM users WHERE id=$1", [userId]);
  if (u.rows[0]!.totp_enabled) throw new AppError(409, "CONFLICT", "TOTP already enabled");
  const secret = newSecret();
  await ctx.db.query("UPDATE users SET totp_secret_enc=$2 WHERE id=$1", [userId, encrypt(ctx.config.totpEncKey, secret)]);
  await audit(ctx.db, { userId, action: "TOTP_ENROLL", result: "SUCCESS", ...info });
  return { secret, otpauthUrl: otpauthUrl(u.rows[0]!.email, secret) };
}

export async function totpVerify(ctx: Ctx, userId: string, sid: string, code: string, info: ReqInfo) {
  const r = await ctx.db.query<UserRow>("SELECT * FROM users WHERE id=$1", [userId]);
  const u = r.rows[0]!;
  if (u.totp_enabled) throw new AppError(409, "CONFLICT", "TOTP already enabled");
  if (!u.totp_secret_enc) throw new AppError(400, "VALIDATION", "Start enrollment first");
  const step = checkTotp(ctx.config, u.totp_secret_enc, code);
  if (step === null) {
    await audit(ctx.db, { userId, action: "TOTP_VERIFY", result: "DENIED", ...info });
    throw accessDenied();
  }
  const codes = Array.from({ length: 10 }, () => randomToken(8).toLowerCase());
  await tx(ctx.db, async (c) => {
    await c.query("UPDATE users SET totp_enabled=true, totp_last_step=$2, recovery_codes=$3 WHERE id=$1",
      [userId, step, codes.map((x) => hmac(ctx.config.pepper, "recovery", userId, x).toString("hex"))]);
    await c.query("UPDATE refresh_tokens SET totp_verified=true WHERE family_id=$1", [sid]);
    await audit(c, { userId, action: "TOTP_ENABLE", result: "SUCCESS", ...info });
  });
  return { recoveryCodes: codes };
}

/** Per-command fresh TOTP (restart/shutdown). Single-use per time step. */
export async function verifyFreshTotp(ctx: Ctx, userId: string, code: string | undefined): Promise<void> {
  const r = await ctx.db.query<UserRow>("SELECT * FROM users WHERE id=$1", [userId]);
  const u = r.rows[0]!;
  if (!u.totp_enabled || !u.totp_secret_enc) throw new AppError(403, "TOTP_ENROLLMENT_REQUIRED", "Enable two-factor authentication first");
  if (!code) throw new AppError(401, "TOTP_REQUIRED", "Two-factor code required");
  const step = checkTotp(ctx.config, u.totp_secret_enc, code);
  if (step === null || (u.totp_last_step !== null && step <= Number(u.totp_last_step))) throw accessDenied();
  const upd = await ctx.db.query("UPDATE users SET totp_last_step=$2 WHERE id=$1 AND (totp_last_step IS NULL OR totp_last_step<$2)", [userId, step]);
  if (!upd.rowCount) throw accessDenied();
}
