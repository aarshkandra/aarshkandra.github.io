import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, randomInt, timingSafeEqual } from "node:crypto";
import argon2 from "argon2";

// OWASP-aligned Argon2id parameters (19 MiB, t=2, p=1) — raise on stronger hosts.
const ARGON = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 } as const;
export const hashPassword = (pw: string, pepper: Buffer) => argon2.hash(pw, { ...ARGON, secret: pepper });
export const verifyPassword = (hash: string, pw: string, pepper: Buffer) => argon2.verify(hash, pw, { secret: pepper }).catch(() => false);

export const sha256 = (data: string | Buffer): Buffer => createHash("sha256").update(data).digest();
export const hmac = (pepper: Buffer, ...parts: string[]): Buffer => createHmac("sha256", pepper).update(parts.join("\n")).digest();
export const safeEqual = (a: Buffer, b: Buffer): boolean => a.length === b.length && timingSafeEqual(a, b);

export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");
export const randomCode = (digits = 6) => String(randomInt(0, 10 ** digits)).padStart(digits, "0");

/** AES-256-GCM: nonce(12) || ciphertext || tag(16). */
export function encrypt(key: Buffer, plaintext: string): Buffer {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
  return Buffer.concat([iv, ct, c.getAuthTag()]);
}
export function decrypt(key: Buffer, blob: Buffer): string {
  const d = createDecipheriv("aes-256-gcm", key, blob.subarray(0, 12));
  d.setAuthTag(blob.subarray(blob.length - 16));
  return Buffer.concat([d.update(blob.subarray(12, blob.length - 16)), d.final()]).toString("utf8");
}
