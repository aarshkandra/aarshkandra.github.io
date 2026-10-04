import { describe, expect, it } from "vitest";
import { decrypt, encrypt, hashPassword, hmac, randomCode, verifyPassword } from "../src/crypto.js";
import { redact } from "../src/audit.js";
import { validatePassword } from "../src/auth/service.js";
import { loadConfig } from "../src/config.js";
import { envFor } from "./helpers.js";

const pepper = Buffer.alloc(32, 1);
describe("crypto", () => {
  it("argon2id hash verifies and is salted + peppered", async () => {
    const h = await hashPassword("a long enough password", pepper);
    expect(h.startsWith("$argon2id$")).toBe(true);
    expect(await verifyPassword(h, "a long enough password", pepper)).toBe(true);
    expect(await verifyPassword(h, "wrong", pepper)).toBe(false);
    expect(await verifyPassword(h, "a long enough password", Buffer.alloc(32, 2))).toBe(false);
    expect(h).not.toBe(await hashPassword("a long enough password", pepper));
  });
  it("AES-GCM round trips and detects tampering", () => {
    const k = Buffer.alloc(32, 3);
    const blob = encrypt(k, "JBSWY3DPEHPK3PXP");
    expect(decrypt(k, blob)).toBe("JBSWY3DPEHPK3PXP");
    blob[blob.length - 1]! ^= 1;
    expect(() => decrypt(k, blob)).toThrow();
  });
  it("hmac is domain separated; codes are 6 digits", () => {
    expect(hmac(pepper, "a", "b").equals(hmac(pepper, "a", "c"))).toBe(false);
    for (let i = 0; i < 200; i++) expect(randomCode(6)).toMatch(/^\d{6}$/);
  });
});
describe("password policy", () => {
  it("enforces length, denylist, email-name and repetition", () => {
    expect(validatePassword("short", "a@b.co")).toBeTruthy();
    expect(validatePassword("password1234", "a@b.co")).toBeTruthy();
    expect(validatePassword("xxxxxxxxxxxxxx", "a@b.co")).toBeTruthy();
    expect(validatePassword("myowner-secret-9", "owner@b.co")).toBeTruthy();
    expect(validatePassword("correct horse battery", "owner@b.co")).toBeNull();
  });
});
describe("audit redaction", () => {
  it("drops credential-looking keys", () => {
    expect(redact({ ok: 1, password: "x", refreshToken: "y", totpCode: "1", privateKey: "k", deviceName: "n" })).toEqual({ ok: 1, deviceName: "n" });
  });
});
describe("config", () => {
  it("rejects missing/short secrets", () => {
    expect(() => loadConfig({ ...envFor(), PEPPER: "AA==" })).toThrow();
    expect(() => loadConfig({ ...envFor(), DATABASE_URL: "" })).toThrow();
  });
});
