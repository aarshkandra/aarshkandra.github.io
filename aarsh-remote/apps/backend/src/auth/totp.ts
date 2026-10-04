import { authenticator } from "otplib";
import type { Config } from "../config.js";
import { decrypt } from "../crypto.js";

authenticator.options = { digits: 6, step: 30, window: 1 };

export const newSecret = () => authenticator.generateSecret(20);
export const otpauthUrl = (email: string, secret: string) => authenticator.keyuri(email, "Aarsh Remote", secret);

/** Returns the matched time-step (for replay protection) or null. Caller must require step > users.totp_last_step. */
export function checkTotp(cfg: Config, enc: Buffer, token: string): number | null {
  if (!/^\d{6}$/.test(token)) return null;
  const delta = authenticator.checkDelta(token, decrypt(cfg.totpEncKey, enc));
  if (delta === null) return null;
  return Math.floor(Date.now() / 30000) + delta;
}
