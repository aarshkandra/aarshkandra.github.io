import { SignJWT, jwtVerify } from "jose";
import type { Config } from "../config.js";

export interface AccessClaims { userId: string; sid: string; tv: boolean }

const AUD = "aarsh-client";

export const signAccess = (cfg: Config, c: AccessClaims) =>
  new SignJWT({ sid: c.sid, tv: c.tv })
    .setProtectedHeader({ alg: "EdDSA" })
    .setSubject(c.userId).setIssuer(cfg.SERVER_ORIGIN).setAudience(AUD)
    .setIssuedAt().setExpirationTime(`${cfg.ACCESS_TOKEN_TTL_S}s`)
    .sign(cfg.jwtPrivateKey);

export async function verifyAccess(cfg: Config, token: string): Promise<AccessClaims | null> {
  try {
    const { payload } = await jwtVerify(token, cfg.jwtPublicKey, { algorithms: ["EdDSA"], issuer: cfg.SERVER_ORIGIN, audience: AUD });
    if (typeof payload.sub !== "string" || typeof payload.sid !== "string") return null;
    return { userId: payload.sub, sid: payload.sid, tv: payload.tv === true };
  } catch {
    return null;
  }
}
