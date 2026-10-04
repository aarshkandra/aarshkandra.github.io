import type { KeyObject } from "node:crypto";
import { z } from "zod";
import { b64, randomB64, signBytes, unb64, verifyBytes } from "./crypto.js";
import { canonicalize } from "./canonical.js";
import { COMMANDS, parseArgs, type Command } from "./commands.js";

export const ENVELOPE_DOMAIN = "aarsh-cmd-v1\n";
export const MAX_ENVELOPE_LIFETIME_S = 60;
export const CLOCK_SKEW_S = 30;

export const envelopeBodySchema = z.object({
  id: z.string().uuid(),
  cmd: z.enum(COMMANDS),
  args: z.record(z.unknown()),
  issuedAt: z.number().int(),
  expiresAt: z.number().int(),
  nonce: z.string().min(16).max(64),
  deviceUuid: z.string().uuid(),
});
export type EnvelopeBody = z.infer<typeof envelopeBodySchema>;
export type CommandEnvelope = EnvelopeBody & { type: "command"; sig: string };

export function signingInput(body: EnvelopeBody): Buffer {
  const { id, cmd, args, issuedAt, expiresAt, nonce, deviceUuid } = body;
  return Buffer.from(ENVELOPE_DOMAIN + canonicalize({ id, cmd, args, issuedAt, expiresAt, nonce, deviceUuid }), "utf8");
}

export function signEnvelope(
  serverKey: KeyObject,
  p: { id: string; cmd: Command; args: Record<string, unknown>; deviceUuid: string; ttlSeconds?: number; now?: number },
): CommandEnvelope {
  const parsed = parseArgs(p.cmd, p.args);
  if (!parsed.ok) throw new Error(`invalid args for ${p.cmd}: ${parsed.error}`);
  const issuedAt = p.now ?? Math.floor(Date.now() / 1000);
  const ttl = Math.min(p.ttlSeconds ?? 30, MAX_ENVELOPE_LIFETIME_S);
  const body: EnvelopeBody = { id: p.id, cmd: p.cmd, args: parsed.args, issuedAt, expiresAt: issuedAt + ttl, nonce: randomB64(16), deviceUuid: p.deviceUuid };
  return { type: "command", ...body, sig: b64(signBytes(serverKey, signingInput(body))) };
}

export type VerifyResult = { ok: true; body: EnvelopeBody } | { ok: false; reason: "MALFORMED" | "BAD_SIGNATURE" | "WRONG_DEVICE" | "EXPIRED" | "NOT_YET_VALID" | "LIFETIME_TOO_LONG" | "BAD_ARGS" };

/** Reference verifier. Agents must implement identical checks; replay-nonce tracking is the agent's job (keep seen ids until expiry). */
export function verifyEnvelope(serverPublicKey: KeyObject, raw: unknown, opts: { expectedDeviceUuid: string; now?: number }): VerifyResult {
  const { type: _t, sig, ...rest } = (raw ?? {}) as Record<string, unknown>;
  const body = envelopeBodySchema.safeParse(rest);
  if (!body.success || typeof sig !== "string") return { ok: false, reason: "MALFORMED" };
  if (!verifyBytes(serverPublicKey, signingInput(body.data), unb64(sig))) return { ok: false, reason: "BAD_SIGNATURE" };
  if (body.data.deviceUuid !== opts.expectedDeviceUuid) return { ok: false, reason: "WRONG_DEVICE" };
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  if (body.data.expiresAt - body.data.issuedAt > MAX_ENVELOPE_LIFETIME_S) return { ok: false, reason: "LIFETIME_TOO_LONG" };
  if (now > body.data.expiresAt) return { ok: false, reason: "EXPIRED" };
  if (now < body.data.issuedAt - CLOCK_SKEW_S) return { ok: false, reason: "NOT_YET_VALID" };
  if (!parseArgs(body.data.cmd, body.data.args).ok) return { ok: false, reason: "BAD_ARGS" };
  return { ok: true, body: body.data };
}
