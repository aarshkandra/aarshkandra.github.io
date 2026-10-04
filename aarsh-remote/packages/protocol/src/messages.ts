import { z } from "zod";
import { b64, signBytes, verifyBytes } from "./crypto.js";
import type { KeyObject } from "node:crypto";

export const AGENT_KINDS = ["DESKTOP", "WAKE"] as const;
export type AgentKind = (typeof AGENT_KINDS)[number];

/** Signed input for the /ws/agent challenge-response. Binds nonce, identity, server origin and timestamp (anti-replay / cross-server relay). */
export function helloSigningInput(c: { nonce: string; deviceUuid: string; serverOrigin: string; ts: number }): Buffer {
  return Buffer.from(`aarsh-hello-v1\n${c.nonce}\n${c.deviceUuid}\n${c.serverOrigin}\n${c.ts}`, "utf8");
}
export const signHello = (key: KeyObject, c: Parameters<typeof helloSigningInput>[0]): string => b64(signBytes(key, helloSigningInput(c)));
export const verifyHello = (pub: KeyObject, c: Parameters<typeof helloSigningInput>[0], sig: Uint8Array): boolean => verifyBytes(pub, helloSigningInput(c), sig);

/** Signed input for the unauthenticated-but-signed pairing poll. */
export const pairingPollInput = (requestId: string, ts: number): Buffer => Buffer.from(`aarsh-pairing-poll-v1\n${requestId}\n${ts}`, "utf8");

const semver = z.string().regex(/^\d+\.\d+\.\d+$/);

// ---- agent -> server -------------------------------------------------------
export const helloMsg = z.object({
  type: z.literal("hello"),
  deviceUuid: z.string().uuid(),
  kind: z.enum(AGENT_KINDS),
  version: semver,
  sig: z.string().min(1),
  info: z
    .object({
      os: z.string().max(200).optional(),
      localIp: z.string().ip().optional(),
      mac: z.string().regex(/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/).optional(),
      rustdeskId: z.string().max(32).optional(),
    })
    .strict()
    .optional(),
});

export const metricsSchema = z
  .object({
    cpuPct: z.number().min(0).max(100).optional(),
    ramPct: z.number().min(0).max(100).optional(),
    gpuPct: z.number().min(0).max(100).optional(),
    diskPct: z.number().min(0).max(100).optional(),
    tempC: z.number().min(-50).max(200).optional(),
    netRxKbps: z.number().min(0).optional(),
    netTxKbps: z.number().min(0).optional(),
    uptimeSec: z.number().min(0).optional(),
    windowsSession: z.enum(["none", "locked", "active", "disconnected"]).optional(),
  })
  .strict();
export type Metrics = z.infer<typeof metricsSchema>;

export const AGENT_EVENTS = ["GOING_TO_SLEEP", "RESUMED", "NETWORK_CHANGED", "REMOTE_DISABLED", "REMOTE_ENABLED"] as const;

export const agentMsg = z.discriminatedUnion("type", [
  z.object({ type: z.literal("heartbeat"), uptimeSec: z.number().min(0).optional(), remoteDisabled: z.boolean().optional() }),
  z.object({ type: z.literal("metrics"), metrics: metricsSchema }),
  z.object({ type: z.literal("event"), name: z.enum(AGENT_EVENTS) }),
  z.object({
    type: z.literal("ack"),
    commandId: z.string().uuid(),
    ok: z.boolean(),
    error: z.string().max(500).optional(),
    data: z.record(z.unknown()).optional(),
  }),
  z.object({ type: z.literal("lan.probe"), deviceUuid: z.string().uuid(), reachable: z.boolean(), ms: z.number().min(0).optional() }),
]);
export type AgentMsg = z.infer<typeof agentMsg>;

// ---- client -> server ------------------------------------------------------
export const clientMsg = z.discriminatedUnion("type", [
  z.object({ type: z.literal("auth"), accessToken: z.string().min(10) }),
  z.object({ type: z.literal("ping") }),
  z.object({
    type: z.literal("session.report"),
    sessionId: z.string().uuid(),
    state: z.enum(["CONNECTED", "DISCONNECTED", "ENDED", "FAILED"]),
    connectionType: z.enum(["P2P", "RELAY", "UNKNOWN"]).optional(),
    rttMs: z.number().min(0).max(60000).optional(),
  }),
]);
export type ClientMsg = z.infer<typeof clientMsg>;

export const DEVICE_STATUSES = ["UNKNOWN", "OFFLINE", "SLEEPING", "WAKE_REQUESTED", "WAKING", "ONLINE", "ERROR"] as const;
export type DeviceStatus = (typeof DEVICE_STATUSES)[number];

export const ERROR_CODES = [
  "ACCESS_DENIED", "TOTP_REQUIRED", "TOTP_ENROLLMENT_REQUIRED", "RATE_LIMITED", "DEVICE_REVOKED", "REMOTE_PAUSED",
  "REMOTE_DISABLED_LOCALLY", "DEVICE_OFFLINE", "WAKE_AGENT_UNREACHABLE", "WAKE_NO_RESPONSE", "COMMAND_TIMEOUT",
  "UNKNOWN_COMMAND", "AGENT_OUTDATED", "PAIRING_EXPIRED", "PAIRING_ATTEMPTS_EXCEEDED", "INVALID_STATE", "NOT_FOUND",
  "VALIDATION", "CONFLICT", "COMMAND_FAILED",
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];

export function compareSemver(a: string, b: string): number {
  const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) { const d = (pa[i] ?? 0) - (pb[i] ?? 0); if (d) return Math.sign(d); }
  return 0;
}
