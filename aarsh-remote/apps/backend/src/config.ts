import { createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { z } from "zod";

const b64Key = (bytes: number) =>
  z.string().refine((s) => Buffer.from(s, "base64").length === bytes, `must be base64 of ${bytes} bytes`);

const bool = z.enum(["true", "false"]).transform((v) => v === "true");

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().default(8080),
  HOST: z.string().default("0.0.0.0"),
  DATABASE_URL: z.string().min(1),
  SERVER_ORIGIN: z.string().url(),
  // Ed25519 PKCS8 DER, base64. Generate with scripts/gen-secrets.mjs
  JWT_PRIVATE_KEY: z.string().min(40),
  COMMAND_SIGNING_KEY: z.string().min(40),
  TOTP_ENC_KEY: b64Key(32),
  PEPPER: b64Key(32),
  REGISTRATION_ENABLED: bool.default("false"),
  REQUIRE_TOTP_FOR_COMMANDS: bool.default("true"),
  MIN_AGENT_VERSION: z.string().regex(/^\d+\.\d+\.\d+$/).default("0.1.0"),
  WAKE_TIMEOUT_MS: z.coerce.number().int().default(180_000),
  COMMAND_TIMEOUT_MS: z.coerce.number().int().default(30_000),
  HEARTBEAT_TIMEOUT_MS: z.coerce.number().int().default(45_000),
  HEARTBEAT_SWEEP_MS: z.coerce.number().int().default(5_000),
  ACCESS_TOKEN_TTL_S: z.coerce.number().int().default(600),
  REFRESH_TOKEN_TTL_S: z.coerce.number().int().default(30 * 86400),
  RUSTDESK_ID_SERVER: z.string().default(""),
  RUSTDESK_RELAY_SERVER: z.string().default(""),
  RUSTDESK_PUBLIC_KEY: z.string().default(""),
  TRUST_PROXY: bool.default("false"),
  RATE_LIMIT_GLOBAL_PER_MIN: z.coerce.number().int().default(100),
  RATE_LIMIT_LOGIN_PER_MIN: z.coerce.number().int().default(5),
  RATE_LIMIT_PAIRING_PER_HOUR: z.coerce.number().int().default(3),
  RATE_LIMIT_CLAIM_PER_MIN: z.coerce.number().int().default(10),
});

export type Config = Omit<z.infer<typeof envSchema>, "JWT_PRIVATE_KEY" | "COMMAND_SIGNING_KEY" | "TOTP_ENC_KEY" | "PEPPER"> & {
  jwtPrivateKey: KeyObject;
  jwtPublicKey: KeyObject;
  commandPrivateKey: KeyObject;
  commandPublicKey: KeyObject;
  totpEncKey: Buffer;
  pepper: Buffer;
};

const loadKey = (b64: string) => createPrivateKey({ key: Buffer.from(b64, "base64"), format: "der", type: "pkcs8" });

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const e = envSchema.parse(env);
  const jwtPrivateKey = loadKey(e.JWT_PRIVATE_KEY);
  const commandPrivateKey = loadKey(e.COMMAND_SIGNING_KEY);
  const { JWT_PRIVATE_KEY: _a, COMMAND_SIGNING_KEY: _b, TOTP_ENC_KEY, PEPPER, ...rest } = e;
  return {
    ...rest,
    SERVER_ORIGIN: e.SERVER_ORIGIN.replace(/\/$/, ""),
    jwtPrivateKey,
    jwtPublicKey: createPublicKey(jwtPrivateKey),
    commandPrivateKey,
    commandPublicKey: createPublicKey(commandPrivateKey),
    totpEncKey: Buffer.from(TOTP_ENC_KEY, "base64"),
    pepper: Buffer.from(PEPPER, "base64"),
  };
}
