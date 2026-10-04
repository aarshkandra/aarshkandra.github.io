import { z } from "zod";

/**
 * The closed command allow-list. There is intentionally NO generic execute/shell command.
 * `target` says who executes it: the desktop agent, the wake agent, or the server/client orchestration only.
 */
export const COMMANDS = [
  "WAKE",
  "SLEEP",
  "RESTART",
  "SHUTDOWN",
  "CONNECT",
  "DISCONNECT",
  "PREPARE_CONNECT",
  "GET_STATUS",
  "GET_METRICS",
  "PAUSE_REMOTE",
  "RESUME_REMOTE",
] as const;
export type Command = (typeof COMMANDS)[number];
export const isCommand = (s: unknown): s is Command => typeof s === "string" && (COMMANDS as readonly string[]).includes(s);

export const MAC_RE = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
const ipv4 = z.string().ip({ version: "v4" });

export const COMMAND_ARGS = {
  WAKE: z.object({ mac: z.string().regex(MAC_RE), broadcast: ipv4 }).strict(),
  SLEEP: z.object({}).strict(),
  RESTART: z.object({ delaySeconds: z.number().int().min(0).max(60).default(0) }).strict(),
  SHUTDOWN: z.object({ delaySeconds: z.number().int().min(0).max(60).default(0) }).strict(),
  PREPARE_CONNECT: z.object({ ttlSeconds: z.number().int().min(30).max(600) }).strict(),
  DISCONNECT: z.object({ sessionId: z.string().uuid() }).strict(),
  CONNECT: z.object({}).strict(),
  GET_STATUS: z.object({}).strict(),
  GET_METRICS: z.object({}).strict(),
  PAUSE_REMOTE: z.object({}).strict(),
  RESUME_REMOTE: z.object({}).strict(),
} as const satisfies Record<Command, z.ZodTypeAny>;

export type CommandTarget = "desktop" | "wake" | "orchestration";
export const COMMAND_TARGET: Record<Command, CommandTarget> = {
  WAKE: "wake",
  SLEEP: "desktop",
  RESTART: "desktop",
  SHUTDOWN: "desktop",
  PREPARE_CONNECT: "desktop",
  DISCONNECT: "desktop",
  GET_STATUS: "desktop",
  GET_METRICS: "desktop",
  PAUSE_REMOTE: "desktop",
  RESUME_REMOTE: "desktop",
  CONNECT: "orchestration",
};

/** Commands that change power state or open a session: require TOTP step-up (see architecture §9.2). */
export const STEP_UP_COMMANDS: ReadonlySet<Command> = new Set(["WAKE", "SLEEP", "RESTART", "SHUTDOWN", "CONNECT"]);

export function parseArgs(cmd: Command, args: unknown): { ok: true; args: Record<string, unknown> } | { ok: false; error: string } {
  const r = COMMAND_ARGS[cmd].safeParse(args ?? {});
  return r.success ? { ok: true, args: r.data as Record<string, unknown> } : { ok: false, error: r.error.issues.map((i) => i.message).join("; ") };
}
