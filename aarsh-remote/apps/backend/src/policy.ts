import type { Command } from "@aarsh/protocol";
import { STEP_UP_COMMANDS } from "@aarsh/protocol";
import type { Ctx } from "./ctx.js";
import { AppError } from "./errors.js";
import { verifyFreshTotp } from "./auth/service.js";

/** Commands that additionally need a *fresh* single-use TOTP code in the request body. */
export const FRESH_TOTP_COMMANDS: ReadonlySet<Command> = new Set(["RESTART", "SHUTDOWN"]);

/** Session must have been established with a TOTP-verified login (claim `tv`). */
export async function requireTotpSession(ctx: Ctx, user: { id: string; tv: boolean }): Promise<void> {
  if (!ctx.config.REQUIRE_TOTP_FOR_COMMANDS || user.tv) return;
  const r = await ctx.db.query<{ totp_enabled: boolean }>("SELECT totp_enabled FROM users WHERE id=$1", [user.id]);
  if (!r.rows[0]?.totp_enabled) throw new AppError(403, "TOTP_ENROLLMENT_REQUIRED", "Enable two-factor authentication first");
  throw new AppError(401, "TOTP_REQUIRED", "Log in again with a two-factor code");
}

export async function stepUp(ctx: Ctx, user: { id: string; tv: boolean }, cmd: Command, totp: string | undefined): Promise<void> {
  if (!ctx.config.REQUIRE_TOTP_FOR_COMMANDS || !STEP_UP_COMMANDS.has(cmd)) return;
  await requireTotpSession(ctx, user);
  if (FRESH_TOTP_COMMANDS.has(cmd)) await verifyFreshTotp(ctx, user.id, totp);
}
