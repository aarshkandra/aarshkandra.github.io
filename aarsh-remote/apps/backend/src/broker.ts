import { randomUUID } from "node:crypto";
import { signEnvelope, type Command } from "@aarsh/protocol";
import { AppError } from "./errors.js";
import type { Ctx } from "./ctx.js";
import type { AckResult, AgentConn } from "./hub.js";

/** Signs an allow-listed command for exactly one agent and waits for its ack. Args are schema-validated by signEnvelope. */
export async function sendCommand(ctx: Ctx, conn: AgentConn, cmd: Command, args: Record<string, unknown>, timeoutMs = ctx.config.COMMAND_TIMEOUT_MS): Promise<AckResult & { commandId: string }> {
  const commandId = randomUUID();
  const env = signEnvelope(ctx.config.commandPrivateKey, { id: commandId, cmd, args, deviceUuid: conn.uuid, ttlSeconds: Math.ceil(timeoutMs / 1000) });
  if (conn.ws.readyState !== 1) throw new AppError(503, "DEVICE_OFFLINE", "Agent not connected");
  const waiting = ctx.hub.expectAck(commandId, conn, timeoutMs);
  conn.ws.send(JSON.stringify(env));
  const r = await waiting;
  if (r === "TIMEOUT") throw new AppError(504, "COMMAND_TIMEOUT", `${cmd} timed out`);
  return { ...r, commandId };
}
