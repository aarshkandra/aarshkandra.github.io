import type { FastifyInstance, FastifyRequest } from "fastify";
import type { z } from "zod";
import type { Ctx } from "./ctx.js";
import { AppError, accessDenied } from "./errors.js";
import { audit } from "./audit.js";
import { sessionActive } from "./auth/service.js";
import { verifyAccess } from "./auth/tokens.js";

declare module "fastify" {
  interface FastifyRequest { user?: { id: string; sid: string; tv: boolean } }
}

export function parse<T extends z.ZodTypeAny>(schema: T, data: unknown): z.infer<T> {
  const r = schema.safeParse(data);
  if (!r.success) throw new AppError(400, "VALIDATION", r.error.issues.map((i) => `${i.path.join(".") || "body"}: ${i.message}`).join("; "));
  return r.data;
}

export const info = (req: FastifyRequest) => ({ ip: req.ip, userAgent: req.headers["user-agent"] });

export function authPreHandler(ctx: Ctx) {
  return async (req: FastifyRequest) => {
    const h = req.headers.authorization;
    const token = h?.startsWith("Bearer ") ? h.slice(7) : null;
    const claims = token ? await verifyAccess(ctx.config, token) : null;
    if (!claims || !(await sessionActive(ctx, claims.userId, claims.sid))) throw accessDenied();
    req.user = { id: claims.userId, sid: claims.sid, tv: claims.tv };
  };
}

/** Runs `fn`, writing exactly one audit row for the outcome (SUCCESS / DENIED for 4xx auth-ish errors / FAILURE otherwise). */
export async function withAudit<T>(ctx: Ctx, req: FastifyRequest, a: { action: string; deviceId?: string | null; detail?: Record<string, unknown> }, fn: () => Promise<T>): Promise<T> {
  try {
    const r = await fn();
    await audit(ctx.db, { userId: req.user?.id, deviceId: a.deviceId, action: a.action, result: "SUCCESS", detail: a.detail, ...info(req) });
    return r;
  } catch (e) {
    const denied = e instanceof AppError && [401, 403].includes(e.status);
    await audit(ctx.db, {
      userId: req.user?.id, deviceId: a.deviceId, action: a.action, result: denied ? "DENIED" : "FAILURE",
      detail: { ...a.detail, error: e instanceof AppError ? e.code : "INTERNAL" }, ...info(req),
    }).catch(() => {});
    throw e;
  }
}

export function registerErrorHandler(app: FastifyInstance) {
  app.setErrorHandler((err: Error & { statusCode?: number; code?: string }, req, reply) => {
    if (err instanceof AppError) return reply.status(err.status).send({ error: { code: err.code, message: err.message, ...err.extra } });
    if (err.statusCode === 429) return reply.status(429).send({ error: { code: "RATE_LIMITED", message: "Too many requests" } });
    if (err.statusCode && err.statusCode < 500) return reply.status(err.statusCode).send({ error: { code: "VALIDATION", message: err.message } });
    req.log.error({ err }, "unhandled error");
    return reply.status(500).send({ error: { code: "INTERNAL", message: "Internal error" } });
  });
  app.setNotFoundHandler((_req, reply) => reply.status(404).send({ error: { code: "NOT_FOUND", message: "Not found" } }));
}
