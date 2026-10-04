import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Ctx } from "../ctx.js";
import { authPreHandler, info, parse } from "../http.js";
import * as auth from "../auth/service.js";

const email = z.string().email().max(254).transform((s) => s.toLowerCase());

export function registerAuthRoutes(app: FastifyInstance, ctx: Ctx) {
  const limit = { rateLimit: { max: ctx.config.RATE_LIMIT_LOGIN_PER_MIN, timeWindow: "1 minute" } };
  const needAuth = { preHandler: authPreHandler(ctx) };

  app.post("/api/v1/auth/register", { config: limit }, async (req, reply) => {
    const b = parse(z.object({ email, password: z.string().max(256), displayName: z.string().min(1).max(100) }).strict(), req.body);
    return reply.status(201).send(await auth.register(ctx, b, info(req)));
  });
  app.post("/api/v1/auth/login", { config: limit }, async (req) => {
    const b = parse(z.object({ email, password: z.string().max(256), totp: z.string().max(10).optional(), recoveryCode: z.string().max(40).optional(), clientLabel: z.string().max(80).optional() }).strict(), req.body);
    return auth.login(ctx, b, info(req));
  });
  app.post("/api/v1/auth/refresh", { config: limit }, async (req) => {
    const b = parse(z.object({ refreshToken: z.string().min(20).max(200) }).strict(), req.body);
    return auth.refresh(ctx, b.refreshToken, info(req));
  });
  app.post("/api/v1/auth/logout", needAuth, async (req, reply) => {
    await auth.logout(ctx, req.user!.id, req.user!.sid, info(req));
    return reply.status(204).send();
  });
  app.post("/api/v1/auth/totp/enroll", needAuth, async (req) => auth.totpEnroll(ctx, req.user!.id, info(req)));
  app.post("/api/v1/auth/totp/verify", { ...needAuth, config: limit }, async (req) => {
    const b = parse(z.object({ code: z.string().regex(/^\d{6}$/) }).strict(), req.body);
    return auth.totpVerify(ctx, req.user!.id, req.user!.sid, b.code, info(req));
  });
}
