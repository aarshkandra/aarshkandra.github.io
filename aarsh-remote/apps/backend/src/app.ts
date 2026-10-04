import Fastify from "fastify";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import websocket from "@fastify/websocket";
import type { Config } from "./config.js";
import type { Db } from "./db.js";
import { Hub } from "./hub.js";
import type { Ctx } from "./ctx.js";
import { registerErrorHandler } from "./http.js";
import { registerAuthRoutes } from "./routes/auth.js";
import { registerPairingRoutes } from "./routes/pairing.js";
import { registerDeviceRoutes } from "./routes/devices.js";
import { registerAgentGateway } from "./ws/agent.js";
import { registerClientGateway } from "./ws/client.js";

export async function buildApp(config: Config, db: Db, opts: { logger?: boolean } = {}) {
  const app = Fastify({
    trustProxy: config.TRUST_PROXY,
    bodyLimit: 64 * 1024,
    logger: opts.logger === false ? false : {
      level: config.NODE_ENV === "test" ? "silent" : "info",
      // Never log credentials, even if a handler logs a request body by mistake.
      redact: { paths: ["req.headers.authorization", "req.headers.cookie", "*.password", "*.refreshToken", "*.accessToken", "*.totp", "*.recoveryCode", "*.oneTimePassword", "*.code", "*.privateKey"], censor: "[redacted]" },
    },
  });
  const hub = new Hub();
  const ctx: Ctx = { config, db, hub, log: app.log };

  await app.register(helmet, { contentSecurityPolicy: false });
  await app.register(rateLimit, { global: true, max: config.RATE_LIMIT_GLOBAL_PER_MIN, timeWindow: "1 minute" });
  await app.register(websocket, { options: { maxPayload: 64 * 1024 } });
  registerErrorHandler(app);

  app.get("/healthz", { config: { rateLimit: false } }, async () => ({ ok: true }));
  registerAuthRoutes(app, ctx);
  registerPairingRoutes(app, ctx);
  registerDeviceRoutes(app, ctx);
  registerAgentGateway(app, ctx);
  registerClientGateway(app, ctx);

  app.addHook("onClose", async () => hub.shutdown());
  return { app, ctx };
}
