import { createHash } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { AGENT_KINDS, pairingPollInput, publicKeyFromRaw, unb64, verifyBytes } from "@aarsh/protocol";
import type { Ctx } from "../ctx.js";
import { AppError, accessDenied, notFound } from "../errors.js";
import { authPreHandler, info, parse, withAudit } from "../http.js";
import { hmac, randomCode, safeEqual } from "../crypto.js";
import { tx } from "../db.js";
import { requireTotpSession } from "../policy.js";

const PAIRING_TTL_MIN = 10;
const MAX_OPEN_PAIRINGS = 50;
const uuid = z.string().uuid();

export function registerPairingRoutes(app: FastifyInstance, ctx: Ctx) {
  // Agent side: unauthenticated, strictly rate limited, can only create a short-lived pending request.
  app.post("/api/v1/pairing/requests", { config: { rateLimit: { max: ctx.config.RATE_LIMIT_PAIRING_PER_HOUR, timeWindow: "1 hour" } } }, async (req, reply) => {
    const b = parse(z.object({
      deviceUuid: uuid, name: z.string().min(1).max(100), kind: z.enum(AGENT_KINDS).default("DESKTOP"),
      publicKey: z.string().refine((s) => unb64(s).length === 32, "must be base64 of 32 bytes"),
    }).strict(), req.body);
    const taken = await ctx.db.query(
      b.kind === "DESKTOP" ? "SELECT 1 FROM devices WHERE device_uuid=$1" : "SELECT 1 FROM network_agents WHERE agent_uuid=$1", [b.deviceUuid]);
    if (taken.rowCount) throw new AppError(409, "CONFLICT", "Already registered");
    const code = randomCode(6);
    const row = await tx(ctx.db, async (c) => {
      await c.query("DELETE FROM device_pairings WHERE (expires_at < now() - interval '1 day') OR (device_uuid=$1 AND consumed_at IS NULL)", [b.deviceUuid]);
      const open = await c.query<{ n: string }>("SELECT count(*) AS n FROM device_pairings WHERE consumed_at IS NULL AND expires_at > now()");
      if (Number(open.rows[0]!.n) >= MAX_OPEN_PAIRINGS) throw new AppError(503, "RATE_LIMITED", "Too many pending pairings");
      const id = (await c.query<{ id: string }>("SELECT gen_random_uuid() AS id")).rows[0]!.id;
      const r = await c.query<{ id: string; expires_at: Date }>(
        `INSERT INTO device_pairings(id,kind,device_uuid,device_name,public_key,code_hash,expires_at,requester_ip)
         VALUES ($1,$2,$3,$4,$5,$6, now()+make_interval(mins=>$7), $8) RETURNING id, expires_at`,
        [id, b.kind, b.deviceUuid, b.name, unb64(b.publicKey), hmac(ctx.config.pepper, "pairing", id, code), PAIRING_TTL_MIN, req.ip]);
      return r.rows[0]!;
    });
    return reply.status(201).send({ requestId: row.id, code, expiresAt: row.expires_at.toISOString() });
  });

  // Agent polls (proof of possession of the key it registered).
  app.get("/api/v1/pairing/requests/:id", async (req) => {
    const { id } = req.params as { id: string };
    const ts = Number(req.headers["x-timestamp"]);
    const sig = req.headers["x-signature"];
    if (!uuid.safeParse(id).success || !Number.isFinite(ts) || typeof sig !== "string" || Math.abs(Date.now() / 1000 - ts) > 60) throw accessDenied();
    const r = await ctx.db.query<{ public_key: Buffer; consumed_at: Date | null; expires_at: Date; attempts: number; max_attempts: number; paired_id: string | null; kind: string }>(
      "SELECT public_key, consumed_at, expires_at, attempts, max_attempts, paired_id, kind FROM device_pairings WHERE id=$1", [id]);
    const p = r.rows[0];
    if (!p || !verifyBytes(publicKeyFromRaw(p.public_key), pairingPollInput(id, ts), unb64(sig))) throw accessDenied();
    if (p.consumed_at) return { status: "paired", kind: p.kind, pairedId: p.paired_id };
    if (p.attempts >= p.max_attempts) return { status: "burned" };
    if (p.expires_at <= new Date()) return { status: "expired" };
    return { status: "pending" };
  });

  // User side: `:id` is the pairing request id shown by the agent alongside the code.
  app.post("/api/v1/devices/:id/pair", { preHandler: authPreHandler(ctx), config: { rateLimit: { max: ctx.config.RATE_LIMIT_CLAIM_PER_MIN, timeWindow: "1 minute" } } }, async (req) => {
    const { id } = req.params as { id: string };
    const b = parse(z.object({ code: z.string().regex(/^\d{6}$/) }).strict(), req.body);
    if (!uuid.safeParse(id).success) throw notFound();
    return withAudit(ctx, req, { action: "PAIR", detail: { requestId: id } }, async () => {
      await requireTotpSession(ctx, req.user!);
      const out = await tx(ctx.db, async (c) => {
        const r = await c.query<{ kind: "DESKTOP" | "WAKE"; device_uuid: string; device_name: string; public_key: Buffer; code_hash: Buffer; attempts: number; max_attempts: number; expires_at: Date; consumed_at: Date | null }>(
          "SELECT * FROM device_pairings WHERE id=$1 FOR UPDATE", [id]);
        const p = r.rows[0];
        if (!p) return { err: notFound() };
        if (p.consumed_at || p.expires_at <= new Date()) return { err: new AppError(410, "PAIRING_EXPIRED", "Pairing code expired") };
        if (p.attempts >= p.max_attempts) return { err: new AppError(429, "PAIRING_ATTEMPTS_EXCEEDED", "Too many attempts; restart pairing on the device") };
        if (!safeEqual(p.code_hash, hmac(ctx.config.pepper, "pairing", id, b.code))) {
          await c.query("UPDATE device_pairings SET attempts=attempts+1 WHERE id=$1", [id]); // committed even though we then reject
          return { err: accessDenied() };
        }
        const fp = createHash("sha256").update(p.public_key).digest("hex");
        let pairedId: string;
        if (p.kind === "DESKTOP") {
          const d = await c.query<{ id: string }>("INSERT INTO devices(device_uuid,name,owner_id,status) VALUES ($1,$2,$3,'OFFLINE') RETURNING id", [p.device_uuid, p.device_name, req.user!.id]);
          pairedId = d.rows[0]!.id;
          await c.query("INSERT INTO device_credentials(device_id,public_key,key_fingerprint) VALUES ($1,$2,$3)", [pairedId, p.public_key, fp]);
        } else {
          const n = await c.query<{ id: string }>("INSERT INTO network_agents(agent_uuid,name,owner_id) VALUES ($1,$2,$3) RETURNING id", [p.device_uuid, p.device_name, req.user!.id]);
          pairedId = n.rows[0]!.id;
          await c.query("INSERT INTO device_credentials(network_agent_id,public_key,key_fingerprint) VALUES ($1,$2,$3)", [pairedId, p.public_key, fp]);
        }
        await c.query("UPDATE device_pairings SET consumed_at=now(), consumed_by=$2, paired_id=$3 WHERE id=$1", [id, req.user!.id, pairedId]);
        return { ok: { kind: p.kind, pairedId } };
      }).catch((e: { code?: string }) => {
        if (e.code === "23505") return { err: new AppError(409, "CONFLICT", "Already registered") };
        throw e;
      });
      if ("err" in out && out.err) throw out.err;
      const ok = (out as { ok: { kind: "DESKTOP" | "WAKE"; pairedId: string } }).ok;
      return ok.kind === "DESKTOP" ? { deviceId: ok.pairedId } : { networkAgentId: ok.pairedId };
    });
  });
}
