import { randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { MAC_RE, type Command } from "@aarsh/protocol";
import type { Ctx } from "../ctx.js";
import { AppError, notFound } from "../errors.js";
import { authPreHandler, info, parse, withAudit } from "../http.js";
import { sendCommand } from "../broker.js";
import { applyDeviceEvent } from "../presence.js";
import { IllegalTransition } from "../state-machine.js";
import { stepUp } from "../policy.js";
import { tx } from "../db.js";

const idParam = z.string().uuid();
const COLS = `d.id, d.device_uuid, d.name, d.status, d.status_reason, d.last_seen, d.mac_address::text AS mac_address, host(d.local_ip) AS local_ip,
  host(d.broadcast_ip) AS broadcast_ip, d.net_interface, d.os, d.agent_version, d.remote_paused, d.remote_disabled_locally, d.revoked_at,
  d.rustdesk_id, d.created_at, (SELECT network_agent_id FROM device_wake_routes r WHERE r.device_id=d.id) AS wake_agent_id`;

interface DeviceRow {
  id: string; device_uuid: string; name: string; status: string; status_reason: string | null; last_seen: Date | null; mac_address: string | null;
  local_ip: string | null; broadcast_ip: string | null; net_interface: string | null; os: string | null; agent_version: string | null;
  remote_paused: boolean; remote_disabled_locally: boolean; revoked_at: Date | null; rustdesk_id: string | null; created_at: Date; wake_agent_id: string | null;
}

export function registerDeviceRoutes(app: FastifyInstance, ctx: Ctx) {
  const { hub, db, config } = ctx;
  const pre = { preHandler: authPreHandler(ctx) };

  async function loadDevice(req: FastifyRequest): Promise<DeviceRow> {
    const id = (req.params as { id: string }).id;
    if (!idParam.safeParse(id).success) throw notFound();
    // Not-owner and not-found are indistinguishable on purpose.
    const r = await db.query<DeviceRow>(`SELECT ${COLS} FROM devices d WHERE d.id=$1 AND d.owner_id=$2 AND d.deleted_at IS NULL`, [id, req.user!.id]);
    if (!r.rows[0]) throw notFound();
    return r.rows[0];
  }
  const view = (d: DeviceRow) => ({
    id: d.id, name: d.name, status: d.status, statusReason: d.status_reason, lastSeen: d.last_seen, online: hub.desktops.has(d.id),
    macAddress: d.mac_address, localIp: d.local_ip, broadcastIp: d.broadcast_ip, netInterface: d.net_interface, os: d.os, agentVersion: d.agent_version,
    remotePaused: d.remote_paused, remoteDisabledLocally: d.remote_disabled_locally, revokedAt: d.revoked_at, rustdeskId: d.rustdesk_id,
    wakeAgentId: d.wake_agent_id, createdAt: d.created_at,
  });
  function assertUsable(d: DeviceRow) {
    if (d.revoked_at) throw new AppError(403, "DEVICE_REVOKED", "Device has been revoked");
    if (d.remote_paused) throw new AppError(403, "REMOTE_PAUSED", "Remote access is paused");
    if (d.remote_disabled_locally) throw new AppError(403, "REMOTE_DISABLED_LOCALLY", "Remote access was disabled on the PC");
  }
  function onlineConn(d: DeviceRow) {
    const c = hub.desktops.get(d.id);
    if (!c) throw new AppError(409, "DEVICE_OFFLINE", `Device is ${d.status.toLowerCase()}`);
    return c;
  }
  async function run(d: DeviceRow, cmd: Command, args: Record<string, unknown>) {
    const ack = await sendCommand(ctx, onlineConn(d), cmd, args);
    if (!ack.ok) throw new AppError(502, "COMMAND_FAILED", ack.error ?? `${cmd} failed`);
    return ack;
  }

  app.get("/api/v1/devices", pre, async (req) => {
    const r = await db.query<DeviceRow>(`SELECT ${COLS} FROM devices d WHERE d.owner_id=$1 AND d.deleted_at IS NULL ORDER BY d.created_at`, [req.user!.id]);
    return { devices: r.rows.map(view) };
  });
  app.get("/api/v1/devices/:id", pre, async (req) => view(await loadDevice(req)));

  app.patch("/api/v1/devices/:id", pre, async (req) => {
    const d = await loadDevice(req);
    const b = parse(z.object({
      name: z.string().min(1).max(100), macAddress: z.string().regex(MAC_RE), broadcastIp: z.string().ip({ version: "v4" }),
      localIp: z.string().ip({ version: "v4" }), netInterface: z.string().max(100), wakeAgentId: z.string().uuid().nullable(),
    }).partial().strict(), req.body);
    return withAudit(ctx, req, { action: "DEVICE_UPDATE", deviceId: d.id, detail: { fields: Object.keys(b) } }, async () => {
      await tx(db, async (c) => {
        await c.query(
          `UPDATE devices SET name=COALESCE($2,name), mac_address=COALESCE($3::macaddr,mac_address), broadcast_ip=COALESCE($4::inet,broadcast_ip),
             local_ip=COALESCE($5::inet,local_ip), net_interface=COALESCE($6,net_interface), updated_at=now() WHERE id=$1`,
          [d.id, b.name ?? null, b.macAddress ?? null, b.broadcastIp ?? null, b.localIp ?? null, b.netInterface ?? null]);
        if (b.wakeAgentId === null) await c.query("DELETE FROM device_wake_routes WHERE device_id=$1", [d.id]);
        else if (b.wakeAgentId) {
          const na = await c.query("SELECT 1 FROM network_agents WHERE id=$1 AND owner_id=$2 AND revoked_at IS NULL", [b.wakeAgentId, req.user!.id]);
          if (!na.rowCount) throw new AppError(400, "VALIDATION", "Unknown wake agent");
          await c.query("INSERT INTO device_wake_routes(device_id,network_agent_id) VALUES ($1,$2) ON CONFLICT (device_id) DO UPDATE SET network_agent_id=EXCLUDED.network_agent_id", [d.id, b.wakeAgentId]);
        }
      });
      return view(await loadDevice(req));
    });
  });

  async function revoke(req: FastifyRequest, d: DeviceRow, softDelete: boolean) {
    await tx(db, async (c) => {
      await c.query("UPDATE devices SET revoked_at=COALESCE(revoked_at,now()), deleted_at=CASE WHEN $2 THEN now() ELSE deleted_at END, updated_at=now() WHERE id=$1", [d.id, softDelete]);
      await c.query("UPDATE device_credentials SET state='REVOKED', revoked_at=COALESCE(revoked_at,now()) WHERE device_id=$1", [d.id]);
      await c.query("UPDATE remote_sessions SET state='ENDED', ended_at=now(), end_reason='device revoked' WHERE device_id=$1 AND state NOT IN ('ENDED','FAILED')", [d.id]);
    });
    const conn = hub.desktops.get(d.id);
    if (conn) { hub.desktops.delete(d.id); hub.failPendingFor(conn, "REVOKED"); conn.ws.close(4403, "revoked"); }
    hub.clearWakeTimer(d.id);
    await applyDeviceEvent(ctx, d.id, { type: "REVOKED" });
  }
  app.post("/api/v1/devices/:id/revoke", pre, async (req, reply) => {
    const d = await loadDevice(req);
    await withAudit(ctx, req, { action: "REVOKE", deviceId: d.id }, () => revoke(req, d, false));
    return reply.status(204).send();
  });
  app.delete("/api/v1/devices/:id", pre, async (req, reply) => {
    const d = await loadDevice(req);
    await withAudit(ctx, req, { action: "DEVICE_DELETE", deviceId: d.id }, () => revoke(req, d, true));
    return reply.status(204).send();
  });

  for (const [path, cmd, flag] of [["pause", "PAUSE_REMOTE", true], ["resume", "RESUME_REMOTE", false]] as const) {
    app.post(`/api/v1/devices/:id/${path}`, pre, async (req, reply) => {
      const d = await loadDevice(req);
      await withAudit(ctx, req, { action: cmd, deviceId: d.id }, async () => {
        if (d.revoked_at) throw new AppError(403, "DEVICE_REVOKED", "Device has been revoked");
        await db.query("UPDATE devices SET remote_paused=$2, updated_at=now() WHERE id=$1", [d.id, flag]);
        const c = hub.desktops.get(d.id);
        if (c) await sendCommand(ctx, c, cmd, {}, 5000).catch(() => {}); // server-side pause already enforced; agent copy is best-effort
      });
      return reply.status(204).send();
    });
  }

  // ---- power commands --------------------------------------------------------------------------
  const powerBody = z.object({ confirm: z.literal(true), totp: z.string().max(10).optional(), delaySeconds: z.number().int().min(0).max(60).optional() }).strict();
  for (const [path, cmd] of [["sleep", "SLEEP"], ["restart", "RESTART"], ["shutdown", "SHUTDOWN"]] as const) {
    app.post(`/api/v1/devices/:id/${path}`, pre, async (req) => {
      const d = await loadDevice(req);
      const b = parse(powerBody, req.body);
      return withAudit(ctx, req, { action: cmd, deviceId: d.id }, async () => {
        await stepUp(ctx, req.user!, cmd, b.totp);
        assertUsable(d);
        const args = cmd === "SLEEP" ? {} : { delaySeconds: b.delaySeconds ?? 0 };
        const conn = onlineConn(d);
        if (cmd === "SLEEP") conn.goingToSleep = true; // expected disconnect → SLEEPING, not OFFLINE
        try { await run(d, cmd, args); } catch (e) { if (cmd === "SLEEP") conn.goingToSleep = false; throw e; }
        return { accepted: true };
      });
    });
  }

  // ---- wake --------------------------------------------------------------------------------------
  app.post("/api/v1/devices/:id/wake", pre, async (req, reply) => {
    const d = await loadDevice(req);
    parse(z.object({}).strict(), req.body ?? {});
    const result = await withAudit(ctx, req, { action: "WAKE", deviceId: d.id }, async () => {
      await stepUp(ctx, req.user!, "WAKE", undefined);
      assertUsable(d);
      if (!d.mac_address) throw new AppError(400, "VALIDATION", "MAC address is not configured for this device");
      const route = await db.query<{ id: string }>("SELECT n.id FROM device_wake_routes r JOIN network_agents n ON n.id=r.network_agent_id WHERE r.device_id=$1 AND n.revoked_at IS NULL", [d.id]);
      const naId = route.rows[0]?.id;
      if (!naId) throw new AppError(400, "VALIDATION", "No wake agent assigned to this device");
      const wconn = hub.wakers.get(naId);
      const mk = async (status: string, reason: string | null) =>
        (await db.query<{ id: string }>("INSERT INTO wake_requests(device_id,network_agent_id,requested_by,status,failure_reason,prior_state,completed_at) VALUES ($1,$2,$3,$4::wake_status,$5,$6::device_status, CASE WHEN $4='FAILED' THEN now() END) RETURNING id",
          [d.id, naId, req.user!.id, status, reason, d.status])).rows[0]!.id;
      if (!wconn) {
        await mk("FAILED", "WAKE_AGENT_UNREACHABLE");
        throw new AppError(503, "WAKE_AGENT_UNREACHABLE", "Wake agent is offline", { diagnostics: ["Wake agent unreachable: check the Raspberry Pi power, network and internet"] });
      }
      try { await applyDeviceEvent(ctx, d.id, { type: "WAKE_REQUESTED" }); }
      catch (e) { if (e instanceof IllegalTransition) throw new AppError(409, "INVALID_STATE", `Device is already ${d.status.toLowerCase()}`); throw e; }
      const wakeRequestId = await mk("REQUESTED", null);
      void completeWake(wakeRequestId, d, wconn, req.user!.id);
      return { wakeRequestId };
    });
    return reply.status(202).send(result);
  });

  async function completeWake(wakeRequestId: string, d: DeviceRow, wconn: NonNullable<ReturnType<typeof hub.wakers.get>>, userId: string) {
    const fail = async (reason: string, status: "FAILED" | "TIMED_OUT") => {
      await db.query("UPDATE wake_requests SET status=$2::wake_status, failure_reason=$3, completed_at=now() WHERE id=$1 AND status NOT IN ('SUCCEEDED')", [wakeRequestId, status, reason]);
      hub.sendToUser(userId, { type: "wake.progress", wakeRequestId, deviceId: d.id, stage: "FAILED", reason });
    };
    try {
      const ack = await sendCommand(ctx, wconn, "WAKE", { mac: d.mac_address!.toUpperCase(), broadcast: d.broadcast_ip ?? "255.255.255.255" });
      if (!ack.ok) {
        await applyDeviceEvent(ctx, d.id, { type: "WAKE_FAILED", reason: "WAKE_SEND_FAILED" }).catch(() => {});
        return await fail("WAKE_SEND_FAILED", "FAILED");
      }
      await db.query("UPDATE wake_requests SET status='SENT', sent_at=now() WHERE id=$1 AND status='REQUESTED'", [wakeRequestId]);
      const after = await applyDeviceEvent(ctx, d.id, { type: "WAKE_SENT" }).catch(() => null);
      if (!after) return; // device connected (or was revoked) before the ack arrived
      hub.sendToUser(userId, { type: "wake.progress", wakeRequestId, deviceId: d.id, stage: "SENT" });
      const t = setTimeout(() => {
        hub.wakeTimers.delete(d.id);
        void (async () => {
          try { await applyDeviceEvent(ctx, d.id, { type: "WAKE_TIMEOUT" }); } catch (e) { if (e instanceof IllegalTransition) return; throw e; }
          await fail("WAKE_NO_RESPONSE", "TIMED_OUT");
        })().catch((err) => ctx.log.error({ err }, "wake timeout handling failed"));
      }, config.WAKE_TIMEOUT_MS);
      t.unref();
      hub.clearWakeTimer(d.id);
      hub.wakeTimers.set(d.id, t);
    } catch (e) {
      const reason = e instanceof AppError ? e.code === "COMMAND_TIMEOUT" ? "WAKE_AGENT_UNREACHABLE" : e.code : "INTERNAL";
      await applyDeviceEvent(ctx, d.id, { type: "WAKE_FAILED", reason }).catch(() => {});
      await fail(reason, "FAILED").catch(() => {});
    }
  }

  // ---- connect / disconnect --------------------------------------------------------------------------
  const ticketSchema = z.object({ oneTimePassword: z.string().min(8).max(128), rustdeskId: z.string().min(1).max(32) });
  app.post("/api/v1/devices/:id/connect", pre, async (req) => {
    const d = await loadDevice(req);
    parse(z.object({}).strict(), req.body ?? {});
    return withAudit(ctx, req, { action: "CONNECT", deviceId: d.id }, async () => {
      await stepUp(ctx, req.user!, "CONNECT", undefined);
      assertUsable(d);
      const ack = await run(d, "PREPARE_CONNECT", { ttlSeconds: 120 });
      const t = ticketSchema.safeParse(ack.data);
      if (!t.success) throw new AppError(502, "COMMAND_FAILED", "Agent returned an invalid connection ticket");
      const sessionId = randomUUID();
      await tx(db, async (c) => {
        await c.query("UPDATE remote_sessions SET state='ENDED', ended_at=now(), end_reason='superseded' WHERE device_id=$1 AND state NOT IN ('ENDED','FAILED')", [d.id]);
        await c.query("INSERT INTO remote_sessions(id,device_id,user_id,client_ip) VALUES ($1,$2,$3,$4)", [sessionId, d.id, req.user!.id, req.ip]);
      });
      await db.query("UPDATE devices SET rustdesk_id=$2 WHERE id=$1", [d.id, t.data.rustdeskId]);
      // The one-time password is returned once to this authenticated caller and is never stored or logged.
      return {
        sessionId, provider: "rustdesk", rustdeskId: t.data.rustdeskId, oneTimePassword: t.data.oneTimePassword, expiresInSeconds: 120,
        serverConfig: { idServer: config.RUSTDESK_ID_SERVER, relayServer: config.RUSTDESK_RELAY_SERVER, key: config.RUSTDESK_PUBLIC_KEY },
      };
    });
  });
  app.post("/api/v1/devices/:id/disconnect", pre, async (req, reply) => {
    const d = await loadDevice(req);
    const b = parse(z.object({ sessionId: z.string().uuid() }).strict(), req.body);
    await withAudit(ctx, req, { action: "DISCONNECT", deviceId: d.id, detail: { sessionId: b.sessionId } }, async () => {
      const s = await db.query("SELECT 1 FROM remote_sessions WHERE id=$1 AND device_id=$2 AND user_id=$3 AND state NOT IN ('ENDED','FAILED')", [b.sessionId, d.id, req.user!.id]);
      if (!s.rowCount) throw notFound();
      await db.query("UPDATE remote_sessions SET state='ENDED', ended_at=now(), end_reason='user' WHERE id=$1", [b.sessionId]);
      const c = hub.desktops.get(d.id);
      if (c) await sendCommand(ctx, c, "DISCONNECT", { sessionId: b.sessionId }, 10_000).catch(() => {}); // agent rotates the RustDesk password
    });
    return reply.status(204).send();
  });

  // ---- read-only ----------------------------------------------------------------------------------------------
  app.get("/api/v1/devices/:id/status", pre, async (req) => {
    const d = await loadDevice(req);
    const waker = d.wake_agent_id ? hub.wakers.has(d.wake_agent_id) : null;
    const diagnostics: string[] = [];
    if (d.revoked_at) diagnostics.push("Device revoked");
    else if (d.status === "OFFLINE") diagnostics.push("Home PC unreachable. Possible reasons: Internet disconnected, PC powered off, router offline");
    if (d.status === "SLEEPING") diagnostics.push("PC is sleeping: use Wake");
    if (d.status === "WAKING" || d.status === "WAKE_REQUESTED") diagnostics.push("Waking PC…");
    if (d.status === "ERROR") diagnostics.push(`Error: ${d.status_reason ?? "unknown"}`);
    if (waker === false && d.status !== "ONLINE") diagnostics.push("Wake agent is offline");
    if (d.status === "ONLINE" && !d.rustdesk_id) diagnostics.push("PC is online but the remote desktop engine has not reported in");
    if (d.remote_paused) diagnostics.push("Remote access is paused");
    if (d.remote_disabled_locally) diagnostics.push("Remote access was disabled on the PC");
    return { ...view(d), wakeAgentOnline: waker, diagnostics };
  });
  app.get("/api/v1/devices/:id/metrics", pre, async (req) => {
    const d = await loadDevice(req);
    const m = hub.metrics.get(d.id);
    return { deviceId: d.id, metrics: m ? { ...m, ts: undefined } : null, at: m ? new Date(m.ts).toISOString() : null };
  });
  app.get("/api/v1/wake-requests", pre, async (req) => {
    const q = parse(z.object({ deviceId: z.string().uuid().optional(), limit: z.coerce.number().int().min(1).max(100).default(20) }), req.query);
    const r = await db.query(
      `SELECT w.id, w.device_id, w.status, w.failure_reason, w.requested_at, w.sent_at, w.completed_at, w.prior_state FROM wake_requests w
       JOIN devices d ON d.id=w.device_id WHERE d.owner_id=$1 AND ($2::uuid IS NULL OR w.device_id=$2) ORDER BY w.requested_at DESC LIMIT $3`, [req.user!.id, q.deviceId ?? null, q.limit]);
    return { wakeRequests: r.rows };
  });
  app.get("/api/v1/network-agents", pre, async (req) => {
    const r = await db.query("SELECT id, name, status, last_seen, agent_version, revoked_at FROM network_agents WHERE owner_id=$1 ORDER BY created_at", [req.user!.id]);
    return { networkAgents: r.rows };
  });
  app.get("/api/v1/sessions", pre, async (req) => {
    const q = parse(z.object({ deviceId: z.string().uuid().optional(), limit: z.coerce.number().int().min(1).max(200).default(50) }), req.query);
    const r = await db.query(
      `SELECT s.id, s.device_id, s.user_id, s.state, s.started_at, s.ended_at, host(s.client_ip) AS client_ip, s.connection_type, s.provider, s.latency_ms_avg, s.reconnect_count, s.end_reason
       FROM remote_sessions s JOIN devices d ON d.id=s.device_id WHERE d.owner_id=$1 AND ($2::uuid IS NULL OR s.device_id=$2) ORDER BY s.started_at DESC LIMIT $3`,
      [req.user!.id, q.deviceId ?? null, q.limit]);
    return { sessions: r.rows };
  });
  app.get("/api/v1/audit-logs", pre, async (req) => {
    const q = parse(z.object({ deviceId: z.string().uuid().optional(), before: z.coerce.number().int().optional(), limit: z.coerce.number().int().min(1).max(200).default(50) }), req.query);
    const r = await db.query(
      `SELECT a.id, a.ts, a.user_id, a.device_id, a.action, a.result, host(a.ip) AS ip, a.detail FROM audit_logs a
       WHERE (a.user_id=$1 OR a.device_id IN (SELECT id FROM devices WHERE owner_id=$1)) AND ($2::uuid IS NULL OR a.device_id=$2) AND ($3::bigint IS NULL OR a.id<$3)
       ORDER BY a.id DESC LIMIT $4`, [req.user!.id, q.deviceId ?? null, q.before ?? null, q.limit]);
    return { auditLogs: r.rows };
  });
}
