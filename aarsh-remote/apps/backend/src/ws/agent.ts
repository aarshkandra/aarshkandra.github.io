import { randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { WebSocket } from "ws";
import { agentMsg, compareSemver, helloMsg, publicKeyFromRaw, unb64, verifyHello, type AgentKind } from "@aarsh/protocol";
import type { Ctx } from "../ctx.js";
import type { AgentConn } from "../hub.js";
import { audit } from "../audit.js";
import { applyDeviceEvent } from "../presence.js";
import { IllegalTransition } from "../state-machine.js";

const HELLO_TIMEOUT_MS = 10_000;

interface CredRow { id: string; uuid: string; owner_id: string; public_key: Buffer; cred_id: string }

async function lookup(ctx: Ctx, kind: AgentKind, uuid: string): Promise<CredRow | null> {
  const q = kind === "DESKTOP"
    ? "SELECT d.id, d.device_uuid AS uuid, d.owner_id, c.public_key, c.id AS cred_id FROM devices d JOIN device_credentials c ON c.device_id=d.id WHERE d.device_uuid=$1 AND c.state='ACTIVE' AND d.revoked_at IS NULL AND d.deleted_at IS NULL"
    : "SELECT n.id, n.agent_uuid AS uuid, n.owner_id, c.public_key, c.id AS cred_id FROM network_agents n JOIN device_credentials c ON c.network_agent_id=n.id WHERE n.agent_uuid=$1 AND c.state='ACTIVE' AND n.revoked_at IS NULL";
  return (await ctx.db.query<CredRow>(q, [uuid])).rows[0] ?? null;
}

export function registerAgentGateway(app: FastifyInstance, ctx: Ctx) {
  const { hub, config, log } = ctx;

  app.get("/ws/agent", { websocket: true, config: { rateLimit: false } }, (socket: WebSocket, req) => {
    const challenge = { nonce: randomBytes(24).toString("base64"), serverOrigin: config.SERVER_ORIGIN, ts: Math.floor(Date.now() / 1000) };
    let conn: AgentConn | null = null;
    let authing = false;
    const ip = req.ip;
    const helloTimer = setTimeout(() => socket.close(4408, "hello timeout"), HELLO_TIMEOUT_MS);
    socket.send(JSON.stringify({ type: "challenge", ...challenge }));

    const denyAndClose = async (uuid: string | null, why: string, code = 4401) => {
      await audit(ctx.db, { action: "AGENT_AUTH", result: "DENIED", ip, detail: { why, uuid } }).catch(() => {});
      socket.close(code, why);
    };

    socket.on("message", async (raw: Buffer) => {
      try {
        let json: unknown;
        try { json = JSON.parse(raw.toString("utf8")); } catch { return socket.close(4400, "bad json"); }

        if (!conn) {
          if (authing) return;
          authing = true;
          const hello = helloMsg.safeParse(json);
          if (!hello.success) return void (await denyAndClose(null, "bad hello"));
          const h = hello.data;
          const cred = await lookup(ctx, h.kind, h.deviceUuid);
          if (!cred) return void (await denyAndClose(h.deviceUuid, "unknown or revoked"));
          const okSig = verifyHello(publicKeyFromRaw(cred.public_key), { ...challenge, deviceUuid: h.deviceUuid }, unb64(h.sig));
          if (!okSig) return void (await denyAndClose(h.deviceUuid, "bad signature"));
          if (compareSemver(h.version, config.MIN_AGENT_VERSION) < 0) {
            socket.send(JSON.stringify({ type: "error", code: "AGENT_OUTDATED", minVersion: config.MIN_AGENT_VERSION }));
            return void (await denyAndClose(h.deviceUuid, "agent outdated", 4426));
          }
          clearTimeout(helloTimer);
          const c: AgentConn = { ws: socket, kind: h.kind, id: cred.id, uuid: cred.uuid, ownerId: cred.owner_id, lastBeat: Date.now(), goingToSleep: false };
          const map = hub.agentMap(h.kind);
          const old = map.get(c.id);
          map.set(c.id, c);
          conn = c;
          if (old) { hub.failPendingFor(old, "REPLACED"); old.ws.close(4409, "replaced"); }
          await onAuthenticated(ctx, c, h.version, h.info, cred.cred_id, ip);
          socket.send(JSON.stringify({ type: "ready", heartbeatSec: 15 }));
          return;
        }

        const msg = agentMsg.safeParse(json);
        if (!msg.success) return void log.warn({ id: conn.id }, "invalid agent message");
        conn.lastBeat = Date.now();
        await onAgentMessage(ctx, conn, msg.data);
      } catch (err) {
        log.error({ err }, "agent ws error");
      }
    });

    socket.on("close", () => {
      clearTimeout(helloTimer);
      const c = conn;
      if (!c) return;
      const map = hub.agentMap(c.kind);
      if (map.get(c.id) !== c) return; // replaced by a newer connection
      map.delete(c.id);
      hub.failPendingFor(c, "AGENT_DISCONNECTED");
      void onDisconnected(ctx, c).catch((err) => log.error({ err }, "disconnect handling failed"));
    });
    socket.on("error", () => socket.terminate());
  });

  // Liveness sweeper: terminates half-open connections.
  const sweeper = setInterval(() => {
    const cutoff = Date.now() - config.HEARTBEAT_TIMEOUT_MS;
    for (const c of [...hub.desktops.values(), ...hub.wakers.values()]) if (c.lastBeat < cutoff) c.ws.terminate();
  }, config.HEARTBEAT_SWEEP_MS);
  sweeper.unref();
  app.addHook("onClose", async () => clearInterval(sweeper));
}

async function onAuthenticated(ctx: Ctx, c: AgentConn, version: string, info: { os?: string; localIp?: string; mac?: string; rustdeskId?: string } | undefined, credId: string, ip: string) {
  await ctx.db.query("UPDATE device_credentials SET last_used_at=now() WHERE id=$1", [credId]);
  if (c.kind === "WAKE") {
    await ctx.db.query("UPDATE network_agents SET status='ONLINE', last_seen=now(), agent_version=$2 WHERE id=$1", [c.id, version]);
    ctx.hub.sendToUser(c.ownerId, { type: "network-agent.state", networkAgentId: c.id, status: "ONLINE" });
  } else {
    await ctx.db.query(
      "UPDATE devices SET agent_version=$2, os=COALESCE($3,os), local_ip=COALESCE($4::inet,local_ip), rustdesk_id=COALESCE($5,rustdesk_id), mac_address=COALESCE(mac_address,$6::macaddr), updated_at=now() WHERE id=$1",
      [c.id, version, info?.os ?? null, info?.localIp ?? null, info?.rustdeskId ?? null, info?.mac ?? null]);
    ctx.hub.clearWakeTimer(c.id);
    await applyDeviceEvent(ctx, c.id, { type: "AGENT_CONNECTED" });
    await ctx.db.query("UPDATE wake_requests SET status='SUCCEEDED', completed_at=now() WHERE device_id=$1 AND status IN ('REQUESTED','SENT','WAKING')", [c.id]);
  }
  await audit(ctx.db, { userId: c.ownerId, deviceId: c.kind === "DESKTOP" ? c.id : null, action: "AGENT_CONNECT", result: "SUCCESS", ip, detail: { kind: c.kind, version } });
}

async function onAgentMessage(ctx: Ctx, c: AgentConn, m: ReturnType<typeof agentMsg.parse>) {
  switch (m.type) {
    case "heartbeat":
      if (c.kind === "DESKTOP") {
        await ctx.db.query("UPDATE devices SET last_seen=now(), remote_disabled_locally=COALESCE($2, remote_disabled_locally) WHERE id=$1", [c.id, m.remoteDisabled ?? null]);
      } else {
        await ctx.db.query("UPDATE network_agents SET last_seen=now() WHERE id=$1", [c.id]);
      }
      return;
    case "metrics":
      if (c.kind !== "DESKTOP") return;
      ctx.hub.metrics.set(c.id, { ...m.metrics, ts: Date.now() });
      ctx.hub.sendToUser(c.ownerId, { type: "device.metrics", deviceId: c.id, metrics: m.metrics });
      return;
    case "event":
      if (c.kind !== "DESKTOP") return;
      if (m.name === "GOING_TO_SLEEP") c.goingToSleep = true;
      if (m.name === "RESUMED") c.goingToSleep = false;
      if (m.name === "REMOTE_DISABLED" || m.name === "REMOTE_ENABLED") {
        await ctx.db.query("UPDATE devices SET remote_disabled_locally=$2 WHERE id=$1", [c.id, m.name === "REMOTE_DISABLED"]);
        await audit(ctx.db, { userId: c.ownerId, deviceId: c.id, action: m.name, result: "SUCCESS" });
      }
      return;
    case "ack":
      ctx.hub.resolveAck(m.commandId, c, { ok: m.ok, error: m.error, data: m.data });
      return;
    case "lan.probe":
      if (c.kind === "WAKE") ctx.hub.sendToUser(c.ownerId, { type: "lan.probe", networkAgentId: c.id, deviceUuid: m.deviceUuid, reachable: m.reachable, ms: m.ms });
      return;
  }
}

async function onDisconnected(ctx: Ctx, c: AgentConn) {
  if (c.kind === "WAKE") {
    await ctx.db.query("UPDATE network_agents SET status='OFFLINE', last_seen=now() WHERE id=$1", [c.id]);
    ctx.hub.sendToUser(c.ownerId, { type: "network-agent.state", networkAgentId: c.id, status: "OFFLINE" });
    return;
  }
  ctx.hub.metrics.delete(c.id);
  try {
    await applyDeviceEvent(ctx, c.id, { type: "AGENT_DISCONNECTED", sleeping: c.goingToSleep });
  } catch (e) {
    if (!(e instanceof IllegalTransition)) throw e;
  }
  await ctx.db.query("UPDATE devices SET last_seen=now() WHERE id=$1", [c.id]);
}
