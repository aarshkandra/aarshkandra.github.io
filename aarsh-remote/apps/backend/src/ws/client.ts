import type { FastifyInstance } from "fastify";
import type { WebSocket } from "ws";
import { clientMsg } from "@aarsh/protocol";
import type { Ctx } from "../ctx.js";
import type { ClientConn } from "../hub.js";
import { sessionActive } from "../auth/service.js";
import { verifyAccess } from "../auth/tokens.js";

export function registerClientGateway(app: FastifyInstance, ctx: Ctx) {
  app.get("/ws/client", { websocket: true, config: { rateLimit: false } }, (socket: WebSocket) => {
    let conn: ClientConn | null = null;
    let sid = "";
    let exp = 0;
    const authTimer = setTimeout(() => socket.close(4408, "auth timeout"), 5000);

    socket.on("message", async (raw: Buffer) => {
      try {
        let json: unknown;
        try { json = JSON.parse(raw.toString("utf8")); } catch { return socket.close(4400, "bad json"); }
        const m = clientMsg.safeParse(json);
        if (!m.success) return socket.close(4400, "bad message");

        if (!conn) {
          if (m.data.type !== "auth") return socket.close(4401, "auth required");
          const claims = await verifyAccess(ctx.config, m.data.accessToken);
          if (!claims || !(await sessionActive(ctx, claims.userId, claims.sid))) return socket.close(4401, "access denied");
          clearTimeout(authTimer);
          conn = { ws: socket, userId: claims.userId };
          sid = claims.sid;
          exp = Date.now() + ctx.config.ACCESS_TOKEN_TTL_S * 1000;
          ctx.hub.addClient(conn);
          socket.send(JSON.stringify({ type: "ready" }));
          return;
        }
        // Access-token expiry applies to the socket too: the client must reconnect with a fresh token.
        if (Date.now() > exp || !(await sessionActive(ctx, conn.userId, sid))) return socket.close(4401, "session expired");

        switch (m.data.type) {
          case "ping": socket.send(JSON.stringify({ type: "pong" })); return;
          case "auth": return;
          case "session.report": {
            const s = m.data;
            const ended = s.state === "ENDED" || s.state === "FAILED";
            await ctx.db.query(
              `UPDATE remote_sessions SET state=$3::session_state, connection_type=COALESCE($4,connection_type),
                 latency_ms_avg=COALESCE($5::int,latency_ms_avg),
                 reconnect_count=reconnect_count + CASE WHEN $3='CONNECTED' AND state='DISCONNECTED' THEN 1 ELSE 0 END,
                 ended_at=CASE WHEN $6 THEN now() ELSE ended_at END
               WHERE id=$1 AND user_id=$2 AND state NOT IN ('ENDED','FAILED')`,
              [s.sessionId, conn.userId, s.state, s.connectionType ?? null, s.rttMs !== undefined ? Math.round(s.rttMs) : null, ended]);
            return;
          }
        }
      } catch (err) {
        ctx.log.error({ err }, "client ws error");
      }
    });
    socket.on("close", () => { clearTimeout(authTimer); if (conn) ctx.hub.removeClient(conn); });
    socket.on("error", () => socket.terminate());
  });
}
