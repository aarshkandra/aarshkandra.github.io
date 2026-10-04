import type { WebSocket } from "ws";
import type { AgentKind, Metrics } from "@aarsh/protocol";

export interface AgentConn {
  ws: WebSocket;
  kind: AgentKind;
  /** devices.id (DESKTOP) or network_agents.id (WAKE) */
  id: string;
  uuid: string;
  ownerId: string;
  lastBeat: number;
  goingToSleep: boolean;
}

export interface ClientConn { ws: WebSocket; userId: string }

export interface AckResult { ok: boolean; error?: string; data?: Record<string, unknown> }
interface Pending { conn: AgentConn; resolve: (r: AckResult) => void; timer: NodeJS.Timeout }

/** In-memory connection registry. Single-instance by design (architecture D9); persisted state lives in Postgres. */
export class Hub {
  readonly desktops = new Map<string, AgentConn>();
  readonly wakers = new Map<string, AgentConn>();
  readonly clients = new Map<string, Set<ClientConn>>();
  readonly metrics = new Map<string, Metrics & { ts: number }>();
  readonly pending = new Map<string, Pending>();
  readonly wakeTimers = new Map<string, NodeJS.Timeout>();

  agentMap(kind: AgentKind) { return kind === "DESKTOP" ? this.desktops : this.wakers; }

  addClient(c: ClientConn) {
    let s = this.clients.get(c.userId);
    if (!s) this.clients.set(c.userId, (s = new Set()));
    s.add(c);
  }
  removeClient(c: ClientConn) {
    const s = this.clients.get(c.userId);
    s?.delete(c);
    if (s && s.size === 0) this.clients.delete(c.userId);
  }
  sendToUser(userId: string, msg: unknown) {
    const data = JSON.stringify(msg);
    for (const c of this.clients.get(userId) ?? []) if (c.ws.readyState === 1) c.ws.send(data);
  }

  expectAck(commandId: string, conn: AgentConn, timeoutMs: number): Promise<AckResult | "TIMEOUT"> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => { this.pending.delete(commandId); resolve("TIMEOUT"); }, timeoutMs);
      this.pending.set(commandId, { conn, resolve: (r) => { clearTimeout(timer); resolve(r); }, timer });
    });
  }
  /** Only the agent the command was sent to may ack it. */
  resolveAck(commandId: string, from: AgentConn, r: AckResult): boolean {
    const p = this.pending.get(commandId);
    if (!p || p.conn !== from) return false;
    this.pending.delete(commandId);
    p.resolve(r);
    return true;
  }
  failPendingFor(conn: AgentConn, error: string) {
    for (const [id, p] of this.pending) if (p.conn === conn) { this.pending.delete(id); p.resolve({ ok: false, error }); }
  }

  clearWakeTimer(deviceId: string) {
    const t = this.wakeTimers.get(deviceId);
    if (t) { clearTimeout(t); this.wakeTimers.delete(deviceId); }
  }

  shutdown() {
    for (const t of this.wakeTimers.values()) clearTimeout(t);
    for (const p of this.pending.values()) clearTimeout(p.timer);
    for (const c of [...this.desktops.values(), ...this.wakers.values()]) c.ws.terminate();
    for (const s of this.clients.values()) for (const c of s) c.ws.terminate();
  }
}
