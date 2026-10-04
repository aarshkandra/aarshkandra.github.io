import type { DeviceStatus } from "@aarsh/protocol";
import type { Ctx } from "./ctx.js";
import { tx, type Db } from "./db.js";
import { transition, type DeviceEvent, type DeviceState } from "./state-machine.js";

/** The single place a device's persisted status changes. Throws IllegalTransition if the event is not allowed. */
export async function applyDeviceEvent(ctx: Ctx, deviceId: string, ev: DeviceEvent): Promise<DeviceState & { changed: boolean; ownerId: string }> {
  const r = await tx(ctx.db, async (c) => {
    const cur = await c.query<{ status: DeviceStatus; status_reason: string | null; owner_id: string }>(
      "SELECT status, status_reason, owner_id FROM devices WHERE id=$1 FOR UPDATE", [deviceId]);
    const row = cur.rows[0];
    if (!row) throw new Error("device not found");
    const next = transition(row.status, ev);
    const changed = next.status !== row.status || next.reason !== row.status_reason;
    const touchSeen = ev.type === "AGENT_CONNECTED";
    if (changed || touchSeen) {
      await c.query("UPDATE devices SET status=$2, status_reason=$3, last_seen=CASE WHEN $4 THEN now() ELSE last_seen END, updated_at=now() WHERE id=$1",
        [deviceId, next.status, next.reason, touchSeen]);
    }
    return { ...next, changed, ownerId: row.owner_id };
  });
  if (r.changed) {
    ctx.hub.sendToUser(r.ownerId, { type: "device.state", deviceId, status: r.status, reason: r.reason, lastSeen: new Date().toISOString() });
  }
  return r;
}

/**
 * Presence lives in memory, so after a server restart nobody is connected yet. Clear stale statuses so the dashboard never shows
 * a device ONLINE that nobody can reach; agents reconnect within seconds and flip themselves back.
 * SLEEPING stays (a sleeping PC cannot be connected). Interrupted wakes become ERROR (their timers died with the process),
 * and an agent connecting later still moves ERROR → ONLINE.
 */
export async function resetPresenceOnStartup(db: Db): Promise<{ devices: number; networkAgents: number }> {
  const d = await db.query(
    `UPDATE devices SET
       status = CASE WHEN status = 'ONLINE' THEN 'OFFLINE'::device_status ELSE 'ERROR'::device_status END,
       status_reason = CASE WHEN status = 'ONLINE' THEN NULL ELSE 'WAKE_INTERRUPTED' END,
       updated_at = now()
     WHERE status IN ('ONLINE','WAKE_REQUESTED','WAKING')`);
  const n = await db.query("UPDATE network_agents SET status='OFFLINE' WHERE status='ONLINE'");
  await db.query("UPDATE wake_requests SET status='FAILED', failure_reason='SERVER_RESTARTED', completed_at=now() WHERE status IN ('REQUESTED','SENT','WAKING')");
  return { devices: d.rowCount ?? 0, networkAgents: n.rowCount ?? 0 };
}
