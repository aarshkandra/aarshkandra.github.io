import type { Queryable } from "./db.js";

export interface AuditEntry {
  userId?: string | null;
  deviceId?: string | null;
  action: string;
  result: "SUCCESS" | "FAILURE" | "DENIED";
  ip?: string | null;
  userAgent?: string | null;
  detail?: Record<string, unknown>;
}

const FORBIDDEN = /pass|token|secret|key|totp|code|sig/i;
/** Defence in depth: strip anything that looks like a credential before it can reach the audit table. */
export function redact(detail: Record<string, unknown> = {}): Record<string, unknown> {
  return Object.fromEntries(Object.entries(detail).filter(([k]) => !FORBIDDEN.test(k)));
}

export async function audit(q: Queryable, e: AuditEntry): Promise<void> {
  await q.query(
    "INSERT INTO audit_logs(user_id,device_id,action,result,ip,user_agent,detail) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    [e.userId ?? null, e.deviceId ?? null, e.action, e.result, e.ip ?? null, e.userAgent?.slice(0, 300) ?? null, JSON.stringify(redact(e.detail))],
  );
}
