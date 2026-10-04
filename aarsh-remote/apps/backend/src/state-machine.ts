import type { DeviceStatus } from "@aarsh/protocol";

/** Device presence state machine (architecture §6). Pure; all status changes in the server go through `transition`. */
export type DeviceEvent =
  | { type: "AGENT_CONNECTED" }
  | { type: "AGENT_DISCONNECTED"; sleeping: boolean }
  | { type: "WAKE_REQUESTED" }
  | { type: "WAKE_SENT" }
  | { type: "WAKE_FAILED"; reason: string }
  | { type: "WAKE_TIMEOUT" }
  | { type: "AGENT_ERROR"; reason: string }
  | { type: "REVOKED" };

export interface DeviceState { status: DeviceStatus; reason: string | null }

export class IllegalTransition extends Error {
  constructor(public readonly from: DeviceStatus, public readonly event: DeviceEvent["type"]) {
    super(`illegal transition ${from} --${event}-->`);
  }
}

const IDLE: readonly DeviceStatus[] = ["UNKNOWN", "OFFLINE", "SLEEPING", "ERROR"];
const WAKING_STATES: readonly DeviceStatus[] = ["WAKE_REQUESTED", "WAKING"];

export function transition(from: DeviceStatus, ev: DeviceEvent): DeviceState {
  const ok = (status: DeviceStatus, reason: string | null = null): DeviceState => ({ status, reason });
  switch (ev.type) {
    case "AGENT_CONNECTED":
      return ok("ONLINE");
    case "AGENT_DISCONNECTED":
      if (from === "ONLINE") return ok(ev.sleeping ? "SLEEPING" : "OFFLINE");
      return ok(from); // not online: nothing to lose (e.g. already WAKING)
    case "WAKE_REQUESTED":
      if (IDLE.includes(from)) return ok("WAKE_REQUESTED");
      throw new IllegalTransition(from, ev.type);
    case "WAKE_SENT":
      if (from === "WAKE_REQUESTED") return ok("WAKING");
      throw new IllegalTransition(from, ev.type);
    case "WAKE_FAILED":
      if (WAKING_STATES.includes(from)) return ok("ERROR", ev.reason);
      throw new IllegalTransition(from, ev.type);
    case "WAKE_TIMEOUT":
      if (from === "WAKING") return ok("ERROR", "WAKE_NO_RESPONSE");
      throw new IllegalTransition(from, ev.type);
    case "AGENT_ERROR":
      return ok("ERROR", ev.reason);
    case "REVOKED":
      return ok("OFFLINE", "DEVICE_REVOKED");
  }
}
