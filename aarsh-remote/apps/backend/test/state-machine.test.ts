import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { DEVICE_STATUSES, type DeviceStatus } from "@aarsh/protocol";
import { IllegalTransition, transition, type DeviceEvent } from "../src/state-machine.js";

const events: DeviceEvent[] = [
  { type: "AGENT_CONNECTED" }, { type: "AGENT_DISCONNECTED", sleeping: true }, { type: "AGENT_DISCONNECTED", sleeping: false },
  { type: "WAKE_REQUESTED" }, { type: "WAKE_SENT" }, { type: "WAKE_FAILED", reason: "X" }, { type: "WAKE_TIMEOUT" },
  { type: "AGENT_ERROR", reason: "E" }, { type: "REVOKED" },
];

describe("device state machine", () => {
  it("happy path: SLEEPING → WAKE_REQUESTED → WAKING → ONLINE", () => {
    let s: DeviceStatus = "SLEEPING";
    s = transition(s, { type: "WAKE_REQUESTED" }).status; expect(s).toBe("WAKE_REQUESTED");
    s = transition(s, { type: "WAKE_SENT" }).status; expect(s).toBe("WAKING");
    s = transition(s, { type: "AGENT_CONNECTED" }).status; expect(s).toBe("ONLINE");
  });
  it("distinguishes sleeping from offline on disconnect", () => {
    expect(transition("ONLINE", { type: "AGENT_DISCONNECTED", sleeping: true }).status).toBe("SLEEPING");
    expect(transition("ONLINE", { type: "AGENT_DISCONNECTED", sleeping: false }).status).toBe("OFFLINE");
  });
  it("disconnect while waking does not regress the wake", () => {
    expect(transition("WAKING", { type: "AGENT_DISCONNECTED", sleeping: false }).status).toBe("WAKING");
  });
  it("waking timeout → ERROR with reason", () => {
    expect(transition("WAKING", { type: "WAKE_TIMEOUT" })).toEqual({ status: "ERROR", reason: "WAKE_NO_RESPONSE" });
  });
  it("rejects wake when already online or already waking", () => {
    for (const s of ["ONLINE", "WAKE_REQUESTED", "WAKING"] as const) expect(() => transition(s, { type: "WAKE_REQUESTED" })).toThrow(IllegalTransition);
  });
  it("rejects WAKE_SENT/WAKE_TIMEOUT from wrong states", () => {
    expect(() => transition("ONLINE", { type: "WAKE_SENT" })).toThrow(IllegalTransition);
    expect(() => transition("SLEEPING", { type: "WAKE_TIMEOUT" })).toThrow(IllegalTransition);
  });
  it("property: any event sequence either throws IllegalTransition or lands on a valid status; ONLINE only via AGENT_CONNECTED", () => {
    fc.assert(fc.property(fc.array(fc.constantFrom(...events), { maxLength: 40 }), fc.constantFrom(...DEVICE_STATUSES), (seq, start) => {
      let s: DeviceStatus = start;
      for (const ev of seq) {
        try {
          const n = transition(s, ev);
          expect(DEVICE_STATUSES).toContain(n.status);
          if (n.status === "ONLINE" && s !== "ONLINE") expect(ev.type).toBe("AGENT_CONNECTED");
          s = n.status;
        } catch (e) {
          expect(e).toBeInstanceOf(IllegalTransition);
        }
      }
    }), { numRuns: 500 });
  });
});
