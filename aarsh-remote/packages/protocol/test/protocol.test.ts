import { describe, expect, it } from "vitest";
import {
  COMMANDS, COMMAND_ARGS, canonicalize, generateEd25519, isCommand, publicKeyFromRaw, publicKeyOf, parseArgs,
  signEnvelope, verifyEnvelope, signHello, verifyHello, unb64, privateKeyFromSeed, agentMsg, compareSemver, signingInput,
  signBytes, b64,
} from "../src/index.js";
import { buildVectors } from "./vectors.js";
import fixture from "./vectors.json" with { type: "json" };

const dev = "11111111-1111-4111-8111-111111111111";
const id = "22222222-2222-4222-8222-222222222222";
const server = generateEd25519();
const serverPub = publicKeyOf(server.privateKey);

describe("canonicalize", () => {
  it("sorts keys, drops undefined, no whitespace", () => {
    expect(canonicalize({ b: 1, a: [1, { d: 1, c: undefined }] })).toBe('{"a":[1,{"d":1}],"b":1}');
  });
  it("rejects non-JSON values", () => {
    expect(() => canonicalize({ a: NaN })).toThrow();
    expect(() => canonicalize({ a: () => 1 })).toThrow();
  });
});

describe("command allow-list", () => {
  it("has no generic execute/shell command", () => {
    expect(COMMANDS.some((c) => /EXEC|SHELL|RUN|CMD/i.test(c))).toBe(false);
    expect(isCommand("EXECUTE_COMMAND")).toBe(false);
  });
  it("every command has an args schema", () => {
    for (const c of COMMANDS) expect(COMMAND_ARGS[c]).toBeDefined();
  });
  it("rejects unknown/extra args (strict) and bad MAC", () => {
    expect(parseArgs("SLEEP", { cmd: "calc.exe" }).ok).toBe(false);
    expect(parseArgs("WAKE", { mac: "nope", broadcast: "192.168.1.255" }).ok).toBe(false);
    expect(parseArgs("WAKE", { mac: "AA:BB:CC:DD:EE:FF", broadcast: "192.168.1.255" }).ok).toBe(true);
    expect(parseArgs("RESTART", { delaySeconds: 999 }).ok).toBe(false);
  });
});

describe("command envelope", () => {
  const mk = (over: Record<string, unknown> = {}) => signEnvelope(server.privateKey, { id, cmd: "SLEEP", args: {}, deviceUuid: dev, now: 1000, ...over });
  it("verifies a good envelope", () => {
    expect(verifyEnvelope(serverPub, mk(), { expectedDeviceUuid: dev, now: 1010 }).ok).toBe(true);
  });
  it("rejects tampering with cmd or args", () => {
    const e = mk();
    expect(verifyEnvelope(serverPub, { ...e, cmd: "SHUTDOWN" }, { expectedDeviceUuid: dev, now: 1010 })).toMatchObject({ ok: false, reason: "BAD_SIGNATURE" });
    const w = signEnvelope(server.privateKey, { id, cmd: "RESTART", args: { delaySeconds: 1 }, deviceUuid: dev, now: 1000 });
    expect(verifyEnvelope(serverPub, { ...w, args: { delaySeconds: 0 } }, { expectedDeviceUuid: dev, now: 1010 })).toMatchObject({ reason: "BAD_SIGNATURE" });
  });
  it("rejects a different server key", () => {
    const other = publicKeyOf(generateEd25519().privateKey);
    expect(verifyEnvelope(other, mk(), { expectedDeviceUuid: dev, now: 1010 })).toMatchObject({ reason: "BAD_SIGNATURE" });
  });
  it("rejects wrong device (cannot replay to another agent)", () => {
    expect(verifyEnvelope(serverPub, mk(), { expectedDeviceUuid: "33333333-3333-4333-8333-333333333333", now: 1010 })).toMatchObject({ reason: "WRONG_DEVICE" });
  });
  it("rejects expired and not-yet-valid", () => {
    expect(verifyEnvelope(serverPub, mk(), { expectedDeviceUuid: dev, now: 1031 })).toMatchObject({ reason: "EXPIRED" });
    expect(verifyEnvelope(serverPub, mk(), { expectedDeviceUuid: dev, now: 900 })).toMatchObject({ reason: "NOT_YET_VALID" });
  });
  it("rejects over-long lifetime even if correctly signed", () => {
    const body = { id, cmd: "SLEEP" as const, args: {}, issuedAt: 1000, expiresAt: 1000 + 3600, nonce: "AAAAAAAAAAAAAAAAAAAAAA==", deviceUuid: dev };
    const sig = b64(signBytes(server.privateKey, signingInput(body)));
    expect(verifyEnvelope(serverPub, { type: "command", ...body, sig }, { expectedDeviceUuid: dev, now: 1001 })).toMatchObject({ reason: "LIFETIME_TOO_LONG" });
  });
  it("rejects malformed / unknown commands", () => {
    expect(verifyEnvelope(serverPub, { foo: 1 }, { expectedDeviceUuid: dev })).toMatchObject({ reason: "MALFORMED" });
    expect(verifyEnvelope(serverPub, null, { expectedDeviceUuid: dev })).toMatchObject({ reason: "MALFORMED" });
    const e = { ...mk(), cmd: "EXECUTE_COMMAND" };
    expect(verifyEnvelope(serverPub, e, { expectedDeviceUuid: dev, now: 1010 })).toMatchObject({ reason: "MALFORMED" });
  });
  it("refuses to sign invalid args", () => {
    expect(() => mk({ cmd: "SLEEP", args: { x: 1 } })).toThrow();
  });
});

describe("hello challenge-response", () => {
  const agent = generateEd25519();
  const c = { nonce: "abc", deviceUuid: dev, serverOrigin: "https://s.example", ts: 5 };
  it("verifies and binds every field", () => {
    const sig = unb64(signHello(agent.privateKey, c));
    const pub = publicKeyFromRaw(agent.publicKeyRaw);
    expect(verifyHello(pub, c, sig)).toBe(true);
    for (const k of Object.keys(c) as (keyof typeof c)[]) {
      expect(verifyHello(pub, { ...c, [k]: k === "ts" ? 6 : "zzz" }, sig)).toBe(false);
    }
  });
});

describe("agent messages", () => {
  it("validates ack and rejects junk", () => {
    expect(agentMsg.safeParse({ type: "ack", commandId: id, ok: true }).success).toBe(true);
    expect(agentMsg.safeParse({ type: "exec", cmd: "calc" }).success).toBe(false);
    expect(agentMsg.safeParse({ type: "metrics", metrics: { cpuPct: 150 } }).success).toBe(false);
  });
});

describe("semver", () => {
  it("compares", () => {
    expect(compareSemver("1.2.3", "1.2.3")).toBe(0);
    expect(compareSemver("1.10.0", "1.9.9")).toBe(1);
    expect(compareSemver("0.9.0", "1.0.0")).toBe(-1);
  });
});

describe("cross-language test vectors", () => {
  it("fixture matches regenerated vectors (run `pnpm gen:vectors` if intentionally changed)", () => {
    expect(JSON.parse(JSON.stringify(buildVectors()))).toEqual(fixture);
    expect(privateKeyFromSeed(Buffer.alloc(32, 1))).toBeDefined();
  });
});
