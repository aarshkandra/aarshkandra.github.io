import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, randomBytes, type KeyObject } from "node:crypto";

// Ed25519 helpers. Raw public keys are 32 bytes; private keys travel as PKCS8 DER.
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export const b64 = (b: Uint8Array): string => Buffer.from(b).toString("base64");
export const unb64 = (s: string): Buffer => Buffer.from(s, "base64");

export function generateEd25519(): { privateKey: KeyObject; publicKeyRaw: Buffer } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicKeyRaw: rawPublicKey(publicKey) };
}

export function rawPublicKey(key: KeyObject): Buffer {
  const der = key.export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(SPKI_PREFIX.length));
}

export function publicKeyFromRaw(raw: Uint8Array): KeyObject {
  if (raw.length !== 32) throw new Error("ed25519 public key must be 32 bytes");
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

export function privateKeyFromSeed(seed: Uint8Array): KeyObject {
  if (seed.length !== 32) throw new Error("ed25519 seed must be 32 bytes");
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
}

export function publicKeyOf(privateKey: KeyObject): KeyObject {
  return createPublicKey(privateKey);
}

export function signBytes(privateKey: KeyObject, data: Uint8Array): Buffer {
  return sign(null, data, privateKey);
}

export function verifyBytes(publicKey: KeyObject, data: Uint8Array, signature: Uint8Array): boolean {
  try {
    return verify(null, data, publicKey, signature);
  } catch {
    return false;
  }
}

export const randomB64 = (bytes = 16): string => randomBytes(bytes).toString("base64");
