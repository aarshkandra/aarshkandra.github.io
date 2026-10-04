import { b64, privateKeyFromSeed, publicKeyOf, rawPublicKey, signEnvelope, signHello, canonicalize } from "../src/index.js";

/** Deterministic cross-language fixtures. Ed25519 is deterministic, so these are stable. */
export function buildVectors() {
  const serverKey = privateKeyFromSeed(Buffer.alloc(32, 1));
  const agentKey = privateKeyFromSeed(Buffer.alloc(32, 2));
  const deviceUuid = "11111111-1111-4111-8111-111111111111";
  const env = signEnvelope(serverKey, {
    id: "22222222-2222-4222-8222-222222222222", cmd: "RESTART", args: { delaySeconds: 5 }, deviceUuid, now: 1790000000,
  });
  // nonce is random in production; pin it for the vector.
  const pinned = { ...env, nonce: "AAAAAAAAAAAAAAAAAAAAAA==" };
  const challenge = { nonce: "BBBBBBBBBBBBBBBBBBBBBB==", deviceUuid, serverOrigin: "https://remote.example.com", ts: 1790000000 };
  return {
    serverPublicKeyRaw: b64(rawPublicKey(publicKeyOf(serverKey))),
    agentPublicKeyRaw: b64(rawPublicKey(publicKeyOf(agentKey))),
    canonical: { input: { b: [2, 1, { z: null, a: "x" }], a: true }, output: canonicalize({ b: [2, 1, { z: null, a: "x" }], a: true }) },
    helloChallenge: challenge,
    helloSig: signHello(agentKey, challenge),
    pinnedBody: { ...pinned, sig: undefined },
    deviceUuid,
  };
}
