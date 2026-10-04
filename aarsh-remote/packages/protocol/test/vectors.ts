import { b64, privateKeyFromSeed, publicKeyOf, rawPublicKey, signEnvelope, signHello, canonicalize, pairingPollInput, signBytes, signingInput } from "../src/index.js";

/** Deterministic cross-language fixtures. Ed25519 is deterministic, so these are stable. */
export function buildVectors() {
  const serverKey = privateKeyFromSeed(Buffer.alloc(32, 1));
  const agentKey = privateKeyFromSeed(Buffer.alloc(32, 2));
  const deviceUuid = "11111111-1111-4111-8111-111111111111";
  const env = signEnvelope(serverKey, {
    id: "22222222-2222-4222-8222-222222222222", cmd: "RESTART", args: { delaySeconds: 5 }, deviceUuid, now: 1790000000,
  });
  // nonce is random in production; pin it and re-sign for the vector.
  const { type: _t, sig: _s, ...body } = { ...env, nonce: "AAAAAAAAAAAAAAAAAAAAAA==" };
  const pinned = { type: "command" as const, ...body, sig: b64(signBytes(serverKey, signingInput(body))) };
  const pollTs = 1790000000;
  const pollRequestId = "44444444-4444-4444-8444-444444444444";
  const challenge = { nonce: "BBBBBBBBBBBBBBBBBBBBBB==", deviceUuid, serverOrigin: "https://remote.example.com", ts: 1790000000 };
  return {
    serverPublicKeyRaw: b64(rawPublicKey(publicKeyOf(serverKey))),
    agentPublicKeyRaw: b64(rawPublicKey(publicKeyOf(agentKey))),
    canonical: { input: { b: [2, 1, { z: null, a: "x" }], a: true }, output: canonicalize({ b: [2, 1, { z: null, a: "x" }], a: true }) },
    canonicalUnicode: (() => {
      const input = { s: "a\"b\\c\n\t\u0001é😀\u007f\u2028", lone: "x\ud800y", k: { "é": 1, Z: 2, a: 3, "😀": 4 }, n: [-5, 0, 9007199254740991] };
      return { input, output: canonicalize(input) };
    })(),
    helloChallenge: challenge,
    helloSig: signHello(agentKey, challenge),
    serverSeed: b64(Buffer.alloc(32, 1)),
    agentSeed: b64(Buffer.alloc(32, 2)),
    envelope: pinned,
    envelopeSigningInput: signingInput(body).toString("utf8"),
    pairingPoll: { requestId: pollRequestId, ts: pollTs, sig: b64(signBytes(agentKey, pairingPollInput(pollRequestId, pollTs))) },
    deviceUuid,
  };
}
