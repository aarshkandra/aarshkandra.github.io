#!/usr/bin/env node
// Prints fresh secrets for infrastructure/docker/.env — run once, store the output safely, never commit it.
import { generateKeyPairSync, randomBytes } from "node:crypto";
const pkcs8 = () => generateKeyPairSync("ed25519").privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
const rnd = (n) => randomBytes(n).toString("base64");
console.log(`JWT_PRIVATE_KEY=${pkcs8()}`);
console.log(`COMMAND_SIGNING_KEY=${pkcs8()}`);
console.log(`TOTP_ENC_KEY=${rnd(32)}`);
console.log(`PEPPER=${rnd(32)}`);
console.log(`POSTGRES_PASSWORD=${randomBytes(24).toString("base64url")}`);
