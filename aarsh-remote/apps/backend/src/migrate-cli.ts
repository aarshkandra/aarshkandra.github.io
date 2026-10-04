import { fileURLToPath } from "node:url";
import { createDb, migrate } from "./db.js";

const dir = process.env.MIGRATIONS_DIR ?? fileURLToPath(new URL("../../../infrastructure/postgres/migrations", import.meta.url));
const db = createDb(process.env.DATABASE_URL ?? "");
console.log("applied:", await migrate(db, dir));
await db.end();
