import { fileURLToPath } from "node:url";
import { loadConfig } from "./config.js";
import { createDb, migrate } from "./db.js";
import { buildApp } from "./app.js";

const config = loadConfig();
const db = createDb(process.env.DATABASE_URL!);
const dir = process.env.MIGRATIONS_DIR ?? fileURLToPath(new URL("../../../infrastructure/postgres/migrations", import.meta.url));
if (process.env.AUTO_MIGRATE !== "false") await migrate(db, dir);

const { app } = await buildApp(config, db);
await app.listen({ port: config.PORT, host: config.HOST });

for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, async () => { await app.close(); await db.end(); process.exit(0); });
}
