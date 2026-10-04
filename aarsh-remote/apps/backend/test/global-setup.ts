import { fileURLToPath } from "node:url";
import pg from "pg";
import { createDb, migrate } from "../src/db.js";

export const ADMIN_URL = process.env.TEST_ADMIN_DATABASE_URL ?? "postgres://postgres@localhost:5433/postgres";
export const TEST_DB = "aarsh_test";

export default async function setup() {
  const admin = new pg.Client({ connectionString: ADMIN_URL });
  await admin.connect();
  await admin.query(`DROP DATABASE IF EXISTS ${TEST_DB} WITH (FORCE)`);
  await admin.query(`CREATE DATABASE ${TEST_DB}`);
  await admin.end();
  const url = new URL(ADMIN_URL);
  url.pathname = `/${TEST_DB}`;
  process.env.TEST_DATABASE_URL = url.toString();
  const db = createDb(url.toString());
  await migrate(db, fileURLToPath(new URL("../../../infrastructure/postgres/migrations", import.meta.url)));
  await db.end();
}
