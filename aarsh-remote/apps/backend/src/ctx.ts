import type { FastifyBaseLogger } from "fastify";
import type { Config } from "./config.js";
import type { Db } from "./db.js";
import type { Hub } from "./hub.js";

export interface Ctx { config: Config; db: Db; hub: Hub; log: FastifyBaseLogger }
