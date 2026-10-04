import { writeFileSync } from "node:fs";
import { buildVectors } from "./vectors.js";
writeFileSync(new URL("./vectors.json", import.meta.url), JSON.stringify(buildVectors(), null, 2) + "\n");
