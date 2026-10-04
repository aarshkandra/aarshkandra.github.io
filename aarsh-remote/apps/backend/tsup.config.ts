import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/server.ts"],
  format: ["esm"],
  target: "node22",
  noExternal: ["@aarsh/protocol"], // workspace package ships as TS source; inline it
  clean: true,
});
