import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/loader/record-fixture.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  target: "node20",
  splitting: false,
  sourcemap: true,
});
