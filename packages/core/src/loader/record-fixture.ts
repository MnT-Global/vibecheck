/**
 * record-fixture — snapshot a local directory into fixtures/<name> for deterministic tests.
 * Usage: pnpm record-fixture <source-dir> <fixture-name>
 * (v0.1: local copy. Cloning a public git URL is a later enhancement.)
 */
import { cp, mkdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", "out", "coverage"]);

function repoRoot(): string {
  // .../packages/core/src/loader/record-fixture.ts -> up 4 dirs
  return resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
}

async function main(): Promise<void> {
  const [source, name] = process.argv.slice(2);
  if (!source || !name) {
    console.error("Usage: pnpm record-fixture <source-dir> <fixture-name>");
    process.exit(1);
  }
  const dest = join(repoRoot(), "fixtures", name);
  await mkdir(dirname(dest), { recursive: true });
  await cp(resolve(source), dest, {
    recursive: true,
    filter: (src) => !SKIP.has(src.split("/").pop() ?? ""),
  });
  console.log(`Recorded fixture: fixtures/${name}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
