import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Dependency, SourceFile } from "../types.js";

/** package-lock.json v2/v3: the `packages` map keyed by node_modules paths. */
function fromPackageLock(text: string): Dependency[] {
  const out: Dependency[] = [];
  let json: { packages?: Record<string, { version?: string; dev?: boolean }> };
  try {
    json = JSON.parse(text);
  } catch {
    return out;
  }
  for (const [key, val] of Object.entries(json.packages ?? {})) {
    if (key === "" || !val?.version) continue;
    const name = key.replace(/^.*node_modules\//, "");
    if (!name) continue;
    out.push({ name, version: val.version, dev: !!val.dev });
  }
  return out;
}

/** pnpm-lock.yaml: `packages:` keys like `/name@version:` or `name@version:`. */
function fromPnpmLock(text: string): Dependency[] {
  const out: Dependency[] = [];
  const re = /^\s+\/?((?:@[^/@\s]+\/)?[^@\s/]+)@([\d][^:\s(]*)[(:]/gm;
  for (const m of text.matchAll(re)) {
    if (m[1] && m[2]) out.push({ name: m[1], version: m[2], dev: false });
  }
  return out;
}

/** yarn.lock: an `"name@range:"` header followed by a `version "x.y.z"` line. */
function fromYarnLock(text: string): Dependency[] {
  const out: Dependency[] = [];
  const re = /^"?((?:@[^/@\s"]+\/)?[^@\s"]+)@[^\n]*:\n(?:[^\n]*\n)*?\s+version:? "?([^"\n]+)"?/gm;
  for (const m of text.matchAll(re)) {
    if (m[1] && m[2]) out.push({ name: m[1], version: m[2], dev: false });
  }
  return out;
}

/** Parse dependencies from whichever lockfile is present (package-lock preferred). */
export async function parseDependencies(files: SourceFile[], root: string): Promise<Dependency[]> {
  const lock = files.find((f) => f.path === "package-lock.json");
  if (lock) return dedupe(fromPackageLock(lock.text));

  const pnpm = await readFile(join(root, "pnpm-lock.yaml"), "utf8").catch(() => null);
  if (pnpm) return dedupe(fromPnpmLock(pnpm));

  const yarn = await readFile(join(root, "yarn.lock"), "utf8").catch(() => null);
  if (yarn) return dedupe(fromYarnLock(yarn));

  return [];
}

function dedupe(deps: Dependency[]): Dependency[] {
  const seen = new Set<string>();
  const out: Dependency[] = [];
  for (const d of deps) {
    const key = `${d.name}@${d.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(d);
  }
  return out;
}
