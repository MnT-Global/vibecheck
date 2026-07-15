import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Advisory, AdvisoryMap, Dependency, Severity } from "../types.js";

const OSV_BATCH = "https://api.osv.dev/v1/querybatch";
const OSV_VULN = "https://api.osv.dev/v1/vulns/";
const TIMEOUT_MS = 12_000;
const CHUNK = 500;

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  database_specific?: { severity?: string };
  affected?: Array<{ ranges?: Array<{ events?: Array<{ fixed?: string }> }> }>;
}
interface OsvBatchResponse {
  results?: Array<{ vulns?: Array<{ id: string }> }>;
}

function severityFrom(vuln: OsvVuln): Severity {
  switch (String(vuln.database_specific?.severity ?? "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MODERATE":
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "medium";
  }
}

function firstFixed(vuln: OsvVuln): string | undefined {
  for (const aff of vuln.affected ?? []) {
    for (const range of aff.ranges ?? []) {
      for (const ev of range.events ?? []) if (ev.fixed) return ev.fixed;
    }
  }
  return undefined;
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T | null> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...init, signal: ac.signal });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Load a vuln's detail (severity/summary/fixed), from the on-disk cache or OSV. */
async function loadVuln(id: string, cacheDir: string): Promise<Advisory | null> {
  const cacheFile = join(cacheDir, `${id}.json`);
  let vuln = await readFile(cacheFile, "utf8")
    .then((t) => JSON.parse(t) as OsvVuln)
    .catch(() => null);
  if (!vuln) {
    vuln = await fetchJson<OsvVuln>(OSV_VULN + id);
    if (!vuln) return null;
    await mkdir(cacheDir, { recursive: true }).catch(() => {});
    await writeFile(cacheFile, JSON.stringify(vuln)).catch(() => {});
  }
  return {
    id,
    severity: severityFrom(vuln),
    summary: vuln.summary ?? vuln.details?.slice(0, 120) ?? id,
    fixed: firstFixed(vuln),
  };
}

export function defaultCacheDir(): string {
  return join(homedir(), ".cache", "vibecheck", "osv");
}

/**
 * Look up known vulnerabilities for the given npm dependencies via OSV.
 * Returns a name@version → advisories map, or `null` if OSV is unreachable (offline).
 * Vuln details are cached on disk so repeat runs work offline for seen advisories.
 */
export async function fetchOsvAdvisories(
  deps: Dependency[],
  cacheDir: string = defaultCacheDir(),
): Promise<AdvisoryMap | null> {
  if (deps.length === 0) return new Map();
  const map: AdvisoryMap = new Map();

  for (let i = 0; i < deps.length; i += CHUNK) {
    const chunk = deps.slice(i, i + CHUNK);
    const body = JSON.stringify({
      queries: chunk.map((d) => ({
        package: { name: d.name, ecosystem: "npm" },
        version: d.version,
      })),
    });
    const res = await fetchJson<OsvBatchResponse>(OSV_BATCH, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    if (!res) return null; // offline / error — signal failure to the caller

    const results = res.results ?? [];
    for (let j = 0; j < chunk.length; j++) {
      const vulns = results[j]?.vulns;
      const dep = chunk[j];
      if (!vulns?.length || !dep) continue;
      const advisories: Advisory[] = [];
      for (const v of vulns) {
        const adv = await loadVuln(v.id, cacheDir);
        if (adv) advisories.push(adv);
      }
      if (advisories.length) map.set(`${dep.name}@${dep.version}`, advisories);
    }
  }
  return map;
}
