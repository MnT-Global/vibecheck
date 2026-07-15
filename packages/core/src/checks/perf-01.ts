import { truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext } from "../types.js";
import { calleeName, enclosingFunction } from "./ast.js";
import { isTestOrExampleFile, lineAt, looksServerSide } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#perf-01";

/** Blocking, synchronous I/O calls that serialize the event loop on a hot path. */
const SYNC_IO: ReadonlySet<string> = new Set([
  "readFileSync",
  "writeFileSync",
  "appendFileSync",
  "readdirSync",
  "statSync",
  "lstatSync",
  "mkdirSync",
  "rmSync",
  "unlinkSync",
  "readlinkSync",
  "copyFileSync",
  "execSync",
  "spawnSync",
  "execFileSync",
]);

export const perf01: Check = {
  id: "PERF-01",
  category: "perf",
  severity: "high",
  confidence: "high",
  tier: "structural",
  title: "Synchronous I/O inside a request handler",

  // Only relevant if the file runs a server; a build script's sync I/O is fine.
  appliesTo: (ctx) => ctx.files.some((f) => f.tree && looksServerSide(f.text)),

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path) || !looksServerSide(file.text)) continue;
      walk(file.tree.rootNode, (node) => {
        if (node.type !== "call_expression") return;
        const name = calleeName(node);
        if (!SYNC_IO.has(name)) return;
        // Module-scope sync I/O (boot-time config load) is fine; only flag inside a function.
        if (enclosingFunction(node) === null) return;
        findings.push({
          id: "PERF-01",
          category: "perf",
          severity: "high",
          confidence: "high",
          title: `Synchronous ${name}() on the request path`,
          file: file.path,
          line: node.startPosition.row + 1,
          column: node.startPosition.column,
          evidence: truncate(lineAt(file.text, node.startPosition.row)),
          fix: "Use the async API, or load once at boot into memory and serve from there.",
          docsUrl: DOCS,
        });
      });
    }
    return findings;
  },
};
