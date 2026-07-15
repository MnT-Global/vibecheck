import { truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext } from "../types.js";
import { ancestorOfType, calleeName } from "./ast.js";
import { isTestOrExampleFile, lineAt } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#perf-03";

/** DB-ish read methods (awaited → not Array.prototype.find etc.). */
const DB_METHODS: ReadonlySet<string> = new Set([
  "find",
  "findone",
  "findmany",
  "findfirst",
  "findunique",
  "findbyid",
  "query",
  "aggregate",
  "select",
]);
const LOOP_TYPES: ReadonlySet<string> = new Set([
  "for_statement",
  "for_in_statement",
  "while_statement",
  "do_statement",
]);

export const perf03: Check = {
  id: "PERF-03",
  category: "perf",
  severity: "low",
  confidence: "medium",
  tier: "flow",
  title: "Database query inside a loop (N+1)",

  appliesTo: () => true,

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path)) continue;
      walk(file.tree.rootNode, (node) => {
        if (node.type !== "call_expression") return;
        if (!DB_METHODS.has(calleeName(node).toLowerCase())) return;
        // await gates out Array.prototype.find/map (sync) — DB reads are async.
        if (node.parent?.type !== "await_expression") return;
        if (!ancestorOfType(node, LOOP_TYPES)) return;
        findings.push({
          id: "PERF-03",
          category: "perf",
          severity: "low",
          confidence: "medium",
          title: "Awaited database query inside a loop (N+1)",
          file: file.path,
          line: node.startPosition.row + 1,
          column: node.startPosition.column,
          evidence: truncate(lineAt(file.text, node.startPosition.row)),
          fix: "Batch the query (one IN/join query outside the loop) instead of one per iteration.",
          docsUrl: DOCS,
        });
      });
    }
    return findings;
  },
};
