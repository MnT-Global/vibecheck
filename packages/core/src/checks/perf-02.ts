import { truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext, SyntaxNode } from "../types.js";
import { calleeName, enclosingFunction } from "./ast.js";
import { isTestOrExampleFile, lineAt, looksServerSide } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#perf-02";

const FILE_READS: ReadonlySet<string> = new Set(["readFileSync", "readFile"]);

/** Is `node` a `JSON.parse(...)` call? */
function isJsonParse(node: SyntaxNode): boolean {
  if (node.type !== "call_expression" || calleeName(node) !== "parse") return false;
  const fn = node.childForFieldName("function");
  return fn?.type === "member_expression" && fn.childForFieldName("object")?.text === "JSON";
}

/** Does the argument (transitively) come from a file read? */
function readsAFile(node: SyntaxNode | null): boolean {
  if (!node) return false;
  let found = false;
  walk(node, (n) => {
    if (n.type === "call_expression" && FILE_READS.has(calleeName(n))) found = true;
  });
  return found;
}

export const perf02: Check = {
  id: "PERF-02",
  category: "perf",
  severity: "medium",
  confidence: "medium",
  tier: "flow",
  title: "Entire data file read + parsed on every request",

  appliesTo: (ctx) => ctx.files.some((f) => f.tree && looksServerSide(f.text)),

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();
    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path) || !looksServerSide(file.text)) continue;
      walk(file.tree.rootNode, (node) => {
        if (!isJsonParse(node)) return;
        const arg = node.childForFieldName("arguments")?.namedChild(0);
        if (!readsAFile(arg ?? null)) return;
        // Boot-time parse (module scope) is fine; only a per-request (in-function) parse is the bug.
        const fn = enclosingFunction(node);
        if (!fn) return;
        const line = fn.startPosition.row + 1;
        const key = `${file.path}:${line}`;
        if (seen.has(key)) return;
        seen.add(key);
        findings.push({
          id: "PERF-02",
          category: "perf",
          severity: "medium",
          confidence: "medium",
          title: "Reads and JSON-parses a whole file inside a per-request function",
          file: file.path,
          line,
          column: fn.startPosition.column,
          evidence: truncate(lineAt(file.text, fn.startPosition.row)),
          fix: "Load the data once at boot into an in-memory index; don't re-read/parse it per request.",
          docsUrl: DOCS,
        });
      });
    }
    return findings;
  },
};
