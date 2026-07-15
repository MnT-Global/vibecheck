import { truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext, SyntaxNode } from "../types.js";
import { calleeName, isConstantString } from "./ast.js";
import { isTestOrExampleFile, lineAt } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#inj-02";

/** Query sinks that execute raw SQL. */
const QUERY_SINKS: ReadonlySet<string> = new Set([
  "query",
  "raw",
  "execute",
  "$queryRawUnsafe",
  "$executeRawUnsafe",
  "unsafe",
]);

/** True if the argument is dynamically built (template with `${}` or string concatenation). */
function isDynamicString(node: SyntaxNode): boolean {
  if (node.type === "template_string") return !isConstantString(node);
  if (node.type === "binary_expression") {
    const op = node.childForFieldName("operator")?.text ?? "";
    if (op !== "+") return false;
    const l = node.childForFieldName("left");
    const r = node.childForFieldName("right");
    return (!!l && !isConstantString(l)) || (!!r && !isConstantString(r));
  }
  return false;
}

export const inj02: Check = {
  id: "INJ-02",
  category: "injection",
  severity: "critical",
  confidence: "medium",
  tier: "flow",
  title: "SQL/NoSQL injection via a string-built query",

  appliesTo: () => true,

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path)) continue;
      walk(file.tree.rootNode, (node) => {
        if (node.type !== "call_expression") return;
        if (!QUERY_SINKS.has(calleeName(node))) return;
        const arg = node.childForFieldName("arguments")?.namedChild(0);
        if (!arg || !isDynamicString(arg)) return;
        findings.push({
          id: "INJ-02",
          category: "injection",
          severity: "critical",
          confidence: "medium",
          title: "Query built by string interpolation/concatenation",
          file: file.path,
          line: node.startPosition.row + 1,
          column: node.startPosition.column,
          evidence: truncate(lineAt(file.text, node.startPosition.row)),
          fix: "Use parameterized queries / prepared statements; never interpolate input into SQL.",
          docsUrl: DOCS,
        });
      });
    }
    return findings;
  },
};
