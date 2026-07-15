import { truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext, SyntaxNode } from "../types.js";
import { calleeName, isConstantString } from "./ast.js";
import { isTestOrExampleFile, lineAt } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#inj-01";

/** eval(x) or new Function(...) where an argument is not a constant string → RCE risk. */
function dynamicExecTitle(node: SyntaxNode): string | null {
  if (node.type === "call_expression" && calleeName(node) === "eval") {
    const arg = node.childForFieldName("arguments")?.namedChild(0);
    return arg && !isConstantString(arg) ? "eval() of a non-constant value" : null;
  }
  if (node.type === "new_expression" && calleeName(node) === "Function") {
    const args = node.childForFieldName("arguments");
    if (!args) return null;
    for (let i = 0; i < args.namedChildCount; i++) {
      const a = args.namedChild(i);
      if (a && !isConstantString(a))
        return "Code built with new Function() from a non-constant value";
    }
  }
  return null;
}

export const inj01: Check = {
  id: "INJ-01",
  category: "injection",
  severity: "critical",
  confidence: "high",
  tier: "structural",
  title: "Dynamic code execution from a non-constant value",

  appliesTo: () => true,

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path)) continue;
      walk(file.tree.rootNode, (node) => {
        const title = dynamicExecTitle(node);
        if (!title) return;
        findings.push({
          id: "INJ-01",
          category: "injection",
          severity: "critical",
          confidence: "high",
          title,
          file: file.path,
          line: node.startPosition.row + 1,
          column: node.startPosition.column,
          evidence: truncate(lineAt(file.text, node.startPosition.row)),
          fix: "Never build code from input. Use a lookup table, a safe parser, or explicit logic.",
          docsUrl: DOCS,
        });
      });
    }
    return findings;
  },
};
