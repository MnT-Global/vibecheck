import { truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext, SyntaxNode } from "../types.js";
import { calleeName, isConstantString } from "./ast.js";
import { isTestOrExampleFile, lineAt } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#inj-01";

/** Timers that execute a *string* first argument as code, exactly like eval. */
const CODE_STRING_TIMERS: ReadonlySet<string> = new Set(["setTimeout", "setInterval"]);

/** Is the argument a *built* code string — a template with interpolation, or a concatenation? */
function isBuiltCodeString(arg: SyntaxNode): boolean {
  if (arg.type === "template_string") return arg.namedChildCount > 0 && !isConstantString(arg);
  if (arg.type === "binary_expression")
    return (arg.childForFieldName("operator")?.text ?? "") === "+";
  return false;
}

/** Does any argument evade the constant-string check → dynamic code built from input? */
function hasNonConstantArg(node: SyntaxNode): boolean {
  const args = node.childForFieldName("arguments");
  for (let i = 0; i < (args?.namedChildCount ?? 0); i++) {
    const a = args?.namedChild(i);
    if (a && !isConstantString(a)) return true;
  }
  return false;
}

/** eval / Function(...) / new Function(...) / setTimeout("code"+x) built from input → RCE risk. */
function dynamicExecTitle(node: SyntaxNode): string | null {
  if (node.type === "call_expression") {
    const callee = calleeName(node);
    if (callee === "eval") {
      const arg = node.childForFieldName("arguments")?.namedChild(0);
      return arg && !isConstantString(arg) ? "eval() of a non-constant value" : null;
    }
    // Function("return " + x)(…) is the same RCE as `new Function`, just without `new`.
    if (callee === "Function") {
      return hasNonConstantArg(node)
        ? "Code built with Function() from a non-constant value"
        : null;
    }
    if (CODE_STRING_TIMERS.has(callee)) {
      const first = node.childForFieldName("arguments")?.namedChild(0);
      return first && isBuiltCodeString(first)
        ? `${callee}() called with a built string of code (evaluated like eval)`
        : null;
    }
    return null;
  }
  if (node.type === "new_expression" && calleeName(node) === "Function") {
    return hasNonConstantArg(node)
      ? "Code built with new Function() from a non-constant value"
      : null;
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
