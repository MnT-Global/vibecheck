import { truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext, SyntaxNode } from "../types.js";
import { isConstantString } from "./ast.js";
import { isTestOrExampleFile, lineAt } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#inj-03";

/** Shell-executing child_process functions. `exec`/`execSync` spawn a shell. */
const SHELL_FNS: ReadonlySet<string> = new Set(["exec", "execSync"]);
const CHILD_PROCESS_RECEIVER = /child_?process|(^|\.)cp$/i;

/**
 * Return the shell-exec fn name if this call is child_process exec/execSync, else null.
 * Crucially distinguishes `cp.exec(x)` from the very common `regex.exec(x)` (RegExp has no
 * execSync, and RegExp.exec is always called on a regex object — never bare).
 */
function shellExecName(call: SyntaxNode): string | null {
  const fn = call.childForFieldName("function");
  if (!fn) return null;
  if (fn.type === "identifier" && SHELL_FNS.has(fn.text)) return fn.text; // bare, destructured
  if (fn.type === "member_expression") {
    const prop = fn.childForFieldName("property")?.text ?? "";
    if (!SHELL_FNS.has(prop)) return null;
    if (prop === "execSync") return prop; // no RegExp.execSync — unambiguous
    return CHILD_PROCESS_RECEIVER.test(fn.childForFieldName("object")?.text ?? "") ? prop : null;
  }
  return null;
}

export const inj03: Check = {
  id: "INJ-03",
  category: "injection",
  severity: "high",
  confidence: "high",
  tier: "structural",
  title: "Command injection via child_process",

  // Only where child_process is actually used.
  appliesTo: (ctx) => ctx.files.some((f) => f.tree && /child_process/.test(f.text)),

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path) || !/child_process/.test(file.text))
        continue;
      walk(file.tree.rootNode, (node) => {
        if (node.type !== "call_expression") return;
        const name = shellExecName(node);
        if (!name) return;
        const arg = node.childForFieldName("arguments")?.namedChild(0);
        if (!arg || isConstantString(arg)) return; // constant command is fine
        findings.push({
          id: "INJ-03",
          category: "injection",
          severity: "high",
          confidence: "high",
          title: `Shell command built from a non-constant value (${name})`,
          file: file.path,
          line: node.startPosition.row + 1,
          column: node.startPosition.column,
          evidence: truncate(lineAt(file.text, node.startPosition.row)),
          fix: "Use execFile/spawn with an args array and no shell; validate and allowlist inputs.",
          docsUrl: DOCS,
        });
      });
    }
    return findings;
  },
};
