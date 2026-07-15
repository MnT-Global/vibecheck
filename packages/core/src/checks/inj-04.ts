import { truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext, SyntaxNode } from "../types.js";
import { calleeName, referencesRequestInput } from "./ast.js";
import { isTestOrExampleFile, lineAt } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#inj-04";

/** Recursive-merge sinks that pollute a prototype when fed request input. */
const MERGE_SINKS: ReadonlySet<string> = new Set([
  "merge",
  "mergewith",
  "assign",
  "extend",
  "defaultsdeep",
]);

function flagAt(file: string, node: SyntaxNode, text: string, title: string, findings: Finding[]) {
  findings.push({
    id: "INJ-04",
    category: "injection",
    severity: "medium",
    confidence: "medium",
    title,
    file,
    line: node.startPosition.row + 1,
    column: node.startPosition.column,
    evidence: truncate(lineAt(text, node.startPosition.row)),
    fix: "Guard against __proto__/constructor keys; use Object.create(null) or a Map for user-keyed data.",
    docsUrl: DOCS,
  });
}

export const inj04: Check = {
  id: "INJ-04",
  category: "injection",
  severity: "medium",
  confidence: "medium",
  tier: "flow",
  title: "Prototype pollution via user-controlled key/merge",

  appliesTo: () => true,

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path)) continue;
      walk(file.tree.rootNode, (node) => {
        // obj[<request key>] = ...  → attacker-controlled property name
        if (node.type === "assignment_expression") {
          const left = node.childForFieldName("left");
          const index =
            left?.type === "subscript_expression" ? left.childForFieldName("index") : null;
          if (index && referencesRequestInput(index)) {
            flagAt(
              file.path,
              node,
              file.text,
              "Object property written with a user-controlled key",
              findings,
            );
          }
          return;
        }
        // merge/assign(target, <request input>) → deep-merge pollution
        if (node.type === "call_expression" && MERGE_SINKS.has(calleeName(node).toLowerCase())) {
          const args = node.childForFieldName("arguments");
          for (let i = 0; i < (args?.namedChildCount ?? 0); i++) {
            const a = args?.namedChild(i);
            if (a && referencesRequestInput(a)) {
              flagAt(
                file.path,
                node,
                file.text,
                "Request input merged into an object (prototype pollution)",
                findings,
              );
              break;
            }
          }
        }
      });
    }
    return findings;
  },
};
