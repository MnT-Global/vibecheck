import { truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext, SyntaxNode } from "../types.js";
import { isTestOrExampleFile, lineAt } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#prod-04";

const LOG_METHODS = new Set(["log", "info", "warn", "error", "debug", "trace"]);
const LOGGER_RECEIVER = /^(?:console|logger|log|winston|pino)$/i;
const SECRET_NAME =
  /(?:secret|token|password|passwd|api[-_]?key|apikey|credential|private[-_]?key)/i;

/** Is this a console/logger call? */
function isLogCall(call: SyntaxNode): boolean {
  const fn = call.childForFieldName("function");
  if (fn?.type !== "member_expression") return false;
  const method = fn.childForFieldName("property")?.text ?? "";
  if (!LOG_METHODS.has(method)) return false;
  return LOGGER_RECEIVER.test(fn.childForFieldName("object")?.text ?? "");
}

/** Does the argument subtree reference a secret-named identifier / env var? */
function referencesSecret(node: SyntaxNode): boolean {
  let hit = false;
  walk(node, (n) => {
    if (hit) return false;
    if (n.type === "identifier" && SECRET_NAME.test(n.text)) hit = true;
    if (
      n.type === "member_expression" &&
      SECRET_NAME.test(n.childForFieldName("property")?.text ?? "")
    ) {
      hit = true;
    }
  });
  return hit;
}

export const prod04: Check = {
  id: "PROD-04",
  category: "prod",
  severity: "low",
  confidence: "medium",
  tier: "flow",
  title: "Secret written to logs",

  appliesTo: () => true,

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path)) continue;
      walk(file.tree.rootNode, (node) => {
        if (node.type !== "call_expression" || !isLogCall(node)) return;
        const args = node.childForFieldName("arguments");
        if (!args || !referencesSecret(args)) return;
        findings.push({
          id: "PROD-04",
          category: "prod",
          severity: "low",
          confidence: "medium",
          title: "Secret value written to logs",
          file: file.path,
          line: node.startPosition.row + 1,
          column: node.startPosition.column,
          evidence: truncate(lineAt(file.text, node.startPosition.row)),
          fix: "Never log secrets; redact sensitive fields before logging.",
          docsUrl: DOCS,
        });
      });
    }
    return findings;
  },
};
