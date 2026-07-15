import { stringLiteralValue, truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext, Severity, SyntaxNode } from "../types.js";
import { calleeName, objectPropValue } from "./ast.js";
import { isTestOrExampleFile, lineAt } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#auth-04";

/** origin: "*" or origin: true — both allow any site. */
function isPermissiveOrigin(value: SyntaxNode | null): boolean {
  if (!value) return false;
  if (value.type === "true") return true;
  if (value.type === "string") return stringLiteralValue(value) === "*";
  return false;
}

export const auth04: Check = {
  id: "AUTH-04",
  category: "auth",
  severity: "medium",
  confidence: "high",
  tier: "structural",
  title: "Permissive CORS configuration",

  appliesTo: () => true,

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    const push = (
      file: string,
      node: SyntaxNode,
      text: string,
      severity: Severity,
      detail: string,
    ) => {
      const line = node.startPosition.row + 1;
      const key = `${file}:${line}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push({
        id: "AUTH-04",
        category: "auth",
        severity,
        confidence: "high",
        title: detail,
        file,
        line,
        column: node.startPosition.column,
        evidence: truncate(lineAt(text, node.startPosition.row)),
        fix: "Restrict CORS to an explicit origin allowlist; never combine a wildcard origin with credentials.",
        docsUrl: DOCS,
      });
    };

    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path)) continue;
      walk(file.tree.rootNode, (node) => {
        if (node.type !== "call_expression" || calleeName(node) !== "cors") return;
        const arg = node.childForFieldName("arguments")?.namedChild(0);
        if (arg?.type !== "object") return;
        if (!isPermissiveOrigin(objectPropValue(arg, "origin"))) return;
        const credentials = objectPropValue(arg, "credentials");
        const withCreds = credentials?.type === "true";
        push(
          file.path,
          node,
          file.text,
          withCreds ? "medium" : "low",
          withCreds
            ? "CORS allows any origin (*) together with credentials"
            : "CORS allows any origin (*)",
        );
      });
    }
    return findings;
  },
};
