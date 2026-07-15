import { truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext, SyntaxNode } from "../types.js";
import { referencesRequestInput } from "./ast.js";
import { isTestOrExampleFile, lineAt } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#web-02";

const HTTP_METHODS = new Set(["get", "post", "put", "patch", "request", "head"]);
const HTTP_RECEIVER = /^(?:axios|https?|got|superagent|needle)$/i;

/** Is this an outbound HTTP call (fetch/axios/got/http.request/…)? */
function isOutboundHttp(call: SyntaxNode): boolean {
  const fn = call.childForFieldName("function");
  if (!fn) return false;
  if (fn.type === "identifier") return /^(?:fetch|got|axios|ky)$/i.test(fn.text);
  if (fn.type === "member_expression") {
    const prop = fn.childForFieldName("property")?.text?.toLowerCase() ?? "";
    if (!HTTP_METHODS.has(prop)) return false;
    return HTTP_RECEIVER.test(fn.childForFieldName("object")?.text ?? "");
  }
  return false;
}

export const web02: Check = {
  id: "WEB-02",
  category: "web",
  severity: "high",
  confidence: "medium",
  tier: "flow",
  title: "Server-side request forgery (SSRF)",

  appliesTo: () => true,

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path)) continue;
      walk(file.tree.rootNode, (node) => {
        if (node.type !== "call_expression" || !isOutboundHttp(node)) return;
        const url = node.childForFieldName("arguments")?.namedChild(0);
        if (!url || !referencesRequestInput(url)) return;
        findings.push({
          id: "WEB-02",
          category: "web",
          severity: "high",
          confidence: "medium",
          title: "Server fetches a user-supplied URL (SSRF)",
          file: file.path,
          line: node.startPosition.row + 1,
          column: node.startPosition.column,
          evidence: truncate(lineAt(file.text, node.startPosition.row)),
          fix: "Allowlist permitted hosts; resolve and validate the target IP; block internal ranges.",
          docsUrl: DOCS,
        });
      });
    }
    return findings;
  },
};
