import { truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext, SyntaxNode } from "../types.js";
import { calleeName, findPropValueDeep, isConstantString } from "./ast.js";
import { isTestOrExampleFile, lineAt } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#web-01";

const HTML_SINKS: ReadonlySet<string> = new Set(["innerHTML", "outerHTML"]);
const SANITIZERS: ReadonlySet<string> = new Set([
  "sanitize",
  "sanitizehtml",
  "purify",
  "escape",
  "escapehtml",
  "clean",
]);

/** A value is "safe enough" if it's a constant string or wrapped in a sanitizer call. */
function isSafeHtml(value: SyntaxNode): boolean {
  if (isConstantString(value)) return true;
  if (value.type === "call_expression") return SANITIZERS.has(calleeName(value).toLowerCase());
  return false;
}

export const web01: Check = {
  id: "WEB-01",
  category: "web",
  severity: "high",
  confidence: "high",
  tier: "structural",
  title: "Unsanitized HTML injection sink (XSS)",

  appliesTo: (ctx) => ctx.files.some((f) => f.lang === "jsx" || f.lang === "tsx" || !!f.tree),

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    const push = (file: string, node: SyntaxNode, text: string, detail: string) => {
      const line = node.startPosition.row + 1;
      const key = `${file}:${line}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push({
        id: "WEB-01",
        category: "web",
        severity: "high",
        confidence: "high",
        title: detail,
        file,
        line,
        column: node.startPosition.column,
        evidence: truncate(lineAt(text, node.startPosition.row)),
        fix: "Sanitize with DOMPurify before rendering, or avoid dangerouslySetInnerHTML/innerHTML.",
        docsUrl: DOCS,
      });
    };

    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path)) continue;
      walk(file.tree.rootNode, (node) => {
        // React: dangerouslySetInnerHTML={{ __html: <non-constant> }}
        if (node.type === "jsx_attribute") {
          const name = node.namedChild(0);
          if (name?.text !== "dangerouslySetInnerHTML") return;
          const html = findPropValueDeep(node, "__html");
          if (html && !isSafeHtml(html)) {
            push(file.path, node, file.text, "Unsanitized value in dangerouslySetInnerHTML");
          }
          return;
        }
        // DOM: el.innerHTML = <non-constant>
        if (node.type === "assignment_expression") {
          const left = node.childForFieldName("left");
          const right = node.childForFieldName("right");
          if (
            left?.type === "member_expression" &&
            HTML_SINKS.has(left.childForFieldName("property")?.text ?? "") &&
            right &&
            !isSafeHtml(right)
          ) {
            push(file.path, node, file.text, "Unsanitized assignment to innerHTML/outerHTML");
          }
        }
      });
    }
    return findings;
  },
};
