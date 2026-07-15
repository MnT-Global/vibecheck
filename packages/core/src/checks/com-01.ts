import { truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext, SyntaxNode } from "../types.js";
import { referencesRequestInput } from "./ast.js";
import { isTestOrExampleFile, lineAt } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#com-01";

const PRICE_FIELDS = new Set(["price", "amount", "total", "unitprice", "cost", "subtotal"]);
const ARITHMETIC = new Set(["*", "+", "-"]);
const AMOUNT_KEYS = new Set(["amount", "price", "total", "subtotal", "unit_amount"]);
const COMMERCE_CONTEXT =
  /checkout|\bcart\b|\border\b|\bprice\b|\btotal\b|payment|charge|stripe|invoice/i;

/** `body.price` / `req.body.amount` — a price field read from request input. */
function isRequestPrice(node: SyntaxNode): boolean {
  if (node.type !== "member_expression") return false;
  const prop = node.childForFieldName("property")?.text?.toLowerCase() ?? "";
  return PRICE_FIELDS.has(prop) && referencesRequestInput(node);
}

export const com01: Check = {
  id: "COM-01",
  category: "commerce",
  severity: "high",
  confidence: "medium",
  tier: "flow",
  title: "Order price/total trusted from the client",

  appliesTo: (ctx) => ctx.files.some((f) => f.tree && COMMERCE_CONTEXT.test(f.text)),

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    const flag = (file: string, node: SyntaxNode, text: string) => {
      const line = node.startPosition.row + 1;
      const key = `${file}:${line}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push({
        id: "COM-01",
        category: "commerce",
        severity: "high",
        confidence: "medium",
        title: "Price/total computed from a client-supplied value",
        file,
        line,
        column: node.startPosition.column,
        evidence: truncate(lineAt(text, node.startPosition.row)),
        fix: "Look the price up from the server-side product record; never trust a client-sent amount.",
        docsUrl: DOCS,
      });
    };

    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path) || !COMMERCE_CONTEXT.test(file.text))
        continue;
      walk(file.tree.rootNode, (node) => {
        // client price used in arithmetic (price * qty, total + amount, ...)
        if (node.type === "binary_expression") {
          const op = node.childForFieldName("operator")?.text ?? "";
          if (!ARITHMETIC.has(op)) return;
          const l = node.childForFieldName("left");
          const r = node.childForFieldName("right");
          if ((l && isRequestPrice(l)) || (r && isRequestPrice(r)))
            flag(file.path, node, file.text);
          return;
        }
        // client price as an `amount`/`total` field passed to a charge/order
        if (node.type === "pair") {
          const key = node.childForFieldName("key")?.text?.replace(/["']/g, "").toLowerCase() ?? "";
          const value = node.childForFieldName("value");
          if (AMOUNT_KEYS.has(key) && value && isRequestPrice(value))
            flag(file.path, node, file.text);
        }
      });
    }
    return findings;
  },
};
