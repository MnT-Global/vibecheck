import { truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext, SyntaxNode } from "../types.js";
import { referencesRequestInput } from "./ast.js";
import { isTestOrExampleFile, lineAt } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#com-04";

const DISCOUNT_FIELDS = new Set([
  "discount",
  "coupon",
  "promo",
  "voucher",
  "percentoff",
  "couponcode",
  "discountamount",
  "discountpercent",
  "rebate",
]);
const ARITHMETIC = new Set(["*", "-", "/"]);
const COMMERCE_CONTEXT = /checkout|\bcart\b|\border\b|\bprice\b|\btotal\b|discount|coupon|payment/i;

function isRequestDiscount(node: SyntaxNode): boolean {
  if (node.type !== "member_expression") return false;
  const prop = node.childForFieldName("property")?.text?.replace(/_/g, "").toLowerCase() ?? "";
  return DISCOUNT_FIELDS.has(prop) && referencesRequestInput(node);
}

export const com04: Check = {
  id: "COM-04",
  category: "commerce",
  severity: "medium",
  confidence: "medium",
  tier: "flow",
  title: "Discount/coupon applied without server-side validation",

  appliesTo: (ctx) => ctx.files.some((f) => f.tree && COMMERCE_CONTEXT.test(f.text)),

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();
    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path) || !COMMERCE_CONTEXT.test(file.text))
        continue;
      walk(file.tree.rootNode, (node) => {
        if (node.type !== "binary_expression") return;
        const op = node.childForFieldName("operator")?.text ?? "";
        if (!ARITHMETIC.has(op)) return;
        const l = node.childForFieldName("left");
        const r = node.childForFieldName("right");
        if (!(l && isRequestDiscount(l)) && !(r && isRequestDiscount(r))) return;
        const line = node.startPosition.row + 1;
        const key = `${file.path}:${line}`;
        if (seen.has(key)) return;
        seen.add(key);
        findings.push({
          id: "COM-04",
          category: "commerce",
          severity: "medium",
          confidence: "medium",
          title: "Client-supplied discount applied to the total without validation",
          file: file.path,
          line,
          column: node.startPosition.column,
          evidence: truncate(lineAt(file.text, node.startPosition.row)),
          fix: "Validate the coupon code server-side and compute the discount from the trusted record.",
          docsUrl: DOCS,
        });
      });
    }
    return findings;
  },
};
