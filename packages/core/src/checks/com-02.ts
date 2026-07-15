import { truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext, SyntaxNode } from "../types.js";
import { calleeName, enclosingFunction } from "./ast.js";
import { isTestOrExampleFile, lineAt } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#com-02";

const QTY_FIELDS: ReadonlySet<string> = new Set(["qty", "quantity", "amount", "count", "units"]);
/** Identifiers that plausibly hold parsed request input. */
const REQUEST_OBJECTS: ReadonlySet<string> = new Set([
  "body",
  "payload",
  "input",
  "reqbody",
  "requestbody",
]);
const ARITHMETIC = new Set(["*", "+", "-"]);
const COMPARISON = new Set(["<", "<=", ">", ">="]);
const COMMERCE_CONTEXT =
  /checkout|\bcart\b|\border\b|\bprice\b|\btotal\b|payment|\bpay\b|charge|invoice/i;

/** Is `node` a `body.qty` / `req.body.qty`-style read of a quantity field from request input? */
function isRequestQty(node: SyntaxNode): boolean {
  if (node.type !== "member_expression") return false;
  const prop = node.childForFieldName("property");
  if (!prop || !QTY_FIELDS.has(prop.text)) return false;
  const obj = node.childForFieldName("object");
  if (!obj) return false;
  if (obj.type === "identifier") return REQUEST_OBJECTS.has(obj.text.toLowerCase());
  if (obj.type === "member_expression") return obj.childForFieldName("property")?.text === "body";
  return false;
}

/** If this access is the value of `const x = <access>` (optionally wrapped in Number()/parseInt()). */
function aliasOf(access: SyntaxNode): string | null {
  const parent = access.parent;
  if (!parent) return null;
  // NB: web-tree-sitter returns a fresh wrapper per access, so compare by position, not identity.
  if (
    parent.type === "variable_declarator" &&
    parent.childForFieldName("value")?.startIndex === access.startIndex
  ) {
    const name = parent.childForFieldName("name");
    return name?.type === "identifier" ? name.text : null;
  }
  if (parent.type === "arguments") {
    const call = parent.parent;
    const decl = call?.parent;
    if (call?.type === "call_expression" && decl?.type === "variable_declarator") {
      const name = decl.childForFieldName("name");
      return name?.type === "identifier" ? name.text : null;
    }
  }
  return null;
}

function isAliasIdentifier(node: SyntaxNode, alias: string | null): boolean {
  return alias !== null && node.type === "identifier" && node.text === alias;
}

/** Does the scope validate the quantity? (Number.isInteger, a range comparison, or a schema parse.) */
function hasValidation(scope: SyntaxNode, alias: string | null): boolean {
  let validated = false;
  walk(scope, (node) => {
    if (validated) return false;
    if (node.type === "call_expression") {
      const name = calleeName(node).toLowerCase();
      // Number.isInteger / Number.isFinite, or a zod-style schema `.safeParse` — NOT JSON.parse.
      if (name === "isinteger" || name === "isfinite" || name === "safeparse") {
        validated = true;
        return false;
      }
    }
    if (node.type === "binary_expression") {
      const op = node.childForFieldName("operator")?.text ?? "";
      if (COMPARISON.has(op)) {
        const l = node.childForFieldName("left");
        const r = node.childForFieldName("right");
        if ((l && isAliasIdentifier(l, alias)) || (r && isAliasIdentifier(r, alias))) {
          validated = true;
          return false;
        }
      }
    }
  });
  return validated;
}

/** Is the quantity used in arithmetic (price * qty, total + amount, ...) within the scope? */
function usedInArithmetic(scope: SyntaxNode, alias: string | null): SyntaxNode | null {
  let hit: SyntaxNode | null = null;
  walk(scope, (node) => {
    if (hit) return false;
    if (node.type !== "binary_expression") return;
    const op = node.childForFieldName("operator")?.text ?? "";
    if (!ARITHMETIC.has(op)) return;
    const l = node.childForFieldName("left");
    const r = node.childForFieldName("right");
    for (const side of [l, r]) {
      if (side && (isAliasIdentifier(side, alias) || isRequestQty(side))) {
        hit = node;
        return false;
      }
    }
  });
  return hit;
}

export const com02: Check = {
  id: "COM-02",
  category: "commerce",
  severity: "high",
  confidence: "high",
  tier: "structural",
  title: "Order quantity/amount used without validation (price-tampering risk)",

  appliesTo: (ctx) => ctx.files.some((f) => f.tree && COMMERCE_CONTEXT.test(f.text)),

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path) || !COMMERCE_CONTEXT.test(file.text))
        continue;
      const tree = file.tree;

      walk(tree.rootNode, (node) => {
        if (!isRequestQty(node)) return;
        const scope = enclosingFunction(node) ?? tree.rootNode;
        const alias = aliasOf(node);
        if (hasValidation(scope, alias)) return;
        const arith = usedInArithmetic(scope, alias);
        if (!arith) return;

        const line = arith.startPosition.row + 1;
        const key = `${file.path}:${line}`;
        if (seen.has(key)) return;
        seen.add(key);

        findings.push({
          id: "COM-02",
          category: "commerce",
          severity: "high",
          confidence: "high",
          title: "Order quantity/amount used in pricing without validation",
          file: file.path,
          line,
          column: arith.startPosition.column,
          evidence: truncate(lineAt(file.text, arith.startPosition.row)),
          fix: "Validate as an integer in a sane range (e.g. Number.isInteger(qty) && qty >= 1 && qty <= 99) before use.",
          docsUrl: DOCS,
        });
      });
    }
    return findings;
  },
};
