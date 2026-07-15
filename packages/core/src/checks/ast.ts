import { stringLiteralValue } from "../loader/redact.js";
import type { SyntaxNode } from "../types.js";

const FUNCTION_TYPES: ReadonlySet<string> = new Set([
  "function_declaration",
  "function_expression",
  "arrow_function",
  "method_definition",
  "generator_function",
  "generator_function_declaration",
]);

/** Nearest ancestor function, or null if the node is at module top level. */
export function enclosingFunction(node: SyntaxNode): SyntaxNode | null {
  let cur = node.parent;
  while (cur) {
    if (FUNCTION_TYPES.has(cur.type)) return cur;
    cur = cur.parent;
  }
  return null;
}

/** Nearest ancestor of any of the given types. */
export function ancestorOfType(node: SyntaxNode, types: ReadonlySet<string>): SyntaxNode | null {
  let cur = node.parent;
  while (cur) {
    if (types.has(cur.type)) return cur;
    cur = cur.parent;
  }
  return null;
}

/** True for a plain string literal or a template string with NO `${}` substitution. */
export function isConstantString(node: SyntaxNode): boolean {
  if (node.type === "string") return true;
  if (node.type === "template_string") {
    for (let i = 0; i < node.namedChildCount; i++) {
      if (node.namedChild(i)?.type === "template_substitution") return false;
    }
    return true;
  }
  return false;
}

/** The callee "name" of a call/new expression: `foo` or the `.bar` of `x.bar(...)`. */
export function calleeName(callOrNew: SyntaxNode): string {
  const fn = callOrNew.childForFieldName("function") ?? callOrNew.childForFieldName("constructor");
  if (!fn) return "";
  if (fn.type === "identifier") return fn.text;
  if (fn.type === "member_expression") {
    return fn.childForFieldName("property")?.text ?? "";
  }
  return "";
}

/** True if node is `<objName>.<propName>` (a member access we care about). */
export function isMemberAccess(node: SyntaxNode, objName: string, propName: string): boolean {
  if (node.type !== "member_expression") return false;
  const obj = node.childForFieldName("object");
  const prop = node.childForFieldName("property");
  return obj?.type === "identifier" && obj.text === objName && prop?.text === propName;
}

/** Nearest enclosing call/new expression, or null. */
export function nearestCall(node: SyntaxNode): SyntaxNode | null {
  return ancestorOfType(node, new Set(["call_expression", "new_expression"]));
}

/** The value node of an object literal's `<keyName>: value` pair, or null. */
export function objectPropValue(obj: SyntaxNode, keyName: string): SyntaxNode | null {
  if (obj.type !== "object") return null;
  for (let i = 0; i < obj.namedChildCount; i++) {
    const pair = obj.namedChild(i);
    if (pair?.type !== "pair") continue;
    const key = pair.childForFieldName("key");
    if (!key) continue;
    const keyText = key.type === "string" ? stringLiteralValue(key) : key.text;
    if (keyText === keyName) return pair.childForFieldName("value");
  }
  return null;
}

/** Find the first descendant object-pair value whose key matches (handles nested objects). */
export function findPropValueDeep(root: SyntaxNode, keyName: string): SyntaxNode | null {
  const stack: SyntaxNode[] = [root];
  while (stack.length) {
    const node = stack.pop();
    if (!node) continue;
    if (node.type === "pair") {
      const key = node.childForFieldName("key");
      const keyText = key ? (key.type === "string" ? stringLiteralValue(key) : key.text) : "";
      if (keyText === keyName) return node.childForFieldName("value");
    }
    for (let i = 0; i < node.namedChildCount; i++) {
      const c = node.namedChild(i);
      if (c) stack.push(c);
    }
  }
  return null;
}
