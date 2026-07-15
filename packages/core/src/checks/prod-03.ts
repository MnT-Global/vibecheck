import { truncate } from "../loader/redact.js";
import { findNodes, walk } from "../parse/index.js";
import type { Check, Finding, ScanContext, SyntaxNode } from "../types.js";
import { ancestorOfType, calleeName, isMemberAccess, nearestCall } from "./ast.js";
import { isTestOrExampleFile, lineAt } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#prod-03";

/** Calls where surfacing an error message is fine (logging / error propagation). */
const SAFE_CALLEES: ReadonlySet<string> = new Set([
  "log",
  "error",
  "warn",
  "info",
  "debug",
  "trace",
  "assert",
  "captureexception",
  "next",
  "reject",
]);

const CATCH_NODE: ReadonlySet<string> = new Set(["catch_clause"]);

/** Is this `err.message`/`err.stack` being leaked (not logged / thrown)? */
function isLeaked(access: SyntaxNode): boolean {
  if (ancestorOfType(access, new Set(["throw_statement"]))) return false;
  const call = nearestCall(access);
  if (!call) return false; // only flag when it flows into a call (a sink)
  if (call.type === "new_expression") return false; // new Error(err.message) — re-wrapping
  return !SAFE_CALLEES.has(calleeName(call).toLowerCase());
}

export const prod03: Check = {
  id: "PROD-03",
  category: "prod",
  severity: "low",
  confidence: "high",
  tier: "structural",
  title: "Internal error detail returned to the client",

  appliesTo: () => true,

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const file of ctx.files) {
      // PROD-03 is about a SERVER leaking internal error detail in its HTTP response. In a
      // client-side file (a React component, etc.) `showErrorToast(err.message)` is ordinary UI,
      // not a leak — and the "log server-side, return a correlation id" fix can't even apply
      // there. Skip client files so a frontend's error toasts don't produce a wall of false lows.
      if (!file.tree || file.isClient || isTestOrExampleFile(file.path)) continue;

      for (const catchNode of findNodes(file.tree.rootNode, CATCH_NODE)) {
        const param = catchNode.childForFieldName("parameter");
        const body = catchNode.childForFieldName("body");
        if (!param || param.type !== "identifier" || !body) continue;
        const err = param.text;

        walk(body, (node) => {
          if (!isMemberAccess(node, err, "message") && !isMemberAccess(node, err, "stack")) return;
          if (!isLeaked(node)) return;
          const line = node.startPosition.row + 1;
          const key = `${file.path}:${line}`;
          if (seen.has(key)) return;
          seen.add(key);
          findings.push({
            id: "PROD-03",
            category: "prod",
            severity: "low",
            confidence: "high",
            title: "Internal error detail returned to the client",
            file: file.path,
            line,
            column: node.startPosition.column,
            evidence: truncate(lineAt(file.text, node.startPosition.row)),
            fix: "Log the error server-side; return a generic message + a correlation id.",
            docsUrl: DOCS,
          });
        });
      }
    }
    return findings;
  },
};
