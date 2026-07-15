import { truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext, SyntaxNode } from "../types.js";
import { calleeName, referencesRequestInput } from "./ast.js";
import { isTestOrExampleFile, lineAt } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#web-03";

/** Filesystem sinks where a user-controlled path enables traversal. */
const FS_SINKS: ReadonlySet<string> = new Set([
  "readFile",
  "readFileSync",
  "createReadStream",
  "sendFile",
  "download",
]);

export const web03: Check = {
  id: "WEB-03",
  category: "web",
  severity: "medium",
  confidence: "medium",
  tier: "flow",
  title: "Path traversal via user-controlled file path",

  appliesTo: () => true,

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path)) continue;
      walk(file.tree.rootNode, (node) => {
        if (node.type !== "call_expression" || !FS_SINKS.has(calleeName(node))) return;
        const args = node.childForFieldName("arguments");
        if (!args) return;
        let tainted = false;
        for (let i = 0; i < args.namedChildCount; i++) {
          const a = args.namedChild(i);
          if (a && referencesRequestInput(a)) {
            tainted = true;
            break;
          }
        }
        if (!tainted) return;
        findings.push({
          id: "WEB-03",
          category: "web",
          severity: "medium",
          confidence: "medium",
          title: "User-controlled path in a filesystem call (path traversal)",
          file: file.path,
          line: node.startPosition.row + 1,
          column: node.startPosition.column,
          evidence: truncate(lineAt(file.text, node.startPosition.row)),
          fix: "Normalize and confine the path to a base directory; reject '..'; prefer an id→path map.",
          docsUrl: DOCS,
        });
      });
    }
    return findings;
  },
};
