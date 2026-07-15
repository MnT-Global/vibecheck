import { redactedEvidence, stringLiteralValue } from "../loader/redact.js";
import { findNodes } from "../parse/index.js";
import type { Check, Finding, ScanContext, Severity } from "../types.js";
import { isTestOrExampleFile } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#sec-04";

interface Pattern {
  name: string;
  re: RegExp;
  severity: Severity;
}

const PATTERNS: Pattern[] = [
  {
    name: "private key",
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
    severity: "critical",
  },
  {
    name: "database connection string with embedded credentials",
    // a URI carrying user:password@ — the password segment must be non-trivial
    re: /(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis|amqp):\/\/[^:@\s/]+:[^@\s/]{3,}@/,
    severity: "critical",
  },
];

const STRING_NODES: ReadonlySet<string> = new Set(["string", "template_string", "string_fragment"]);

export const sec04: Check = {
  id: "SEC-04",
  category: "secrets",
  severity: "critical",
  confidence: "high",
  tier: "structural",
  title: "Private key or credentialed connection string in source",

  appliesTo: () => true,

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path)) continue;

      for (const node of findNodes(file.tree.rootNode, STRING_NODES)) {
        const value = stringLiteralValue(node);
        for (const pattern of PATTERNS) {
          const m = value.match(pattern.re);
          if (!m) continue;
          const line = node.startPosition.row + 1;
          const key = `${file.path}:${line}:${pattern.name}`;
          if (seen.has(key)) break;
          seen.add(key);
          findings.push({
            id: "SEC-04",
            category: "secrets",
            severity: pattern.severity,
            confidence: "high",
            title: `Hardcoded ${pattern.name}`,
            file: file.path,
            line,
            column: node.startPosition.column,
            evidence: redactedEvidence(node.text.split("\n")[0] ?? "", m[0]),
            fix: "Move to a secret manager / environment variable and rotate the exposed credential.",
            docsUrl: DOCS,
          });
          break;
        }
      }
    }
    return findings;
  },
};
