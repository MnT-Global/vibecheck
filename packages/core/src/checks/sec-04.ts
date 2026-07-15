import { redactedEvidence, stringLiteralValue } from "../loader/redact.js";
import { findNodes } from "../parse/index.js";
import type { Check, Finding, ScanContext, Severity } from "../types.js";
import { isLockfile, isPlaceholderSecret, isTestOrExampleFile } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#sec-04";

interface Pattern {
  name: string;
  re: RegExp;
  severity: Severity;
  /** Optional gate: return false to suppress a match (e.g. a local-dev DB URL). */
  accept?(value: string): boolean;
}

/** A connection string pointing at a local / docker-dev host — not a leaked production credential. */
const LOCAL_DB_HOST =
  /@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal)(?::\d+)?(?:[/?]|$)/i;
/** Canonical throwaway dev passwords baked into quickstarts / docker-compose examples. */
const DEV_DB_PASSWORD =
  /^(?:postgres|root|admin|example|password|passwd|pass|secret|changeme|dev|devpassword|test|guest|mysql|mongo|redis|toor)$/i;

/** A local-dev / example DB URL is noise, not a leak. */
function isDevDbUrl(value: string): boolean {
  if (LOCAL_DB_HOST.test(value)) return true;
  const pw = value.match(/:\/\/[^:@\s/]*:([^@\s/]{3,})@/)?.[1] ?? "";
  return isPlaceholderSecret(pw) || DEV_DB_PASSWORD.test(pw);
}

const PATTERNS: Pattern[] = [
  {
    name: "private key",
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----/,
    severity: "critical",
  },
  {
    name: "database connection string with embedded credentials",
    // a URI carrying user:password@ — the password segment must be non-trivial
    re: /(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis|amqp):\/\/[^:@\s/]+:[^@\s/]{3,}@/,
    severity: "critical",
    accept: (value) => !isDevDbUrl(value),
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

    const record = (
      file: string,
      line: number,
      column: number,
      pattern: Pattern,
      match: string,
      evidenceLine: string,
    ) => {
      const key = `${file}:${line}:${pattern.name}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push({
        id: "SEC-04",
        category: "secrets",
        severity: pattern.severity,
        confidence: "high",
        title: `Hardcoded ${pattern.name}`,
        file,
        line,
        column,
        evidence: redactedEvidence(evidenceLine, match),
        fix: "Move to a secret manager / environment variable and rotate the exposed credential.",
        docsUrl: DOCS,
      });
    };

    /** Match the value against the patterns; returns the first accepted hit. */
    const firstHit = (value: string): { pattern: Pattern; match: string } | null => {
      for (const pattern of PATTERNS) {
        const m = value.match(pattern.re);
        if (!m) continue;
        if (pattern.accept && !pattern.accept(value)) continue;
        return { pattern, match: m[0] };
      }
      return null;
    };

    for (const file of ctx.files) {
      if (isTestOrExampleFile(file.path)) continue;

      if (file.tree) {
        for (const node of findNodes(file.tree.rootNode, STRING_NODES)) {
          const hit = firstHit(stringLiteralValue(node));
          if (!hit) continue;
          record(
            file.path,
            node.startPosition.row + 1,
            node.startPosition.column,
            hit.pattern,
            hit.match,
            node.text.split("\n")[0] ?? "",
          );
        }
        continue;
      }

      // No grammar (.json / .env): private keys & DB URIs hide in service-account JSON and .env.
      if (isLockfile(file.path)) continue;
      const lines = file.text.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const hit = firstHit(lines[i] ?? "");
        if (!hit) continue;
        record(file.path, i + 1, 0, hit.pattern, hit.match, lines[i] ?? "");
      }
    }
    return findings;
  },
};
