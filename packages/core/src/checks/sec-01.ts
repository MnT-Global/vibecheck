import { redactedEvidence, stringLiteralValue } from "../loader/redact.js";
import { findNodes } from "../parse/index.js";
import type { Check, Finding, ScanContext, Severity } from "../types.js";
import { isPlaceholderSecret, isTestOrExampleFile, lineAt } from "./shared.js";

interface Pattern {
  name: string;
  re: RegExp;
  severity: Severity;
}

/**
 * Provider secret patterns (structural layer). Transcribed from the R0 research
 * (gitleaks v8.25.0 + trufflehog); see docs/research/secrets-and-deps.md §A.2.
 * Ordered most-severe first so the first match wins.
 */
const PATTERNS: Pattern[] = [
  {
    name: "Stripe secret key",
    re: /(?:sk|rk)_(?:live|prod)_[a-zA-Z0-9]{10,99}/,
    severity: "critical",
  },
  { name: "AWS access key ID", re: /(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}/, severity: "critical" },
  { name: "Shopify access token", re: /shp(?:at|ca|pa)_[a-fA-F0-9]{32}/, severity: "critical" },
  {
    name: "OpenAI API key",
    re: /sk-[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}/,
    severity: "high",
  },
  {
    name: "Anthropic API key",
    re: /sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{20,}/,
    severity: "high",
  },
  {
    name: "GitHub token",
    re: /(?:gh[posu]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{82})/,
    severity: "high",
  },
  { name: "npm token", re: /npm_[A-Za-z0-9]{36}/, severity: "high" },
  { name: "Slack token", re: /xox[bpe]-[0-9A-Za-z-]{10,}/, severity: "high" },
  { name: "SendGrid API key", re: /SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/, severity: "high" },
  { name: "Shopify shared secret", re: /shpss_[a-fA-F0-9]{32}/, severity: "high" },
  { name: "Google API key", re: /AIza[0-9A-Za-z_-]{35}/, severity: "medium" },
  { name: "Stripe test key", re: /(?:sk|rk)_test_[a-zA-Z0-9]{10,99}/, severity: "low" },
  { name: "Stripe publishable key", re: /pk_(?:live|test)_[a-zA-Z0-9]{10,99}/, severity: "low" },
];

const STRING_NODES: ReadonlySet<string> = new Set(["string", "template_string", "string_fragment"]);

function match(value: string): { pattern: Pattern; secret: string } | null {
  for (const pattern of PATTERNS) {
    const m = value.match(pattern.re);
    if (m) return { pattern, secret: m[0] };
  }
  return null;
}

export const sec01: Check = {
  id: "SEC-01",
  category: "secrets",
  severity: "critical",
  confidence: "high",
  tier: "structural",
  title: "Hardcoded provider secret in source",

  appliesTo: () => true,

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path)) continue;

      for (const node of findNodes(file.tree.rootNode, STRING_NODES)) {
        const value = stringLiteralValue(node);
        if (value.length < 8 || isPlaceholderSecret(value)) continue;

        const hit = match(value);
        if (!hit) continue;

        const line = node.startPosition.row + 1;
        const key = `${file.path}:${line}:${hit.pattern.name}`;
        if (seen.has(key)) continue;
        seen.add(key);

        findings.push({
          id: "SEC-01",
          category: "secrets",
          severity: hit.pattern.severity,
          confidence: "high",
          title: `Hardcoded ${hit.pattern.name}`,
          file: file.path,
          line,
          column: node.startPosition.column,
          evidence: redactedEvidence(lineAt(file.text, node.startPosition.row), hit.secret),
          fix: "Move this secret to an environment variable and rotate the exposed key immediately.",
          docsUrl: "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#sec-01",
        });
      }
    }
    return findings;
  },
};
