import type { Check, Report, Severity } from "@mntglobal/vibecheck-core";

/** SARIF only has error/warning/note — map our five severities onto them. */
const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "warning",
  info: "note",
};

/** GitHub Code Scanning uses a numeric `security-severity` (0–10) to rank + gate. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.0",
  high: "7.0",
  medium: "4.0",
  low: "2.0",
  info: "0.0",
};

const RULES_DOC = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md";

/** Render a Report as SARIF 2.1.0 (consumed by GitHub Code Scanning, editors, etc.). */
export function renderSarif(report: Report, checks: Check[], version: string): string {
  const rules = checks.map((c) => ({
    id: c.id,
    name: c.title,
    shortDescription: { text: c.title },
    helpUri: `${RULES_DOC}#${c.id.toLowerCase()}`,
    properties: {
      category: c.category,
      tier: c.tier,
      "security-severity": SECURITY_SEVERITY[c.severity],
    },
  }));

  const results = report.findings.map((f) => ({
    ruleId: f.id,
    level: LEVEL[f.severity],
    message: { text: `${f.title}. ${f.fix}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file },
          region: {
            startLine: f.line,
            startColumn: f.column + 1,
            snippet: { text: f.evidence },
          },
        },
      },
    ],
    properties: {
      severity: f.severity,
      confidence: f.confidence,
      "security-severity": SECURITY_SEVERITY[f.severity],
    },
  }));

  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "vibecheck",
              informationUri: "https://github.com/MnT-Global/vibecheck",
              version,
              rules,
            },
          },
          results,
        },
      ],
    },
    null,
    2,
  );
}
