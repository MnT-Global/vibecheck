import type { Check, Finding, ScanContext, Severity } from "../types.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#dep-01";

const SEV_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * DEP-01 — known-vulnerable dependencies. High confidence (real CVE data), but flow-tier because
 * it needs the OSV lookup (network, opt-in under --experimental). Only applicable once advisories
 * have been resolved; if OSV was unreachable it is N/A (a scan note explains why).
 */
export const dep01: Check = {
  id: "DEP-01",
  category: "deps",
  severity: "high",
  confidence: "high",
  tier: "flow",
  title: "Known-vulnerable dependency",

  appliesTo: (ctx) => ctx.dependencies.length > 0 && !!ctx.advisories,

  run(ctx: ScanContext): Finding[] {
    const advisories = ctx.advisories;
    if (!advisories) return [];
    const lockFile =
      ctx.files.find((f) => /package-lock\.json$/.test(f.path))?.path ?? "package-lock.json";

    const findings: Finding[] = [];
    for (const dep of ctx.dependencies) {
      const vulns = advisories.get(`${dep.name}@${dep.version}`);
      if (!vulns?.length) continue;
      const worst = [...vulns].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])[0];
      if (!worst) continue;
      const fixed = vulns.map((v) => v.fixed).find(Boolean);

      findings.push({
        id: "DEP-01",
        category: "deps",
        severity: worst.severity,
        confidence: "high",
        title: `${dep.name}@${dep.version} — ${vulns.length} known ${vulns.length === 1 ? "vulnerability" : "vulnerabilities"} (${worst.severity})`,
        file: lockFile,
        line: 1,
        column: 0,
        evidence: `${worst.id}: ${worst.summary}${fixed ? ` — fixed in ${fixed}` : ""}`,
        fix: fixed
          ? `Upgrade ${dep.name} to ${fixed} or later.`
          : `Upgrade ${dep.name} to a patched version.`,
        docsUrl: DOCS,
      });
    }
    return findings;
  },
};
