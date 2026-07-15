import { activeChecks } from "./checks/index.js";
import { buildContext } from "./loader/index.js";
import { fetchOsvAdvisories } from "./osv/index.js";
import { score as scoreReport } from "./scoring/index.js";
import type { Category, Finding, Report, ScanOptions, Severity } from "./types.js";

export * from "./types.js";
export { buildContext } from "./loader/index.js";
export { ALL_CHECKS, activeChecks } from "./checks/index.js";
export { CATEGORY_MAX, gradeFor, score } from "./scoring/index.js";
export { parseText } from "./parse/index.js";
export { extractRoutes } from "./loader/routes.js";
export { fetchOsvAdvisories } from "./osv/index.js";

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * Scan a codebase and return a graded report.
 * All I/O happens in buildContext; checks are pure functions over the ScanContext.
 */
export async function scan(root: string, options: ScanOptions = {}): Promise<Report> {
  const started = Date.now();
  const ctx = await buildContext(root, options);

  // Dependency advisories (DEP-01) — injected, or fetched from OSV under --experimental.
  // This is the ONE network step, opt-in, and it fetches public advisory data (never your code).
  if (options.advisories) {
    ctx.advisories = options.advisories;
  } else if (ctx.options.experimental && !options.offline && ctx.dependencies.length > 0) {
    const advisories = await fetchOsvAdvisories(ctx.dependencies);
    if (advisories) ctx.advisories = advisories;
    else
      ctx.notes.push({
        level: "warn",
        message:
          "Couldn't reach OSV — dependency check skipped (run online once to cache advisories).",
      });
  }

  const assessed = new Set<Category>();
  const findings: Finding[] = [];
  for (const check of activeChecks(ctx)) {
    if (!check.appliesTo(ctx)) continue;
    assessed.add(check.category);
    findings.push(...check.run(ctx));
  }

  findings.sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );

  const { score, grade, categoryScores } = scoreReport(findings, assessed);

  return {
    root,
    grade,
    score,
    findings,
    categoryScores,
    notes: ctx.notes,
    filesScanned: ctx.files.length,
    durationMs: Date.now() - started,
  };
}
