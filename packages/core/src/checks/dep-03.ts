import type { Check, Finding, ScanContext } from "../types.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#dep-03";

const TEST_FILE = /\.(test|spec|cy)\.[jt]sx?$/;
const TEST_DIR = /(^|\/)(__tests__|cypress|e2e|playwright|tests?)(\/|$)/;
const NPM_DEFAULT_TEST = /no test specified/i;

/**
 * DEP-03 — no test suite. A production-readiness signal, not a vulnerability, so it is `info`
 * severity (zero score impact) — reported honestly, never a deduction.
 */
export const dep03: Check = {
  id: "DEP-03",
  category: "deps",
  severity: "info",
  confidence: "high",
  tier: "structural",
  title: "No test suite detected",

  appliesTo: () => true,

  run(ctx: ScanContext): Finding[] {
    const hasTestFile = ctx.files.some((f) => TEST_FILE.test(f.path) || TEST_DIR.test(f.path));

    const pkg = ctx.files.find((f) => f.path === "package.json");
    let hasTestScript = false;
    if (pkg) {
      try {
        const parsed = JSON.parse(pkg.text) as { scripts?: Record<string, string> };
        const test = parsed.scripts?.test;
        hasTestScript =
          typeof test === "string" && test.trim() !== "" && !NPM_DEFAULT_TEST.test(test);
      } catch {
        // unparseable package.json — treat as no test script
      }
    }

    if (hasTestFile || hasTestScript) return [];

    return [
      {
        id: "DEP-03",
        category: "deps",
        severity: "info",
        confidence: "high",
        title: "No test suite detected",
        file: pkg ? "package.json" : ".",
        line: 1,
        column: 0,
        evidence: "no test files or test script found",
        fix: "Add tests — start with the checkout and authentication paths.",
        docsUrl: DOCS,
      },
    ];
  },
};
