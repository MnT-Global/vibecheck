import type { Category, CategoryScore, Finding, Grade, Severity } from "../types.js";

/** Category point ceilings (CTO-revised weights — build plan §4.3, sum = 100). */
export const CATEGORY_MAX: Record<Category, number> = {
  secrets: 20,
  injection: 16,
  auth: 17,
  commerce: 15,
  web: 10,
  perf: 8,
  prod: 9,
  deps: 5,
};

/** Points deducted per finding, by severity. `info` never affects the score. */
const SEVERITY_DEDUCTION: Record<Severity, number> = {
  critical: 10,
  high: 6,
  medium: 3,
  low: 1,
  info: 0,
};

export function gradeFor(score: number): Grade {
  if (score >= 97) return "A+";
  if (score >= 93) return "A";
  if (score >= 90) return "A-";
  if (score >= 85) return "B+";
  if (score >= 80) return "B";
  if (score >= 75) return "B-";
  if (score >= 70) return "C+";
  if (score >= 65) return "C";
  if (score >= 60) return "C-";
  if (score >= 55) return "D+";
  if (score >= 50) return "D";
  if (score >= 45) return "D-";
  return "F";
}

/**
 * Score with a stack-neutral denominator: only categories actually assessed (a check ran
 * and applied) count toward the total. Un-shipped / N/A categories are simply absent.
 */
export function score(
  findings: Finding[],
  assessed: ReadonlySet<Category>,
): { score: number; grade: Grade; categoryScores: CategoryScore[] } {
  const categoryScores: CategoryScore[] = [];
  let earnedTotal = 0;
  let maxTotal = 0;

  for (const category of Object.keys(CATEGORY_MAX) as Category[]) {
    const applicable = assessed.has(category);
    const max = CATEGORY_MAX[category];
    const catFindings = findings.filter((f) => f.category === category);
    const deducted = catFindings.reduce((sum, f) => sum + SEVERITY_DEDUCTION[f.severity], 0);
    const earned = Math.max(0, max - deducted);

    categoryScores.push({ category, applicable, max, earned, findings: catFindings.length });

    if (applicable) {
      earnedTotal += earned;
      maxTotal += max;
    }
  }

  const pct = maxTotal === 0 ? 100 : Math.round((earnedTotal / maxTotal) * 100);
  return { score: pct, grade: gradeFor(pct), categoryScores };
}
