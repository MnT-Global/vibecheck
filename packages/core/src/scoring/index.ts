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
  critical: 25,
  high: 12,
  medium: 6,
  low: 2,
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
 * Score out of a fixed 100: start at 100, deduct per finding (by severity), where each category
 * can subtract at most its weight (`CATEGORY_MAX`). Inherently stack-neutral — a category with no
 * applicable check simply has no findings and deducts nothing, so absence is never penalized, and
 * finding *more* issues can never raise the score. `assessed` is carried only for reporting which
 * checks actually ran.
 */
export function score(
  findings: Finding[],
  assessed: ReadonlySet<Category>,
): { score: number; grade: Grade; categoryScores: CategoryScore[] } {
  const categoryScores: CategoryScore[] = [];
  let totalDeduction = 0;

  for (const category of Object.keys(CATEGORY_MAX) as Category[]) {
    const max = CATEGORY_MAX[category];
    const catFindings = findings.filter((f) => f.category === category);
    const raw = catFindings.reduce((sum, f) => sum + SEVERITY_DEDUCTION[f.severity], 0);
    const capped = Math.min(raw, max);
    totalDeduction += capped;

    categoryScores.push({
      category,
      applicable: assessed.has(category),
      max,
      earned: max - capped,
      findings: catFindings.length,
    });
  }

  const points = Math.max(0, 100 - totalDeduction);

  // Severity floor. The per-category cap can let a serious finding score deceptively well — a single
  // hardcoded secret is one critical in `secrets`, capped at −20 → 80/"B". A security grade must
  // never read "B" when a critical is present, nor "A−" for a lone high in a low-weight category.
  // Cap the attainable score by the worst severity seen, so the grade can never overstate safety
  // regardless of which category the finding happens to live in.
  const severities = new Set(findings.map((f) => f.severity));
  const floor = severities.has("critical") ? 50 : severities.has("high") ? 82 : 100;
  const pct = Math.min(points, floor);

  return { score: pct, grade: gradeFor(pct), categoryScores };
}
