import { describe, expect, it } from "vitest";
import { CATEGORY_MAX, type Finding, gradeFor, score } from "../src/index.js";

function finding(partial: Partial<Finding>): Finding {
  return {
    id: "SEC-01",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    title: "test",
    file: "a.ts",
    line: 1,
    column: 0,
    evidence: "",
    fix: "",
    ...partial,
  };
}

describe("scoring", () => {
  it("category weights sum to 100", () => {
    const sum = Object.values(CATEGORY_MAX).reduce((a, b) => a + b, 0);
    expect(sum).toBe(100);
  });

  it("stack-neutral denominator: only assessed categories count", () => {
    // one critical secrets finding; only 'secrets' assessed → 10/20 earned → 50
    const r = score([finding({ severity: "critical" })], new Set(["secrets"]));
    expect(r.score).toBe(50);
    expect(r.grade).toBe("D");
  });

  it("a clean scan is 100 / A+", () => {
    const r = score([], new Set(["secrets"]));
    expect(r.score).toBe(100);
    expect(r.grade).toBe("A+");
  });

  it("grade bands map correctly", () => {
    expect(gradeFor(90)).toBe("A-");
    expect(gradeFor(74)).toBe("C+");
    expect(gradeFor(44)).toBe("F");
  });
});
