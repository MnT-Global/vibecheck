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

describe("scoring (fixed-100 model)", () => {
  it("category weights sum to 100", () => {
    const sum = Object.values(CATEGORY_MAX).reduce((a, b) => a + b, 0);
    expect(sum).toBe(100);
  });

  it("a clean scan is 100 / A+", () => {
    const r = score([], new Set(["secrets"]));
    expect(r.score).toBe(100);
    expect(r.grade).toBe("A+");
  });

  it("deducts per finding: one critical in secrets → 100 - min(25,20) = 80", () => {
    const r = score([finding({ severity: "critical" })], new Set(["secrets"]));
    expect(r.score).toBe(80);
    expect(r.grade).toBe("B");
  });

  it("a category's damage is capped at its weight (many findings don't over-deduct)", () => {
    const many = [
      finding({ severity: "critical", line: 1 }),
      finding({ severity: "critical", line: 2 }),
      finding({ severity: "critical", line: 3 }),
    ];
    const r = score(many, new Set(["secrets"]));
    expect(r.score).toBe(80); // secrets capped at 20
  });

  it("more findings never raise the score (deductions accumulate across categories)", () => {
    const one = score([finding({ severity: "critical", category: "secrets" })], new Set());
    const two = score(
      [
        finding({ severity: "critical", category: "secrets" }),
        finding({ severity: "high", category: "injection" }),
      ],
      new Set(),
    );
    expect(two.score).toBeLessThan(one.score);
    expect(two.score).toBe(100 - 20 - 12); // secrets capped 20 + injection high 12 = 68
  });

  it("info findings never affect the score", () => {
    const r = score([finding({ severity: "info", category: "deps" })], new Set(["deps"]));
    expect(r.score).toBe(100);
  });

  it("grade bands map correctly", () => {
    expect(gradeFor(90)).toBe("A-");
    expect(gradeFor(74)).toBe("C+");
    expect(gradeFor(44)).toBe("F");
  });
});
