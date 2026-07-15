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

  it("severity floor: one critical drops to D, even though the point model alone says 80", () => {
    // point model: 100 - min(25,20) = 80; the critical severity floor caps it at 50.
    const r = score([finding({ severity: "critical" })], new Set(["secrets"]));
    expect(r.score).toBe(50);
    expect(r.grade).toBe("D");
  });

  it("severity floor: any critical caps the grade at D regardless of which category it lives in", () => {
    // one critical in a low-weight category: point model = 100 - min(25,5) = 95, floored to 50.
    const r = score([finding({ severity: "critical", category: "deps" })], new Set(["deps"]));
    expect(r.score).toBe(50);
    expect(r.grade).toBe("D");
  });

  it("severity floor: a lone high can't grade above B (no more A- for a single high)", () => {
    // point model = 100 - min(12,10) = 90 (would be A-); the high floor caps at 82 → B.
    const r = score([finding({ severity: "high", category: "web" })], new Set(["web"]));
    expect(r.score).toBe(82);
    expect(r.grade).toBe("B");
  });

  it("a category's damage is capped at its weight (highs, below the critical floor)", () => {
    const many = [
      finding({ severity: "high", line: 1 }),
      finding({ severity: "high", line: 2 }),
      finding({ severity: "high", line: 3 }),
    ];
    // 3 highs = -36 raw, capped at the secrets weight 20 → 80; the high floor (82) doesn't bite.
    const r = score(many, new Set(["secrets"]));
    expect(r.score).toBe(80);
  });

  it("more findings never raise the score", () => {
    const one = score([finding({ severity: "high", category: "secrets" })], new Set());
    const two = score(
      [
        finding({ severity: "high", category: "secrets" }),
        finding({ severity: "high", category: "injection" }),
      ],
      new Set(),
    );
    expect(two.score).toBeLessThan(one.score);
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
