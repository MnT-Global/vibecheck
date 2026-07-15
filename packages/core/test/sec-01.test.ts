import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scan } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoFixtures = join(here, "../../..", "fixtures");

describe("SEC-01 — hardcoded secret", () => {
  it("flags the Stripe live key in lab-before at the correct file:line, redacted", async () => {
    const report = await scan(join(repoFixtures, "lab-before"));
    const sec = report.findings.filter((f) => f.id === "SEC-01");

    expect(sec.length).toBeGreaterThanOrEqual(1);
    const secret = sec.find((f) => f.file === "server.js");
    expect(secret).toBeDefined();
    expect(secret?.line).toBe(15);
    expect(secret?.severity).toBe("critical");
    expect(secret?.title).toContain("Stripe");
    // never leak the full secret; show only the redacted prefix
    expect(secret?.evidence).not.toContain("sk_live_MnTfixtureFAKE");
    expect(secret?.evidence).toContain("sk_live_…");
  });

  it("does NOT flag lab-after — the regression gate", async () => {
    const report = await scan(join(repoFixtures, "lab-after"));
    expect(report.findings.filter((f) => f.id === "SEC-01")).toHaveLength(0);
  });

  it("lab-before grades worse than lab-after", async () => {
    const before = await scan(join(repoFixtures, "lab-before"));
    const after = await scan(join(repoFixtures, "lab-after"));
    expect(before.score).toBeLessThan(after.score);
  });
});
