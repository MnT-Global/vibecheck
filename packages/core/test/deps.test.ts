import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { type AdvisoryMap, buildContext, scan } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const vulnDeps = join(here, "fixtures", "vuln-deps");

describe("lockfile parsing", () => {
  it("extracts resolved deps from package-lock.json v3", async () => {
    const ctx = await buildContext(vulnDeps);
    const set = new Set(ctx.dependencies.map((d) => `${d.name}@${d.version}`));
    expect(set.has("lodash@4.17.11")).toBe(true);
    expect(set.has("safe-pkg@1.0.0")).toBe(true);
  });
});

describe("DEP-01 — known-vulnerable dependency (injected advisories, offline)", () => {
  const advisories: AdvisoryMap = new Map([
    [
      "lodash@4.17.11",
      [
        {
          id: "GHSA-jf85-cpcp-j695",
          severity: "critical",
          summary: "Prototype Pollution in lodash",
          fixed: "4.17.21",
        },
      ],
    ],
  ]);

  it("flags the vulnerable package and not the safe one", async () => {
    const r = await scan(vulnDeps, { experimental: true, advisories });
    const dep = r.findings.filter((f) => f.id === "DEP-01");
    expect(dep).toHaveLength(1);
    expect(dep[0]?.severity).toBe("critical");
    expect(dep[0]?.title).toContain("lodash@4.17.11");
    expect(dep[0]?.evidence).toContain("4.17.21");
  });

  it("is N/A (no findings) when advisories were not resolved (offline)", async () => {
    const r = await scan(vulnDeps, { experimental: true, offline: true });
    expect(r.findings.filter((f) => f.id === "DEP-01")).toHaveLength(0);
  });

  it("does not run at all without --experimental", async () => {
    const r = await scan(vulnDeps, { advisories });
    expect(r.findings.filter((f) => f.id === "DEP-01")).toHaveLength(0);
  });
});
