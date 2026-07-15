import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scan } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const labBefore = join(here, "../../..", "fixtures", "lab-before");
const labAfter = join(here, "../../..", "fixtures", "lab-after");
const secretsDirty = join(here, "fixtures", "secrets-dirty");
const secretsClean = join(here, "fixtures", "secrets-clean");

describe("COM-02 — unvalidated order quantity (the commerce flagship)", () => {
  it("flags request quantity used in pricing without validation (lab-before:80)", async () => {
    const r = await scan(labBefore);
    const com = r.findings.filter((f) => f.id === "COM-02");
    expect(com).toHaveLength(1);
    expect(com[0]?.line).toBe(80);
    expect(com[0]?.severity).toBe("high");
    expect(com[0]?.category).toBe("commerce");
  });

  it("does NOT flag validated quantity (lab-after uses Number.isInteger + range)", async () => {
    const r = await scan(labAfter);
    expect(r.findings.filter((f) => f.id === "COM-02")).toHaveLength(0);
  });
});

describe("SEC-04 — private keys / connection strings in source", () => {
  it("flags a credentialed DB URI and a private key block", async () => {
    const r = await scan(secretsDirty);
    const sec04 = r.findings.filter((f) => f.id === "SEC-04");
    expect(sec04).toHaveLength(2);
    expect(sec04.every((f) => f.severity === "critical")).toBe(true);
    // credentials must be redacted, never printed in full
    expect(sec04.some((f) => f.evidence.includes("s3cr3tPassw0rd"))).toBe(false);
  });

  it("does NOT flag the env-based clean version", async () => {
    const r = await scan(secretsClean);
    expect(r.findings.filter((f) => f.id === "SEC-04")).toHaveLength(0);
  });
});

describe("DEP-03 — no test suite (info, zero score impact)", () => {
  it("fires as info on a fixture with no tests", async () => {
    const r = await scan(labBefore);
    const dep = r.findings.filter((f) => f.id === "DEP-03");
    expect(dep).toHaveLength(1);
    expect(dep[0]?.severity).toBe("info");
  });

  it("does not fire when tests are present (vibecheck scans itself)", async () => {
    const repoRoot = join(here, "../../..");
    const r = await scan(repoRoot);
    expect(r.findings.filter((f) => f.id === "DEP-03")).toHaveLength(0);
  });
});
