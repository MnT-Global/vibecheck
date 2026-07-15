import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scan } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = join(here, "fixtures");
const labBefore = join(here, "../../..", "fixtures", "lab-before");
const labAfter = join(here, "../../..", "fixtures", "lab-after");

const EXP = { experimental: true };
const ids = (fs: { id: string }[]) => new Set(fs.map((f) => f.id));

describe("flow tier — gated behind --experimental", () => {
  it("does NOT run flow checks by default", async () => {
    const r = await scan(join(fx, "flow-dirty"));
    const flow = r.findings.filter((f) => f.confidence === "medium");
    expect(flow).toHaveLength(0);
  });

  it("runs flow checks under --experimental and flags all four on flow-dirty", async () => {
    const r = await scan(join(fx, "flow-dirty"), EXP);
    const found = ids(r.findings);
    expect(found.has("COM-01")).toBe(true); // client-trusted price
    expect(found.has("INJ-02")).toBe(true); // SQL injection
    expect(found.has("WEB-02")).toBe(true); // SSRF
    expect(found.has("WEB-03")).toBe(true); // path traversal
    expect(r.findings.find((f) => f.id === "COM-01")?.line).toBe(6);
    expect(r.findings.find((f) => f.id === "WEB-02")?.line).toBe(12);
  });

  it("does NOT flag the hardened flow-clean fixture", async () => {
    const r = await scan(join(fx, "flow-clean"), EXP);
    for (const id of ["COM-01", "INJ-02", "WEB-02", "WEB-03"]) {
      expect(r.findings.filter((f) => f.id === id)).toHaveLength(0);
    }
  });
});

describe("PROD-01 — no rate limiting", () => {
  it("fires on lab-before (no limiter) only under --experimental", async () => {
    const off = await scan(labBefore);
    expect(off.findings.filter((f) => f.id === "PROD-01")).toHaveLength(0);
    const on = await scan(labBefore, EXP);
    expect(on.findings.filter((f) => f.id === "PROD-01")).toHaveLength(1);
  });

  it("does NOT fire on lab-after (has a rate limiter)", async () => {
    const r = await scan(labAfter, EXP);
    expect(r.findings.filter((f) => f.id === "PROD-01")).toHaveLength(0);
  });
});
