import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scan } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const labBefore = join(here, "../../..", "fixtures", "lab-before");
const labAfter = join(here, "../../..", "fixtures", "lab-after");

const linesFor = (findings: { id: string; line: number }[], id: string) =>
  findings
    .filter((f) => f.id === id)
    .map((f) => f.line)
    .sort((a, b) => a - b);

describe("INJ-01 — dynamic code execution", () => {
  it("flags new Function() built from a non-constant value (lab-before:48)", async () => {
    const r = await scan(labBefore);
    const inj = r.findings.filter((f) => f.id === "INJ-01");
    expect(inj).toHaveLength(1);
    expect(inj[0]?.line).toBe(48);
    expect(inj[0]?.severity).toBe("critical");
  });

  it("does NOT flag lab-after (incl. the 'no new Function' comment on line 6)", async () => {
    const r = await scan(labAfter);
    expect(r.findings.filter((f) => f.id === "INJ-01")).toHaveLength(0);
  });
});

describe("PERF-01 — synchronous I/O on the request path", () => {
  it("flags function-scoped sync I/O in lab-before (readFileSync:20, writeFileSync:82)", async () => {
    const r = await scan(labBefore);
    expect(linesFor(r.findings, "PERF-01")).toEqual([20, 82]);
  });

  it("does NOT flag module-scope (boot-time) sync I/O in lab-after (line 23)", async () => {
    const r = await scan(labAfter);
    expect(r.findings.filter((f) => f.id === "PERF-01")).toHaveLength(0);
  });
});

describe("PROD-03 — internal error detail leaked to client", () => {
  it("flags err.message returned to the client in lab-before (51, 91)", async () => {
    const r = await scan(labBefore);
    expect(linesFor(r.findings, "PROD-03")).toEqual([51, 91]);
  });

  it("does NOT flag lab-after (generic error responses)", async () => {
    const r = await scan(labAfter);
    expect(r.findings.filter((f) => f.id === "PROD-03")).toHaveLength(0);
  });

  it("skips client-side files (a UI error toast) but still flags the server handler", async () => {
    const r = await scan(join(here, "fixtures", "prod03-client"));
    const prod03 = r.findings.filter((f) => f.id === "PROD-03");
    // the React component's showErrorToast(error.message) must NOT fire...
    expect(prod03.some((f) => f.file.includes("OrderDetail"))).toBe(false);
    // ...but the server handler's res.json({ error: e.message }) still must.
    expect(prod03.some((f) => f.file.includes("handler"))).toBe(true);
    expect(prod03).toHaveLength(1);
  });
});

describe("precision gate — the hardened fixture", () => {
  it("lab-after has no false criticals/highs; only the one real weak-default medium", async () => {
    const r = await scan(labAfter);
    // no false positives at critical/high severity
    expect(r.findings.filter((f) => f.severity === "critical")).toHaveLength(0);
    expect(r.findings.filter((f) => f.severity === "high")).toHaveLength(0);
    // the ONE true positive: `ADMIN_TOKEN || "admin-2024"` (the placeholder default is skipped)
    const nonInfo = r.findings.filter((f) => f.severity !== "info");
    expect(nonInfo).toHaveLength(1);
    expect(nonInfo[0]?.id).toBe("AUTH-03");
    expect(nonInfo[0]?.severity).toBe("medium");
    expect(r.grade).toBe("A");
  });

  it("lab-before lights up 4+ categories and scores below C", async () => {
    const r = await scan(labBefore);
    const categories = new Set(r.findings.map((f) => f.category));
    expect(categories.size).toBeGreaterThanOrEqual(4);
    expect(r.score).toBeLessThan(60);
  });

  it("lab-before grades far worse than lab-after", async () => {
    const before = await scan(labBefore);
    const after = await scan(labAfter);
    expect(after.score - before.score).toBeGreaterThan(40);
  });
});
