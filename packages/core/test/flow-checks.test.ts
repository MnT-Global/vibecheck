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

describe("flow tier batch 3 — COM-04, PERF-03, INJ-04, DEP-02", () => {
  it("flags all four on flow2-dirty under --experimental", async () => {
    const r = await scan(join(fx, "flow2-dirty"), EXP);
    const found = ids(r.findings);
    expect(found.has("COM-04")).toBe(true); // client discount
    expect(found.has("PERF-03")).toBe(true); // N+1 query in loop
    expect(found.has("INJ-04")).toBe(true); // prototype pollution
    expect(found.has("DEP-02")).toBe(true); // no security headers
    expect(r.findings.filter((f) => f.id === "INJ-04")).toHaveLength(2); // key + merge
  });

  it("does NOT flag flow2-clean (validated coupon, batched query, fixed key, helmet)", async () => {
    const r = await scan(join(fx, "flow2-clean"), EXP);
    for (const id of ["COM-04", "PERF-03", "INJ-04", "DEP-02"]) {
      expect(r.findings.filter((f) => f.id === id)).toHaveLength(0);
    }
  });
});

describe("AUTH-01 — unauthenticated sensitive route (via raw-http route mapping)", () => {
  it("flags GET /admin/orders in lab-before (no auth) under --experimental", async () => {
    const off = await scan(labBefore);
    expect(off.findings.filter((f) => f.id === "AUTH-01")).toHaveLength(0);
    const on = await scan(labBefore, EXP);
    const auth = on.findings.filter((f) => f.id === "AUTH-01");
    expect(auth).toHaveLength(1);
    expect(auth[0]?.title).toContain("/admin/orders");
    expect(auth[0]?.severity).toBe("critical");
  });

  it("does NOT flag lab-after (the admin handler checks ADMIN_TOKEN)", async () => {
    const r = await scan(labAfter, EXP);
    expect(r.findings.filter((f) => f.id === "AUTH-01")).toHaveLength(0);
  });
});

describe("PERF-02 — full data file parsed per request", () => {
  it("flags lab-before's per-request db() but not lab-after's boot-time load", async () => {
    const before = await scan(labBefore, EXP);
    expect(before.findings.filter((f) => f.id === "PERF-02")).toHaveLength(1);
    const after = await scan(labAfter, EXP);
    expect(after.findings.filter((f) => f.id === "PERF-02")).toHaveLength(0);
  });
});

describe("PROD-04 — secret written to logs", () => {
  it("flags console/logger calls that log a secret; clean logging is fine", async () => {
    const dirty = await scan(join(fx, "prod04-dirty"), EXP);
    expect(dirty.findings.filter((f) => f.id === "PROD-04").length).toBeGreaterThanOrEqual(2);
    const clean = await scan(join(fx, "prod04-clean"), EXP);
    expect(clean.findings.filter((f) => f.id === "PROD-04")).toHaveLength(0);
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
