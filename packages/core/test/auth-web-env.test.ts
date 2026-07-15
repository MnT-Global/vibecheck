import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scan } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = join(here, "fixtures");

describe("AUTH-04 — permissive CORS", () => {
  it("flags origin:'*' with credentials:true", async () => {
    const r = await scan(join(fx, "cors-dirty"));
    const cors = r.findings.filter((f) => f.id === "AUTH-04");
    expect(cors).toHaveLength(1);
    expect(cors[0]?.severity).toBe("medium");
    expect(cors[0]?.line).toBe(5);
  });

  it("does NOT flag an explicit origin allowlist", async () => {
    const r = await scan(join(fx, "cors-clean"));
    expect(r.findings.filter((f) => f.id === "AUTH-04")).toHaveLength(0);
  });
});

describe("WEB-01 — unsanitized HTML sink (XSS)", () => {
  it("flags dangerouslySetInnerHTML and innerHTML from a non-constant", async () => {
    const r = await scan(join(fx, "web-dirty"));
    const web = r.findings.filter((f) => f.id === "WEB-01");
    expect(web.map((f) => f.line).sort((a, b) => a - b)).toEqual([2, 6]);
    expect(web.every((f) => f.severity === "high")).toBe(true);
  });

  it("does NOT flag DOMPurify-sanitized HTML or textContent", async () => {
    const r = await scan(join(fx, "web-clean"));
    expect(r.findings.filter((f) => f.id === "WEB-01")).toHaveLength(0);
  });
});

describe("SEC-03 — committed .env / credentials", () => {
  it("flags a tracked .env but ignores .env.example", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vibecheck-sec03-"));
    try {
      await writeFile(join(dir, "package.json"), '{"name":"x"}');
      await writeFile(join(dir, ".env"), "STRIPE_SECRET=sk_live_abc123\n");
      const dirty = await scan(dir);
      expect(dirty.findings.filter((f) => f.id === "SEC-03")).toHaveLength(1);

      await rm(join(dir, ".env"));
      await writeFile(join(dir, ".env.example"), "STRIPE_SECRET=\n");
      const clean = await scan(dir);
      expect(clean.findings.filter((f) => f.id === "SEC-03")).toHaveLength(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
