import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scan } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = join(here, "fixtures");

describe("INJ-03 — command injection", () => {
  it("flags execSync built from a non-constant value", async () => {
    const r = await scan(join(fx, "inj03-dirty"));
    const inj = r.findings.filter((f) => f.id === "INJ-03");
    expect(inj).toHaveLength(1);
    expect(inj[0]?.line).toBe(4);
    expect(inj[0]?.severity).toBe("high");
  });

  it("does NOT flag execFile with an args array, nor regex.exec on input", async () => {
    const r = await scan(join(fx, "inj03-clean"));
    expect(r.findings.filter((f) => f.id === "INJ-03")).toHaveLength(0);
  });
});

describe("AUTH-03 — hardcoded / default credentials", () => {
  it("flags a credential compared to a literal (high) and an insecure default (medium)", async () => {
    const r = await scan(join(fx, "auth03-dirty"));
    const auth = r.findings.filter((f) => f.id === "AUTH-03");
    expect(auth).toHaveLength(2);
    expect(auth.some((f) => f.severity === "high" && f.line === 5)).toBe(true);
    expect(auth.some((f) => f.severity === "medium" && f.line === 1)).toBe(true);
  });

  it("does NOT flag env vars without defaults or hashed verification", async () => {
    const r = await scan(join(fx, "auth03-clean"));
    expect(r.findings.filter((f) => f.id === "AUTH-03")).toHaveLength(0);
  });
});

describe("SEC-02 — secret via a client-side env var", () => {
  it("flags NEXT_PUBLIC_/VITE_ vars named like a secret", async () => {
    const r = await scan(join(fx, "sec02-dirty"));
    const sec = r.findings.filter((f) => f.id === "SEC-02");
    expect(sec).toHaveLength(2);
    expect(sec.every((f) => f.severity === "high")).toBe(true);
  });

  it("does NOT flag publishable keys, public URLs, or server-only secrets", async () => {
    const r = await scan(join(fx, "sec02-clean"));
    expect(r.findings.filter((f) => f.id === "SEC-02")).toHaveLength(0);
  });
});

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
