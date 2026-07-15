import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { type Finding, type ScanOptions, scan } from "../src/index.js";

// v0.1.3 "Trust" milestone — locks the false-positive / false-negative fixes from the self-audit so
// they can't silently regress (the audit's #1 risk: precision gates that were never tested).

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

async function scanFiles(
  files: Record<string, string>,
  opts: ScanOptions = {},
): Promise<Finding[]> {
  const dir = await mkdtemp(join(tmpdir(), "vibecheck-v013-"));
  dirs.push(dir);
  for (const [name, content] of Object.entries(files)) {
    const full = join(dir, name);
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, content);
  }
  return (await scan(dir, opts)).findings;
}
const ids = (fs: Finding[], id: string) => fs.filter((f) => f.id === id);

describe("SEC-04 — local-dev DB URLs are not leaks (FP fix)", () => {
  it("does NOT flag localhost / docker-dev connection strings", async () => {
    const f = await scanFiles({
      "db.ts": [
        'export const pg = "postgresql://postgres:postgres@localhost:5432/app";',
        'export const mongo = "mongodb://root:example@localhost:27017";',
        'export const redis = "redis://:devpassword@127.0.0.1:6379";',
      ].join("\n"),
    });
    expect(ids(f, "SEC-04")).toHaveLength(0);
  });
  it("STILL flags a real production connection string", async () => {
    const f = await scanFiles({
      "db.ts":
        'export const url = "postgresql://admin:S3cr3tPassw0rd@prod.db.example.com:5432/app";',
    });
    expect(ids(f, "SEC-04")).toHaveLength(1);
  });
});

describe("SEC-01 / SEC-04 — secrets inside .json / .env are now scanned (FN fix)", () => {
  it("finds a provider secret and a private key in config.json", async () => {
    const f = await scanFiles({
      "config.json": JSON.stringify(
        {
          stripeSecret: "sk_live_MnTauditFAKEjson",
          private_key: "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----",
        },
        null,
        2,
      ),
    });
    expect(ids(f, "SEC-01").length).toBeGreaterThanOrEqual(1);
    expect(ids(f, "SEC-04").length).toBeGreaterThanOrEqual(1);
  });
  it("finds a provider secret in a committed .env", async () => {
    const f = await scanFiles({ ".env": "STRIPE_KEY=sk_live_MnTauditFAKEenv\n" });
    expect(ids(f, "SEC-01").length).toBeGreaterThanOrEqual(1);
  });
  it("does NOT scan a huge hash-dense lockfile", async () => {
    const f = await scanFiles({
      "package-lock.json": `{ "AKIAXXXXXXXXXXXXXXXX": "sha512-${"a".repeat(40)}" }`,
    });
    expect(ids(f, "SEC-01")).toHaveLength(0);
  });
});

describe("SEC-02 — keys that are public by design are not flagged (FP fix)", () => {
  it("does NOT flag Firebase / reCAPTCHA / Maps / Algolia public keys", async () => {
    const f = await scanFiles({
      "config.ts": [
        "export const a = process.env.NEXT_PUBLIC_FIREBASE_API_KEY;",
        "export const b = process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY;",
        "export const c = process.env.NEXT_PUBLIC_GOOGLE_MAPS_API_KEY;",
        "export const d = process.env.NEXT_PUBLIC_ALGOLIA_SEARCH_KEY;",
      ].join("\n"),
    });
    expect(ids(f, "SEC-02")).toHaveLength(0);
  });
  it("STILL flags a real secret in a public-prefixed var", async () => {
    const f = await scanFiles({
      "leak.ts": "export const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;",
    });
    expect(ids(f, "SEC-02")).toHaveLength(1);
  });
});

describe("COM-02 — commerce flagship precision (FP fix)", () => {
  it("does NOT flag string concatenation of a quantity (display string)", async () => {
    const f = await scanFiles({
      "cart.ts":
        'export function show(body){ return "You added " + body.quantity + " items to your cart"; }',
    });
    expect(ids(f, "COM-02")).toHaveLength(0);
  });
  it("does NOT flag a quantity validated by a throwing schema .parse()", async () => {
    const f = await scanFiles({
      "checkout.ts": [
        "export function checkout(body){",
        "  const qty = CheckoutItem.parse(body.qty);",
        "  const total = product.price * qty;",
        "  return total;",
        "}",
      ].join("\n"),
    });
    expect(ids(f, "COM-02")).toHaveLength(0);
  });
  it("STILL flags an unvalidated client quantity in pricing", async () => {
    const f = await scanFiles({
      "checkout.ts":
        "export function checkout(body){ const total = product.price * body.qty; return total; }",
    });
    expect(ids(f, "COM-02")).toHaveLength(1);
  });
});

describe("AUTH-03 — credentials precision (FP + FN fixes)", () => {
  it("does NOT flag comparisons to auth scheme / provider constants", async () => {
    const f = await scanFiles({
      "auth.ts": [
        'export const a = (r) => r.token_type === "bearer";',
        'export const b = (s) => s.authScheme === "Bearer";',
        'export const c = (p) => p.authProvider === "github";',
        'export const d = (x) => x.provider || "credentials";',
      ].join("\n"),
    });
    expect(ids(f, "AUTH-03")).toHaveLength(0);
  });
  it("flags a credential assigned straight to a variable (FN fix)", async () => {
    const f = await scanFiles({
      "config.ts": 'export const ADMIN_PASSWORD = "SuperSecret123!";',
    });
    expect(ids(f, "AUTH-03")).toHaveLength(1);
    expect(ids(f, "AUTH-03")[0]?.severity).toBe("high");
  });
});

describe("WEB-01 — sanitize-then-render is not flagged (FP fix)", () => {
  it("does NOT flag a sanitized value held in a variable", async () => {
    const f = await scanFiles({
      "Profile.tsx": [
        "export function Profile({ bio }){",
        "  const clean = DOMPurify.sanitize(bio);",
        "  return <div dangerouslySetInnerHTML={{ __html: clean }} />;",
        "}",
      ].join("\n"),
    });
    expect(ids(f, "WEB-01")).toHaveLength(0);
  });
  it("STILL flags a raw unsanitized value", async () => {
    const f = await scanFiles({
      "Profile.tsx":
        "export function Profile({ bio }){ return <div dangerouslySetInnerHTML={{ __html: bio }} />; }",
    });
    expect(ids(f, "WEB-01")).toHaveLength(1);
  });
});

describe("INJ-01 — Function() and string-body timers (FN fix)", () => {
  it("flags Function() without new, and setInterval with a built code string", async () => {
    const f = await scanFiles({
      "x.js": [
        'const run = Function("return " + userInput);',
        "setInterval(`${cmd}()`, 100);",
      ].join("\n"),
    });
    expect(ids(f, "INJ-01").length).toBe(2);
  });
});

describe("SEC-03 — test-file gate + convention env files (FP fix)", () => {
  it("does NOT flag a credentials file under test/fixtures, nor a .env.development", async () => {
    const f = await scanFiles({
      "test/fixtures/credentials.json": '{"user":"x"}',
      ".env.development": "PUBLIC_URL=http://localhost:3000\n",
    });
    expect(ids(f, "SEC-03")).toHaveLength(0);
  });
  it("STILL flags a bare committed .env", async () => {
    const f = await scanFiles({ ".env": "FOO=bar\n" });
    expect(ids(f, "SEC-03")).toHaveLength(1);
  });
});
