import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { buildContext } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const testFixtures = join(here, "fixtures");
const repoFixtures = join(here, "../../..", "fixtures");

describe("route extraction", () => {
  it("extracts Express routes with method, path, mutating + sensitivity flags", async () => {
    const ctx = await buildContext(join(testFixtures, "express-app"));
    const summary = ctx.routes.map((r) => `${r.method} ${r.path}`);
    expect(summary).toContain("GET /health");
    expect(summary).toContain("POST /admin/orders");
    expect(summary).toContain("DELETE /users/:id");

    const admin = ctx.routes.find((r) => r.path === "/admin/orders");
    expect(admin?.looksSensitive).toBe(true);
    expect(admin?.isMutating).toBe(true);

    const health = ctx.routes.find((r) => r.path === "/health");
    expect(health?.looksSensitive).toBe(false);
    expect(health?.isMutating).toBe(false);
  });

  it("extracts Next.js App Router verb handlers", async () => {
    const ctx = await buildContext(join(testFixtures, "next-app"));
    const summary = ctx.routes
      .filter((r) => r.framework === "next-app")
      .map((r) => `${r.method} ${r.path}`);
    expect(summary).toContain("GET /admin");
    expect(summary).toContain("POST /admin");
  });

  it('maps raw node:http `if (p === "/x")` routes (incl. method + sensitivity)', async () => {
    const ctx = await buildContext(join(repoFixtures, "lab-before"));
    const summary = ctx.routes.map((r) => `${r.method} ${r.path}`);
    expect(summary).toContain("GET /admin/orders");
    expect(summary).toContain("POST /checkout");
    expect(ctx.routes.find((r) => r.path === "/admin/orders")?.looksSensitive).toBe(true);
  });

  it("emits the F8 honesty note only when routes are genuinely unmappable (opaque router)", async () => {
    const ctx = await buildContext(join(testFixtures, "opaque-server"));
    expect(ctx.routes).toHaveLength(0);
    const f8 = ctx.notes.find((n) => /no routes could be mapped/i.test(n.message));
    expect(f8).toBeDefined();
    expect(f8?.level).toBe("info");
  });
});

describe("loader", () => {
  it("honors ignores and classifies files", async () => {
    const ctx = await buildContext(join(testFixtures, "express-app"));
    expect(ctx.files.some((f) => f.path === "server.js")).toBe(true);
    expect(ctx.files.every((f) => !f.path.includes("node_modules"))).toBe(true);
  });
});
