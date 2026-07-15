import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { buildContext, scan } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));

describe("loader path guard — a bad target must never score A+", () => {
  it("throws on a path that does not exist", async () => {
    await expect(buildContext(join(here, "does-not-exist-xyz"))).rejects.toThrow(/path not found/);
  });

  it("throws when the target is a file, not a directory", async () => {
    // point at this very test file
    await expect(buildContext(fileURLToPath(import.meta.url))).rejects.toThrow(/not a directory/);
  });

  it("treats a URL-shaped path as a missing path (not a silent 0-file A+)", async () => {
    // mirrors the real misuse: `vibecheck ./https://github.com/x/y.git`
    await expect(buildContext(join(here, "https:", "github.com", "x", "y.git"))).rejects.toThrow(
      /path not found/,
    );
  });

  it("scans an empty directory to zero files (caller must not present a grade)", async () => {
    const empty = await mkdtemp(join(tmpdir(), "vibecheck-empty-"));
    const report = await scan(empty);
    expect(report.filesScanned).toBe(0);
  });
});
