import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ALL_CHECKS, scan } from "@mntglobal/vibecheck-core";
import { describe, expect, it } from "vitest";
import { renderHtml } from "../src/renderers/html.js";
import { renderMarkdown } from "../src/renderers/markdown.js";
import { renderSarif } from "../src/renderers/sarif.js";

const here = dirname(fileURLToPath(import.meta.url));
const labBefore = join(here, "../../..", "fixtures", "lab-before");

describe("renderers", () => {
  it("SARIF is valid 2.1.0 with one result per finding", async () => {
    const report = await scan(labBefore);
    const sarif = JSON.parse(renderSarif(report, ALL_CHECKS, "0.1.0"));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].tool.driver.name).toBe("vibecheck");
    expect(sarif.runs[0].tool.driver.rules.length).toBe(ALL_CHECKS.length);
    expect(sarif.runs[0].results.length).toBe(report.findings.length);
    const first = sarif.runs[0].results[0];
    expect(["error", "warning", "note"]).toContain(first.level);
    expect(first.locations[0].physicalLocation.region.startLine).toBeGreaterThan(0);
  });

  it("Markdown includes the grade and a row per finding", async () => {
    const report = await scan(labBefore);
    const md = renderMarkdown(report);
    expect(md).toContain(`Grade ${report.grade}`);
    expect(md).toContain("`SEC-01`");
    expect(md).toContain("mntfuture.com");
  });

  it("HTML is self-contained and escapes evidence (no XSS from findings)", async () => {
    const report = await scan(labBefore);
    const html = renderHtml(report, "lab-before", "0.1.0");
    expect(html).toContain("<!doctype html>");
    expect(html).toContain(report.grade);
    // the lab's `<h1>Results...` evidence must be escaped, never emitted as a live tag
    expect(html).toContain("&lt;h1&gt;");
    expect(html).not.toContain("<script>");
  });
});
