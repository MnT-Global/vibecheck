import type { Grade, Report, Severity } from "@mntglobal/vibecheck-core";

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function gradeColor(grade: Grade): string {
  const g = grade[0];
  if (g === "A" || g === "B") return "#16a34a";
  if (g === "C") return "#d97706";
  return "#dc2626";
}

const SEV_COLOR: Record<Severity, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#2563eb",
  info: "#6b7280",
};

const CTA = "https://mntfuture.com?utm_source=vibecheck&utm_medium=report-card&utm_campaign=oss";

/** Render a self-contained, shareable HTML report card. */
export function renderHtml(report: Report, target: string, version: string): string {
  const color = gradeColor(report.grade);

  const findingsHtml =
    report.findings.length === 0
      ? `<p class="clean">✓ No issues found by the checks that ran.</p>`
      : report.findings
          .map(
            (f) => `
      <li class="finding">
        <div class="fhead">
          <span class="sev" style="background:${SEV_COLOR[f.severity]}">${esc(f.severity.toUpperCase())}</span>
          <span class="ftitle">${esc(f.title)}</span>
          <span class="rid">${esc(f.id)}</span>
        </div>
        <div class="loc">${esc(f.file)}:${f.line}</div>
        <pre class="ev">${esc(f.evidence)}</pre>
        <div class="fix">→ ${esc(f.fix)}</div>
      </li>`,
          )
          .join("");

  const notesHtml = report.notes
    .map((n) => `<div class="note">${n.level === "warn" ? "⚠️" : "ℹ️"} ${esc(n.message)}</div>`)
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vibecheck report — ${esc(target)}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #f1f5f9; color: #0f172a;
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  .card { max-width: 760px; margin: 32px auto; background: #fff; border-radius: 16px;
    box-shadow: 0 8px 30px rgba(2,6,23,.10); overflow: hidden; }
  .top { background: #0b1f3a; color: #fff; padding: 22px 28px; display: flex;
    align-items: center; justify-content: space-between; }
  .brand { font-weight: 800; letter-spacing: -.02em; font-size: 18px; }
  .brand span { color: #7bb9f8; }
  .target { color: #cbd5e1; font-size: 13px; font-family: ui-monospace, Menlo, monospace; }
  .hero { display: flex; align-items: center; gap: 22px; padding: 26px 28px; border-bottom: 1px solid #e2e8f0; }
  .badge { width: 96px; height: 96px; border-radius: 16px; color: #fff; flex: 0 0 auto;
    display: flex; align-items: center; justify-content: center; font-size: 42px; font-weight: 800; }
  .score { font-size: 30px; font-weight: 800; }
  .meta { color: #64748b; font-size: 13px; margin-top: 2px; }
  .chips { margin-top: 8px; display: flex; flex-wrap: wrap; gap: 6px; }
  .chip { font-size: 12px; font-weight: 700; padding: 3px 9px; border-radius: 999px; color: #fff; }
  ul { list-style: none; margin: 0; padding: 8px 0; }
  .finding { padding: 16px 28px; border-bottom: 1px solid #f1f5f9; }
  .fhead { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .sev { font-size: 11px; font-weight: 800; color: #fff; padding: 2px 8px; border-radius: 6px; }
  .ftitle { font-weight: 700; }
  .rid { color: #94a3b8; font-size: 12px; font-family: ui-monospace, Menlo, monospace; }
  .loc { color: #2563eb; font-family: ui-monospace, Menlo, monospace; font-size: 13px; margin: 6px 0; }
  .ev { background: #0b1f3a; color: #e2e8f0; padding: 10px 12px; border-radius: 8px; overflow-x: auto;
    font-family: ui-monospace, Menlo, monospace; font-size: 12.5px; margin: 6px 0; }
  .fix { color: #334155; font-size: 13.5px; }
  .clean { padding: 24px 28px; color: #16a34a; font-weight: 600; }
  .note { padding: 8px 28px; color: #64748b; font-size: 13px; }
  .foot { padding: 20px 28px; background: #f8fafc; border-top: 1px solid #e2e8f0; font-size: 13px; color: #475569; }
  .foot a { color: #2563eb; font-weight: 700; text-decoration: none; }
</style>
</head>
<body>
  <div class="card">
    <div class="top"><div class="brand">vibe<span>check</span></div><div class="target">${esc(target)}</div></div>
    <div class="hero">
      <div class="badge" style="background:${color}">${esc(report.grade)}</div>
      <div>
        <div class="score">${report.score}<span style="color:#94a3b8;font-size:18px">/100</span></div>
        <div class="meta">${report.filesScanned} files · ${report.durationMs}ms · vibecheck ${esc(version)}</div>
        <div class="chips">
          ${(["critical", "high", "medium", "low"] as Severity[])
            .map((s) => ({ s, n: report.findings.filter((f) => f.severity === s).length }))
            .filter((x) => x.n > 0)
            .map(
              (x) => `<span class="chip" style="background:${SEV_COLOR[x.s]}">${x.n} ${x.s}</span>`,
            )
            .join("")}
        </div>
      </div>
    </div>
    <ul>${findingsHtml}</ul>
    ${notesHtml}
    <div class="foot">
      Built by <a href="${CTA}">MnT</a> — we make AI-built commerce secure &amp; production-ready.
      <a href="${CTA}">Book a free architecture workshop →</a>
    </div>
  </div>
</body>
</html>`;
}
