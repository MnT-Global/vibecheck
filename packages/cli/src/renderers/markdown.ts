import type { Report, Severity } from "@mntglobal/vibecheck-core";

const EMOJI: Record<Severity, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function counts(report: Report): string {
  const parts = SEV_ORDER.map((s) => ({
    s,
    n: report.findings.filter((f) => f.severity === s).length,
  }))
    .filter((x) => x.n > 0)
    .map((x) => `${EMOJI[x.s]} ${x.n} ${x.s}`);
  return parts.length ? parts.join(" · ") : "✅ no issues found";
}

function mdEscape(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

/** Render a Report as GitHub-flavored Markdown (for PR comments / the Action summary). */
export function renderMarkdown(report: Report): string {
  const out: string[] = [];
  out.push(`## vibecheck — Grade ${report.grade} (${report.score}/100)`);
  out.push("");
  out.push(counts(report));
  out.push("");

  if (report.findings.length > 0) {
    out.push("| | Rule | Location | Issue |");
    out.push("|---|---|---|---|");
    for (const f of report.findings) {
      out.push(
        `| ${EMOJI[f.severity]} | \`${f.id}\` | \`${mdEscape(f.file)}:${f.line}\` | ${mdEscape(f.title)} |`,
      );
    }
    out.push("");
    out.push("<details><summary>Details &amp; fixes</summary>");
    out.push("");
    for (const f of report.findings) {
      out.push(`- **${f.id}** \`${mdEscape(f.file)}:${f.line}\` — ${mdEscape(f.title)}`);
      out.push(`  - \`${mdEscape(f.evidence)}\``);
      out.push(`  - _Fix:_ ${mdEscape(f.fix)}`);
    }
    out.push("");
    out.push("</details>");
    out.push("");
  }

  for (const note of report.notes) {
    out.push(`> ${note.level === "warn" ? "⚠️" : "ℹ️"} ${mdEscape(note.message)}`);
  }
  if (report.notes.length) out.push("");

  out.push("---");
  out.push(
    "_Scanned by [vibecheck](https://github.com/MnT-Global/vibecheck) — built by " +
      "[MnT](https://mntfuture.com?utm_source=vibecheck&utm_medium=report&utm_campaign=oss). " +
      "We make AI-built commerce secure & production-ready._",
  );
  return out.join("\n");
}
