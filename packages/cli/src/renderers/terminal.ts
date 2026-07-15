import type { Finding, Grade, Report, Severity } from "@mntglobal/vibecheck-core";
import pc from "picocolors";

const SEV_LABEL: Record<Severity, (s: string) => string> = {
  critical: (s) => pc.bgRed(pc.white(` ${s} `)),
  high: (s) => pc.red(s),
  medium: (s) => pc.yellow(s),
  low: (s) => pc.blue(s),
  info: (s) => pc.gray(s),
};

function gradeColor(grade: Grade): (s: string) => string {
  const g = grade[0];
  if (g === "A" || g === "B") return pc.green;
  if (g === "C") return pc.yellow;
  return pc.red;
}

function countBySeverity(findings: Finding[]): string {
  const order: Severity[] = ["critical", "high", "medium", "low"];
  const parts = order
    .map((sev) => ({ sev, n: findings.filter((f) => f.severity === sev).length }))
    .filter((x) => x.n > 0)
    .map((x) => SEV_LABEL[x.sev](`${x.n} ${x.sev}`));
  return parts.length ? parts.join(pc.dim(" · ")) : pc.green("no issues");
}

export function renderTerminal(report: Report): string {
  const out: string[] = [];
  const color = gradeColor(report.grade);

  out.push("");
  out.push(
    `  ${color(pc.bold(` ${report.grade} `))}  ${pc.bold(`${report.score}/100`)}  ${pc.dim(
      `· ${report.filesScanned} files · ${report.durationMs}ms`,
    )}`,
  );
  out.push(`  ${countBySeverity(report.findings)}`);
  out.push("");

  if (report.findings.length === 0) {
    out.push(pc.green("  No issues found by the checks that ran."));
  }

  for (const f of report.findings) {
    out.push(
      `  ${SEV_LABEL[f.severity](f.severity.toUpperCase())} ${pc.bold(f.title)} ${pc.dim(
        `[${f.id}]`,
      )}`,
    );
    out.push(`    ${pc.cyan(`${f.file}:${f.line}`)}`);
    out.push(`    ${pc.dim(f.evidence)}`);
    out.push(`    ${pc.dim("→")} ${f.fix}`);
    out.push("");
  }

  for (const note of report.notes) {
    const tag = note.level === "warn" ? pc.yellow("!") : pc.blue("i");
    out.push(`  ${tag} ${pc.dim(note.message)}`);
  }
  if (report.notes.length) out.push("");

  out.push(
    pc.dim(
      "  Built by MnT — we make AI-built commerce secure & production-ready.\n" +
        "  Book a free architecture workshop → https://mntfuture.com",
    ),
  );
  out.push("");
  return out.join("\n");
}
