#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { basename, resolve } from "node:path";
import { ALL_CHECKS, type Grade, scan } from "@mntglobal/vibecheck-core";
import { renderHtml } from "./renderers/html.js";
import { renderMarkdown } from "./renderers/markdown.js";
import { renderSarif } from "./renderers/sarif.js";
import { renderTerminal } from "./renderers/terminal.js";

const pkg = createRequire(import.meta.url)("../package.json") as { version: string };
const VERSION = pkg.version;

const GRADE_RANK: Grade[] = [
  "F",
  "D-",
  "D",
  "D+",
  "C-",
  "C",
  "C+",
  "B-",
  "B",
  "B+",
  "A-",
  "A",
  "A+",
];

const USAGE = `vibecheck ${VERSION} — is your AI-built store secure & production-ready?

Usage:
  vibecheck <path>                     scan a local directory
  vibecheck <path> --json              machine-readable JSON (stdout)
  vibecheck <path> --sarif [file]      SARIF 2.1.0 (GitHub Code Scanning); stdout if no file
  vibecheck <path> --html <file>       write a shareable HTML report card
  vibecheck <path> --md                Markdown summary (for PR comments)
  vibecheck <path> --experimental      also run flow-tier (experimental) checks
  vibecheck <path> --experimental --offline   skip the OSV dependency lookup (no network)
  vibecheck <path> --ci --min-grade B  exit 1 if below the grade threshold

Built by MnT · https://mntfuture.com`;

function flagValue(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    console.log(USAGE);
    process.exit(args.length === 0 ? 1 : 0);
  }
  if (args.includes("--version") || args.includes("-v")) {
    console.log(VERSION);
    process.exit(0);
  }

  const minGrade = flagValue(args, "--min-grade");
  const target = args.find((a) => !a.startsWith("--") && a !== minGrade);
  if (!target) {
    console.error("error: no scan path given\n");
    console.log(USAGE);
    process.exit(1);
  }

  // A file argument for a flag: the next token, unless it's another flag or the scan path.
  const fileFor = (name: string): string | undefined => {
    const v = flagValue(args, name);
    return v && !v.startsWith("--") && v !== target ? v : undefined;
  };

  const report = await scan(resolve(target), {
    experimental: args.includes("--experimental"),
    offline: args.includes("--offline"),
  });

  // Renderers by format. Each of --json/--sarif/--md may write to a file (any number in one
  // run) or, without a file arg, print to stdout (at most one stdout format).
  const renderers: Record<string, () => string> = {
    "--json": () => JSON.stringify(report, null, 2),
    "--sarif": () => renderSarif(report, ALL_CHECKS, VERSION),
    "--md": () => renderMarkdown(report),
  };
  let stdoutFormat: string | undefined;
  for (const flag of Object.keys(renderers)) {
    if (!args.includes(flag)) continue;
    const file = fileFor(flag);
    if (file) {
      await writeFile(file, renderers[flag]?.() ?? "");
      console.error(`${flag.slice(2)} written to ${file}`);
    } else if (stdoutFormat) {
      console.error(`error: ${flag} and ${stdoutFormat} both target stdout — give one a file path`);
      process.exit(1);
    } else {
      stdoutFormat = flag;
    }
  }

  // --html always writes a file.
  if (args.includes("--html")) {
    const file = fileFor("--html");
    if (!file) {
      console.error("error: --html requires a file path, e.g. --html report.html");
      process.exit(1);
    }
    await writeFile(file, renderHtml(report, basename(resolve(target)), VERSION));
    console.error(`html written to ${file}`);
  }

  // stdout: the chosen machine format, else the human terminal report.
  console.log(stdoutFormat ? (renderers[stdoutFormat]?.() ?? "") : renderTerminal(report));

  // CI gate.
  if (args.includes("--ci")) {
    const min = (minGrade ?? "C") as Grade;
    const minIdx = GRADE_RANK.indexOf(min);
    const gotIdx = GRADE_RANK.indexOf(report.grade);
    if (minIdx >= 0 && gotIdx < minIdx) {
      console.error(`\nCI gate: grade ${report.grade} is below --min-grade ${min}`);
      process.exit(1);
    }
  }
}

main().catch((err) => {
  console.error("vibecheck failed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
