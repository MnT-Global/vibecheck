#!/usr/bin/env node
import { resolve } from "node:path";
import { type Grade, scan } from "@mntglobal/vibecheck-core";
import { renderTerminal } from "./renderers/terminal.js";

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

const USAGE = `vibecheck — is your AI-built store secure & production-ready?

Usage:
  vibecheck <path>              scan a local directory
  vibecheck <path> --json       machine-readable output
  vibecheck <path> --experimental   also run flow-tier (experimental) checks
  vibecheck <path> --ci --min-grade B   exit 1 if below the grade threshold

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

  const target = args.find((a) => !a.startsWith("--") && a !== flagValue(args, "--min-grade"));
  if (!target) {
    console.error("error: no scan path given\n");
    console.log(USAGE);
    process.exit(1);
  }

  const report = await scan(resolve(target), {
    experimental: args.includes("--experimental"),
  });

  if (args.includes("--json")) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(renderTerminal(report));
  }

  if (args.includes("--ci")) {
    const min = (flagValue(args, "--min-grade") ?? "C") as Grade;
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
