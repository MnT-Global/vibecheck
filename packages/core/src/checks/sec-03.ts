import { basename } from "node:path";
import type { Check, Finding, ScanContext } from "../types.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#sec-03";

/** Conventional, safe-to-commit env templates. */
const ENV_TEMPLATE = /\.(example|sample|template|dist|defaults)$/i;

/** Credential files that must never be committed. */
const CREDENTIAL_FILE =
  /^(?:serviceaccount.*|credentials|gcp[-_]?key.*|firebase[-_]adminsdk.*|.*\.p12|.*\.pfx|.*keystore.*)\.(json|p12|pfx)$/i;

/**
 * SEC-03 — an env/credentials file that is present and NOT git-ignored (the loader already drops
 * git-ignored files, so anything here is tracked / about to be committed).
 */
export const sec03: Check = {
  id: "SEC-03",
  category: "secrets",
  severity: "high",
  confidence: "high",
  tier: "structural",
  title: "Committed .env or credentials file",

  appliesTo: () => true,

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      const base = basename(file.path);
      const isEnv = file.lang === "env" && !ENV_TEMPLATE.test(base);
      const isCred = CREDENTIAL_FILE.test(base);
      if (!isEnv && !isCred) continue;

      findings.push({
        id: "SEC-03",
        category: "secrets",
        severity: "high",
        confidence: "high",
        title: isEnv ? "Committed .env file" : "Committed credentials file",
        file: file.path,
        line: 1,
        column: 0,
        evidence: `${base} is tracked (not git-ignored) — it likely contains live credentials`,
        fix: "Remove from git, add it to .gitignore, and rotate every secret it contained.",
        docsUrl: DOCS,
      });
    }
    return findings;
  },
};
