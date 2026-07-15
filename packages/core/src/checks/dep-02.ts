import type { Check, Finding, ScanContext, SourceFile } from "../types.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#dep-02";

/** Signals the app serves HTML (so CSP/headers matter). */
const HTML_SURFACE =
  /text\/html|res\.render\b|\.sendFile\s*\(|renderToString|renderToPipeableStream/;
/** Signals security headers are configured. */
const SECURITY_HEADERS =
  /\bhelmet\b|Content-Security-Policy|X-Frame-Options|Strict-Transport-Security|contentSecurityPolicy|X-Content-Type-Options/i;

export const dep02: Check = {
  id: "DEP-02",
  category: "deps",
  severity: "low",
  confidence: "medium",
  tier: "flow",
  title: "HTML served without security headers",

  appliesTo: (ctx) => ctx.files.some((f) => f.tree && HTML_SURFACE.test(f.text)),

  run(ctx: ScanContext): Finding[] {
    let htmlFile: SourceFile | undefined;
    let hasSecurity = false;
    for (const file of ctx.files) {
      if (file.tree && HTML_SURFACE.test(file.text)) htmlFile ??= file;
      if (SECURITY_HEADERS.test(file.text)) hasSecurity = true;
    }
    if (!htmlFile || hasSecurity) return [];
    return [
      {
        id: "DEP-02",
        category: "deps",
        severity: "low",
        confidence: "medium",
        title: "HTML is served with no Content-Security-Policy / security headers",
        file: htmlFile.path,
        line: 1,
        column: 0,
        evidence: "HTML response surface present; no helmet / CSP / security headers detected",
        fix: "Add helmet (or set CSP, X-Frame-Options, HSTS, X-Content-Type-Options).",
        docsUrl: DOCS,
      },
    ];
  },
};
