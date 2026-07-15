import { truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext } from "../types.js";
import { isTestOrExampleFile, lineAt } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#sec-02";

/** Env prefixes that are compiled into the client bundle. */
const PUBLIC_PREFIX =
  /^(?:NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|EXPO_PUBLIC_|GATSBY_|NUXT_PUBLIC_)/;
/** Name fragments that unambiguously mean "this is a secret". A bare `_KEY`/`API_KEY` is NOT here:
 * Firebase, Google Maps, reCAPTCHA site, and Algolia search keys all end in `_KEY` and are public by
 * design, so requiring a strong token (SECRET/PRIVATE/PASSWORD/TOKEN/…) avoids that whole FP class. */
const SECRET_SUFFIX = /(?:SECRET|PRIVATE|PASSWORD|PASSWD|TOKEN|CREDENTIAL|SERVICE_?ROLE)/i;
/** Keys that are meant to be public (Stripe publishable, etc.) — not a leak. */
const PUBLISHABLE = /(?:PUBLISHABLE|PUBLIC_KEY|PUBKEY)/i;
const ENV_OBJECT = /(?:process\.env|import\.meta\.env)/;

/**
 * SEC-02 (public-prefix case) — a secret referenced through a client-exposed env var, e.g.
 * `process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY`. Public-prefixed vars are compiled into the browser
 * bundle by definition, so naming a secret with one ships it to every visitor.
 */
export const sec02: Check = {
  id: "SEC-02",
  category: "secrets",
  severity: "high",
  confidence: "high",
  tier: "structural",
  title: "Secret exposed through a client-side env var",

  appliesTo: () => true,

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path)) continue;
      walk(file.tree.rootNode, (node) => {
        if (node.type !== "member_expression") return;
        const prop = node.childForFieldName("property")?.text ?? "";
        if (!PUBLIC_PREFIX.test(prop) || !SECRET_SUFFIX.test(prop) || PUBLISHABLE.test(prop))
          return;
        if (!ENV_OBJECT.test(node.childForFieldName("object")?.text ?? "")) return;

        const line = node.startPosition.row + 1;
        const key = `${file.path}:${line}`;
        if (seen.has(key)) return;
        seen.add(key);
        findings.push({
          id: "SEC-02",
          category: "secrets",
          severity: "high",
          confidence: "high",
          title: `Secret in a public-prefixed env var (${prop})`,
          file: file.path,
          line,
          column: node.startPosition.column,
          evidence: truncate(lineAt(file.text, node.startPosition.row)),
          fix: "Drop the public prefix and read the secret server-side only; never ship secrets to the client.",
          docsUrl: DOCS,
        });
      });
    }
    return findings;
  },
};
