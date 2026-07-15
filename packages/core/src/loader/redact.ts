import type { SyntaxNode } from "../types.js";

/** Strip surrounding quotes/backticks from a string or template_string node's text. */
export function stringLiteralValue(node: SyntaxNode): string {
  const t = node.text;
  if (t.length >= 2) {
    const first = t[0];
    const last = t[t.length - 1];
    if ((first === '"' || first === "'" || first === "`") && last === first) {
      return t.slice(1, -1);
    }
  }
  return t;
}

/**
 * Redact a secret value: keep just enough to identify the provider, hide the rest.
 * "sk_live_MnTfixtureFAKE" -> "sk_live_…" (never print the full secret).
 */
export function redactSecret(secret: string): string {
  if (/PRIVATE KEY/.test(secret)) return "[redacted private key]";
  const keep = Math.min(8, Math.max(1, Math.ceil(secret.length / 2)));
  return `${secret.slice(0, keep)}…`;
}

/** Truncate to `max` chars with an ellipsis, collapsing runs of whitespace. */
export function truncate(s: string, max = 120): string {
  const flat = s.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

/** Build an evidence string: the code line with the secret value redacted, truncated. */
export function redactedEvidence(line: string, secret: string): string {
  const safe = line.split(secret).join(redactSecret(secret));
  return truncate(safe);
}
