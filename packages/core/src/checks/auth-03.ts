import { stringLiteralValue, truncate } from "../loader/redact.js";
import { walk } from "../parse/index.js";
import type { Check, Finding, ScanContext, SyntaxNode } from "../types.js";
import { isTestOrExampleFile, lineAt } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#auth-03";

/** Identifier/member names that denote a credential (not a role/flag). */
const SECRET_NAME =
  /(?:secret|token|password|passwd|pwd|api[-_]?key|apikey|auth|credential|private[-_]?key)/i;
/** Defaults that are clearly placeholders, not real credentials — not worth flagging. */
const PLACEHOLDER_DEFAULT =
  /test|dev\b|local|example|placeholder|changeme|from[-_]?env|your[-_]|dummy|xxx|sample|todo|^<.*>$/i;
/** Auth *scheme* / *type* / provider-id words — comparing to these isn't a hardcoded credential. */
const PROTOCOL_CONSTANT =
  /^(?:bearer|basic|digest|negotiate|oauth2?|openid|saml|jwt|apikey|api[-_]?key|none|null|credentials?|password|email|username|user|admin|google|github|gitlab|bitbucket|facebook|twitter|apple|microsoft|azure|okta|auth0|cognito|discord|slack|linkedin|local|ldap|token|access|refresh|id[-_]?token|access[-_]?token|refresh[-_]?token)$/i;
const EQUALITY = new Set(["===", "!==", "=="]);

function isWeakDefault(literal: string, minLen: number): boolean {
  if (PROTOCOL_CONSTANT.test(literal.trim())) return false;
  return literal.length >= minLen && !PLACEHOLDER_DEFAULT.test(literal);
}

/** Provider-formatted secrets (Stripe, AWS, GitHub, …) are SEC-01/04's job — don't double-report. */
const PROVIDER_SHAPE =
  /^(?:sk_|pk_|rk_|whsec_|AKIA|ASIA|ghp_|gho_|ghs_|github_pat_|xox[baprs]-|AIza|SG\.|ya29\.|glpat-|-----BEGIN)/;

/** Does a literal look like an actual secret value (not a role / scheme / dictionary word)? */
function looksLikeCredentialValue(v: string): boolean {
  if (v.length < 8 || PROTOCOL_CONSTANT.test(v.trim()) || PLACEHOLDER_DEFAULT.test(v)) return false;
  if (PROVIDER_SHAPE.test(v)) return false; // owned by SEC-01/SEC-04, avoid a duplicate finding
  const hasDigit = /\d/.test(v);
  const hasSpecial = /[^A-Za-z0-9]/.test(v);
  const mixedCase = /[a-z]/.test(v) && /[A-Z]/.test(v);
  return hasDigit || hasSpecial || mixedCase;
}

/** The name of an identifier, member property, or object key. */
function nameOf(node: SyntaxNode | null): string {
  if (!node) return "";
  if (node.type === "identifier" || node.type === "property_identifier") return node.text;
  if (node.type === "member_expression") return node.childForFieldName("property")?.text ?? "";
  if (node.type === "string") return node.text.replace(/^["'`]|["'`]$/g, "");
  return "";
}

export const auth03: Check = {
  id: "AUTH-03",
  category: "auth",
  severity: "high",
  confidence: "high",
  tier: "structural",
  title: "Hardcoded or default credential",

  appliesTo: () => true,

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    const push = (
      file: string,
      node: SyntaxNode,
      text: string,
      sev: "high" | "medium",
      title: string,
      fix: string,
    ) => {
      const line = node.startPosition.row + 1;
      const key = `${file}:${line}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push({
        id: "AUTH-03",
        category: "auth",
        severity: sev,
        confidence: "high",
        title,
        file,
        line,
        column: node.startPosition.column,
        evidence: truncate(lineAt(text, node.startPosition.row)),
        fix,
        docsUrl: DOCS,
      });
    };

    for (const file of ctx.files) {
      if (!file.tree || isTestOrExampleFile(file.path)) continue;
      walk(file.tree.rootNode, (node) => {
        // Case 3: a credential assigned straight to a variable / property —
        // `const ADMIN_PASSWORD = "SuperSecret123!"` / `{ apiKey: "prod-7f3a9c2b1e8d" }`.
        if (
          node.type === "variable_declarator" ||
          node.type === "assignment_expression" ||
          node.type === "pair"
        ) {
          const nameNode =
            node.childForFieldName("name") ??
            node.childForFieldName("left") ??
            node.childForFieldName("key");
          const valNode = node.childForFieldName("value") ?? node.childForFieldName("right");
          if (
            valNode?.type === "string" &&
            SECRET_NAME.test(nameOf(nameNode)) &&
            looksLikeCredentialValue(stringLiteralValue(valNode))
          ) {
            push(
              file.path,
              node,
              file.text,
              "high",
              "Hardcoded credential assigned in source",
              "Load the credential from a secret manager / environment variable; never hardcode it.",
            );
          }
          return;
        }

        if (node.type !== "binary_expression") return;
        const op = node.childForFieldName("operator")?.text ?? "";
        const left = node.childForFieldName("left");
        const right = node.childForFieldName("right");
        if (!left || !right) return;

        // Case 1: comparing a credential to a hardcoded literal — `pwd === "hunter2secret"`.
        if (EQUALITY.has(op)) {
          const litSide = left.type === "string" ? left : right.type === "string" ? right : null;
          const nameSide = left.type === "string" ? right : left;
          if (
            litSide &&
            SECRET_NAME.test(nameOf(nameSide)) &&
            isWeakDefault(stringLiteralValue(litSide), 6)
          ) {
            push(
              file.path,
              node,
              file.text,
              "high",
              "Credential compared against a hardcoded literal",
              "Never compare secrets to in-source literals; verify against a hashed value from a secret store.",
            );
          }
          return;
        }

        // Case 2: insecure fallback default — `process.env.ADMIN_TOKEN || "admin-2024"`.
        if (op === "||" && right.type === "string") {
          if (SECRET_NAME.test(nameOf(left)) && isWeakDefault(stringLiteralValue(right), 5)) {
            push(
              file.path,
              node,
              file.text,
              "medium",
              "Insecure default credential fallback",
              "Remove the fallback; fail closed if the environment variable is unset.",
            );
          }
        }
      });
    }
    return findings;
  },
};
