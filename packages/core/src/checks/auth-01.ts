import type { Check, Finding, ScanContext } from "../types.js";
import { isTestOrExampleFile } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#auth-01";

/** Paths that should require authentication (excludes checkout/cart — often public). */
const AUTH_REQUIRED =
  /(^|\/)(admin|internal|orders?|users?|customers?|payments?|refunds?|settings|config|dashboard|account)(\/|$|\?|:)/i;

/** Any signal that the handler authenticates/authorizes the caller. */
const AUTH_SIGNAL =
  /\b(?:authorization|req\.user|req\.session|getServerSession|requireAuth|isAuthenticated|authenticate|authorize|bearer|jwt|passport|ADMIN_TOKEN|api[-_]?key|x-api-key|verify(?:Token|Jwt|Session|Auth)?|clerk|next-auth|lucia|withAuth|ensureAuth|checkAuth|currentUser|getToken)\b/i;

/** App-level auth middleware in the file (`app.use(requireAuth)`, etc.). */
const APP_AUTH_MW =
  /\.use\(\s*[^)]*(?:auth|passport|session|clerk|requireAuth|isAuthenticated|authenticate|jwt)/i;

export const auth01: Check = {
  id: "AUTH-01",
  category: "auth",
  severity: "critical",
  confidence: "medium",
  tier: "flow",
  title: "Sensitive route with no authentication",

  appliesTo: (ctx) => ctx.routes.some((r) => AUTH_REQUIRED.test(r.path)),

  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const route of ctx.routes) {
      if (!AUTH_REQUIRED.test(route.path) || isTestOrExampleFile(route.file)) continue;
      const file = ctx.files.find((f) => f.path === route.file);
      if (!file || APP_AUTH_MW.test(file.text)) continue; // protected by app-level middleware
      if (route.handlerNode && AUTH_SIGNAL.test(route.handlerNode.text)) continue; // handler authenticates

      const key = `${route.file}:${route.method}:${route.path}`;
      if (seen.has(key)) continue;
      seen.add(key);

      findings.push({
        id: "AUTH-01",
        category: "auth",
        severity: "critical",
        confidence: "medium",
        title: `Sensitive route ${route.method} ${route.path} has no authentication`,
        file: route.file,
        line: route.line,
        column: 0,
        evidence: `${route.method} ${route.path} — no authentication check found in the handler`,
        fix: "Require an authenticated session / bearer token and authorize the caller before responding.",
        docsUrl: DOCS,
      });
    }
    return findings;
  },
};
