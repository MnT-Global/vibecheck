import type { Check, Finding, ScanContext } from "../types.js";
import { looksServerSide } from "./shared.js";

const DOCS = "https://github.com/MnT-Global/vibecheck/blob/main/docs/rules.md#prod-01";

const LIMITER_DEPS = [
  "express-rate-limit",
  "@upstash/ratelimit",
  "rate-limiter-flexible",
  "@fastify/rate-limit",
  "express-slow-down",
  "hono-rate-limiter",
  "@nestjs/throttler",
];
/** Hand-rolled limiter signals (e.g. the Lab's `limited(ip)` fixed-window fn). */
const LIMITER_PATTERN = /\blimited\s*\(|rate[-_]?limit|ratelimit|throttle|slow[-_]?down/i;

export const prod01: Check = {
  id: "PROD-01",
  category: "prod",
  severity: "medium",
  confidence: "medium",
  tier: "flow",
  title: "No application-level rate limiting",

  appliesTo: (ctx) => ctx.files.some((f) => f.tree && looksServerSide(f.text)),

  run(ctx: ScanContext): Finding[] {
    const hasDep = ctx.files.some((f) => {
      if (f.lang !== "json" || !/(^|\/)package\.json$/.test(f.path)) return false;
      try {
        const p = JSON.parse(f.text) as {
          dependencies?: Record<string, string>;
          devDependencies?: Record<string, string>;
        };
        const deps = { ...p.dependencies, ...p.devDependencies };
        return LIMITER_DEPS.some((d) => d in deps);
      } catch {
        return false;
      }
    });
    const hasPattern = ctx.files.some((f) => f.tree && LIMITER_PATTERN.test(f.text));
    if (hasDep || hasPattern) return [];

    const server = ctx.files.find((f) => f.tree && looksServerSide(f.text));
    if (!server) return [];
    return [
      {
        id: "PROD-01",
        category: "prod",
        severity: "medium",
        confidence: "medium",
        title: "No rate limiter found on an exposed server",
        file: server.path,
        line: 1,
        column: 0,
        evidence: "server code present; no rate-limiting dependency or pattern detected",
        fix: "Add a rate limiter (e.g. express-rate-limit) on authentication and mutating endpoints.",
        docsUrl: DOCS,
      },
    ];
  },
};
