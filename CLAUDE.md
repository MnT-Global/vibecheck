# vibecheck — Production-Readiness Auditor for AI-Built Stores

CLI + (later) hosted scanner: score an AI-generated commerce codebase for security,
commerce-logic, performance, and production-readiness. TypeScript, pnpm monorepo. MIT.
Built by MnT (mntfuture.com). Sibling of agentready. Full plan: `../VIBECHECK-BUILD-PLAN.md`.
Detection specs: `docs/rules.md`. CTO review (decisions): `docs/cto-review-r0.md`.

## Commands
- `pnpm install && pnpm test`   # vitest, fixture-driven, deterministic (no network)
- `pnpm lint` / `pnpm build`    # biome / tsup  (biome ignores dist, .next, fixtures)
- `pnpm typecheck`              # tsc --noEmit, all packages
- `pnpm dev -- <path>`          # build + run the CLI on a directory
- `pnpm record-fixture <dir> <name>`   # snapshot a repo into fixtures/

## Architecture (do not violate)
- `packages/core` = engine: loader → parse (tree-sitter) → ScanContext → checks[] → scorer → Report
- `packages/cli`  = presentation ONLY (renderers: terminal / json / sarif / html / md)
- Checks are PURE functions `(ctx) => Finding[]`. ALL I/O (walk, read, git, parse) lives in the
  loader. A check that touches the filesystem is a bug.
- New check = `src/checks/<id>.ts` + fixture tests (pass/fail) + registry entry in `checks/index.ts`
  + a `docs/rules.md` row. Weights + severities live in `scoring/` only.
- `appliesTo(ctx)` gates every check for stack-neutrality: N/A → excluded from the denominator.

## The two tiers (ADR-001 — enforced)
- **Structural** checks (tree-sitter is sufficient): `confidence: "high"`, `tier: "structural"`,
  ON by default, ship in v0.1.0.
- **Flow** checks (need cross-file/dataflow): `confidence: "medium"`, `tier: "flow"`,
  `--experimental` only, graduate per-check after passing the precision gate. Never default-on a
  check that hasn't earned it.

## Conventions
- Evidence quotes the ACTUAL code, ≤120 chars, with file:line. **Secret VALUES are always redacted**
  (`redactSecret`) — show the prefix + location only, never the full secret.
- Every finding ships a `fix` + `confidence`. HONEST output: heuristic AST analysis, not taint proof.
- **AI is never a dependency.** Core is deterministic; any AI is opt-in / BYO-key; raw code is never
  sent to a third-party AI. A build that needs an API key is a bug.
- `prove`/`perf` (live exploit) modes are DEFERRED out of v0.1 (CTO F4).
- Conventional commits; changeset for anything user-visible.

## Anchor fixtures (the regression gate)
- `fixtures/lab-before` (vendored from ai-cleanup-lab/before) → must light up findings → low grade.
- `fixtures/lab-after`  (vendored from ai-cleanup-lab/after)  → must score near-clean (A/B).
  Current: lab-before **F 40** (7 findings), lab-after **A 94** (one *true* medium — the
  `ADMIN_TOKEN || "admin-2024"` weak default; no false criticals/highs). If lab-after regresses
  below A, or gains a false critical/high, CI/tests fail.

## Shipped checks — full structural tier (13, on by default)
SEC-01 (provider secrets) · SEC-02 (secret in public-prefixed env var) · SEC-03 (committed .env) ·
SEC-04 (private keys / DB URIs) · INJ-01 (eval/new Function) · INJ-03 (command injection) ·
PERF-01 (sync I/O on hot path) · PROD-03 (error leak) · COM-02 (unvalidated quantity — commerce
flagship) · AUTH-03 (hardcoded/default creds) · AUTH-04 (permissive CORS) · WEB-01 (XSS sink) ·
DEP-03 (no tests, info).

## Flow tier (`--experimental`, medium confidence — 13 so far)
AUTH-01 (unauth sensitive route) · COM-01 (client price) · COM-04 (client discount) · INJ-02 (SQL) ·
INJ-04 (prototype pollution) · WEB-02 (SSRF) · WEB-03 (path traversal) · PERF-02 (full-file parse
per request) · PERF-03 (N+1 query in loop) · PROD-01 (no rate limiting) · PROD-04 (secret in logs) ·
DEP-01 (known-vuln deps via OSV) · DEP-02 (no security headers). Gated by `ctx.options.experimental`
via `activeChecks()`. Use

## DEP-01 & the one network exception
Everything is deterministic + offline EXCEPT DEP-01, which looks up npm advisories from **OSV**
(`api.osv.dev`). It's opt-in (`--experimental`), sends only package **names/versions** (never your
code), caches vuln details in `~/.cache/vibecheck/osv/` (offline after first run), and fails soft
(a note, no crash) when offline or under `--offline`. Loader parses the lockfile → `ctx.dependencies`
(package-lock.json v2/v3 solid; pnpm/yarn best-effort regex). `scan()` fetches advisories →
`ctx.advisories`; inject `options.advisories` to test/host without network. DEP-01 itself is a PURE
check over `ctx.advisories`.

`referencesRequestInput()` (taint-lite) for request-flow checks. The loader maps **raw node:http
routes** (`http.createServer(cb)` + `if (p === "/x")`) so AUTH-01 etc. work on manual-routing AI
code; the F8 note only fires when routing is genuinely opaque.
**Next flow checks:** AUTH-02 (IDOR), COM-03 (inventory), PROD-02, DEP-01 (OSV CVEs), SEC-01 entropy,
WEB-01 server-template (the last two are sub-cases of structural checks — need per-finding tier
gating or separate ids). Each graduates to structural only after passing the precision gate.

## Gotchas
- Block comments: never put `**/` inside a `/** ... */` JSDoc (it closes the comment early).
- Node type-stripping does NOT rewrite `.js`→`.ts` specifiers — `pnpm dev` runs the built dist.
- tree-sitter grammar WASM is resolved from the `tree-sitter-wasms` dependency at runtime.
