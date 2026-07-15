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
- `packages/cli`  = presentation ONLY (terminal / json renderers)
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
DEP-03 (no tests, info). **Next: the flow tier behind `--experimental`** (COM-01/03/04, AUTH-01/02,
INJ-02, WEB-01-server, etc.), then Sprint 2 (SARIF/`--html`/`--md`) → v0.1.0.

## Gotchas
- Block comments: never put `**/` inside a `/** ... */` JSDoc (it closes the comment early).
- Node type-stripping does NOT rewrite `.js`→`.ts` specifiers — `pnpm dev` runs the built dist.
- tree-sitter grammar WASM is resolved from the `tree-sitter-wasms` dependency at runtime.
