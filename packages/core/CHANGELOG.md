# @mntglobal/vibecheck-core

## 0.1.3

### Patch Changes

- Trust milestone — the grade and the gate now tell the truth, and the loud false positives are quiet.

  This closes the top findings from vibecheck's own self-audit.

  **Scoring & CI (were: promise-defeating).**

  - A **severity floor** caps the grade by the worst finding: any `critical` now grades at most **D**, any
    `high` at most **B**. A hardcoded live secret used to grade "B" (the per-category cap clamped it) —
    it now grades D, and the CI gate catches it.
  - The `--ci --min-grade` gate now **fails closed**: an unknown or missing threshold (a typo like
    lowercase `b`, or a swallowed value) errors and exits non-zero instead of silently passing everything.

  **Secrets in `.json` / `.env` are now scanned (were: invisible).** JSON and env files have no grammar,
  so the AST-based secret scanners skipped them — a Stripe key or a `-----BEGIN PRIVATE KEY-----` in
  `config.json`, a service-account file, or a committed `.env` went undetected. SEC-01 and SEC-04 now
  also scan those as raw text (lockfiles excluded).

  **False positives quieted.**

  - SEC-04 no longer flags local-dev DB URLs (`postgres:postgres@localhost`, docker-compose defaults).
  - COM-02 no longer fires on string concatenation (`"You added " + body.quantity`) or on a quantity
    validated by a throwing schema `.parse()`.
  - AUTH-03 no longer flags auth scheme / provider constants (`token_type === "bearer"`).
  - SEC-02 no longer flags keys that are public by design (Firebase, Google Maps, reCAPTCHA, Algolia).
  - WEB-01 no longer penalizes the correct `const clean = DOMPurify.sanitize(x)` pattern.
  - SEC-03 skips test/fixture credential files and framework convention env files (`.env.development`,
    `.env.test`, …); `detectClient` recognizes Vite/CRA/Remix client directories.

  **False negatives closed.**

  - AUTH-03 now flags a credential assigned straight to a variable (`const ADMIN_PASSWORD = "…"`).
  - INJ-01 now flags `Function()` without `new` and string-body `setTimeout`/`setInterval`.

  Adds 17 precision-gate tests. Anchor fixtures unchanged (lab-before F, lab-after A, self-scan A+).
  (Standalone `.pem`/`.key` credential _files_ and the engine-robustness hardening are tracked for v0.1.4.)

## 0.1.2

### Patch Changes

- Fix PROD-03 false positives on client-side code.

  PROD-03 ("internal error detail returned to the client") flagged `err.message` flowing into any
  non-logging call. In a React/frontend file, `showErrorToast(error.message)` is ordinary UI — there
  is no HTTP response, nothing leaks, and the finding's own fix ("log server-side, return a
  correlation id") cannot apply. On a real frontend this produced a wall of false lows (one per error
  toast).

  PROD-03 now **skips client-side files** (`file.isClient`) — the check is about a _server_ leaking
  internal detail in its response, which a client file cannot do. Server handlers are unaffected:
  `res.json({ error: e.message })`, `res.end(err.stack)`, and leaks through custom response helpers
  (e.g. `send(res, 500, { error: String(e.message) })`) still fire. Verified: the lab-before anchor
  fixture is unchanged (F 40).

## 0.1.1

### Patch Changes

- Fix a dangerous false "A+" when nothing was actually scanned.

  A nonexistent path, a file (not a directory), or a remote URL passed as the target used to be
  swallowed silently — the walk yielded zero files, zero findings scored a perfect 100, and vibecheck
  printed `A+ 100/100 · 0 files`. That is the worst possible failure for a security tool: a clean bill
  of health for code it never read.

  - **Core** now fails loudly on a missing path (`path not found`) or a non-directory target
    (`not a directory`), instead of returning an ungrounded perfect score.
  - **CLI** detects a remote repo URL (or `./`-prefixed URL / `.git` suffix) and explains how to scan
    it (`git clone …` then scan the folder) rather than treating it as a missing path.
  - **CLI** refuses to present a grade when a valid folder contains no scannable source, exiting `1`
    with a clear message.

  A real `A+` now always reports the files it scanned; a no-op target always exits non-zero.

## 0.1.0

### Minor Changes

- Initial public release.

  - Deterministic engine (tree-sitter, no AI required): loader → ScanContext → pure checks → scorer.
  - 13 high-confidence structural checks: SEC-01/02/03/04, INJ-01/03, PERF-01, PROD-03, COM-02
    (the commerce flagship), AUTH-03/04, WEB-01, DEP-03.
  - Output: terminal, `--json`, `--sarif` (GitHub Code Scanning), `--html` report card, `--md`.
  - `--ci --min-grade`, `--experimental` (flow-tier checks, off by default).
