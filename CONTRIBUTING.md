# Contributing to vibecheck

Thanks for helping make AI-built commerce safer. This is an MnT open-source project.

## Ground rules

- **DCO sign-off, no CLA.** Sign your commits with `git commit -s` (adds a `Signed-off-by` line
  certifying the [Developer Certificate of Origin](https://developercertificate.org/)).
- **Conventional commits** (`feat:`, `fix:`, `docs:`, …) + a changeset for anything user-visible
  (`pnpm changeset`).
- Be kind — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Dev setup

```bash
pnpm install
pnpm test        # vitest
pnpm lint        # biome
pnpm typecheck
pnpm build
```

## Adding a check

Checks are **pure functions** over a pre-built `ScanContext` — no I/O inside a check.

1. Create `packages/core/src/checks/<id>.ts` exporting a `Check`.
2. Set the right `tier`: **structural** (tree-sitter is enough → high confidence, on by default) or
   **flow** (needs cross-file/dataflow → medium confidence, `--experimental` until it passes the
   precision gate). When unsure, ship it as flow.
3. Register it in `checks/index.ts`.
4. Add **pass and fail fixtures** and a test. A check without a failing-case AND a clean-case test
   won't be merged.
5. Add a row to `docs/rules.md`.
6. Quote real code in `evidence`, **redact secret values**, and always include a `fix`.

## The bar

- **No false criticals** on the clean fixtures. A finding must quote code a human can verify.
- `fixtures/lab-after` must stay near-clean (CI regression gate).
- If your check can't run on a stack, make `appliesTo` return `false` — don't emit a wrong `fail`.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please don't open public issues for vulnerabilities.
