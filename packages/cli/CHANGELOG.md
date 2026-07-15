# @mntglobal/vibecheck

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

- Updated dependencies
  - @mntglobal/vibecheck-core@0.1.1

## 0.1.0

### Minor Changes

- Initial public release.

  - Deterministic engine (tree-sitter, no AI required): loader → ScanContext → pure checks → scorer.
  - 13 high-confidence structural checks: SEC-01/02/03/04, INJ-01/03, PERF-01, PROD-03, COM-02
    (the commerce flagship), AUTH-03/04, WEB-01, DEP-03.
  - Output: terminal, `--json`, `--sarif` (GitHub Code Scanning), `--html` report card, `--md`.
  - `--ci --min-grade`, `--experimental` (flow-tier checks, off by default).

### Patch Changes

- Updated dependencies
  - @mntglobal/vibecheck-core@0.1.0
