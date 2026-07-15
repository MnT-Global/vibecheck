# @mntglobal/vibecheck

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
