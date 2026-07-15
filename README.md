# vibecheck

**Is your AI-built store secure and production-ready? Scan the code, get a graded report.**

You (or an AI) shipped a store fast. `vibecheck` reads the code the way a security reviewer
would — deterministically, in seconds — and grades it: a letter grade, a prioritized list of
issues, each anchored to the exact `file:line` with the fix. Free, MIT, and **your code never
leaves your machine.**

```bash
npx @mntglobal/vibecheck ./my-store
```

```
   F   40/100  · 2 files · 30ms
   2 critical · 3 high · 2 low

   CRITICAL  Hardcoded Stripe secret key [SEC-01]
    server.js:15
    const PAYMENT_API_KEY = "sk_live_…";
    → Move this secret to an environment variable and rotate the exposed key immediately.

   HIGH  Order quantity/amount used in pricing without validation [COM-02]
    server.js:80
    const total = prod ? prod.price * qty : 0;
    → Validate as an integer in a sane range before use.
```

> **Status: v0.1 — 13 high-confidence checks live.** Each is gated on a precision bar (zero false
> criticals on clean code) before it's on by default. Deeper flow-analysis checks ship behind
> `--experimental` and graduate the same way.

## Why

AI codegen ships fast and demos great — then leaks secrets, exposes admin routes, and trusts
client-supplied prices. Veracode's 2025 report found **45% of AI-generated code introduced an
OWASP Top-10 vulnerability.** `vibecheck` is the independent, commerce-tuned second opinion that
the AI which *wrote* the code can't reliably give.

## What it checks

8 categories, 100 points. The commerce-logic checks (price/quantity tampering, client-trusted
totals) are the wedge no generic scanner covers. v0.1 ships these **13 high-confidence checks**:

| Category | Checks |
|---|---|
| Secrets | `SEC-01` provider keys · `SEC-02` secret in a public env var · `SEC-03` committed `.env` · `SEC-04` private keys / DB URIs |
| Injection | `INJ-01` `eval`/`new Function` · `INJ-03` command injection |
| Commerce | `COM-02` unvalidated order quantity ⭐ |
| Auth | `AUTH-03` hardcoded/default creds · `AUTH-04` permissive CORS |
| Web | `WEB-01` XSS sink (`dangerouslySetInnerHTML`/`innerHTML`) |
| Performance | `PERF-01` sync I/O on the request path |
| Production | `PROD-03` internal error leaked to client |
| Dependencies | `DEP-03` no test suite (info) |

Deeper flow-analysis checks (client-trusted price, IDOR, SSRF, taint-based injection/XSS, dependency
CVEs, …) ship behind `--experimental` and graduate to on-by-default only after they pass a measured
precision gate — because a false "critical" is worse than none.

## How it works

- **Deterministic.** No AI required, no API key, no network. Same code = same grade → usable as a
  CI gate. (AI is an optional, opt-in power-up for later, deeper checks — never a dependency.)
- **Honest.** Every finding quotes the real code. If we can't map your framework's routes, the
  report says so — we never let "found nothing" read as "all clear."
- **Private.** The CLI runs entirely on your machine.

## Usage

```bash
npx @mntglobal/vibecheck <path>                  # scan a directory
npx @mntglobal/vibecheck <path> --json           # machine-readable JSON
npx @mntglobal/vibecheck <path> --sarif out.sarif  # SARIF 2.1.0 (GitHub Code Scanning)
npx @mntglobal/vibecheck <path> --html report.html # shareable HTML report card
npx @mntglobal/vibecheck <path> --md             # Markdown (for PR comments)
npx @mntglobal/vibecheck <path> --ci --min-grade B # exit 1 below the threshold
npx @mntglobal/vibecheck <path> --experimental   # also run flow-tier checks
```

## GitHub Action

Add vibecheck to any PR — it posts a summary comment, uploads findings to the
**Security → Code scanning** tab, and fails the check below a grade:

```yaml
# .github/workflows/vibecheck.yml
name: vibecheck
on: pull_request
permissions:
  contents: read
  security-events: write   # upload SARIF to code scanning
  pull-requests: write     # post the summary comment
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: MnT-Global/vibecheck@v0.1.0
        with:
          min-grade: B
          # experimental: true   # also run the flow-tier checks
```

Inputs: `path`, `min-grade`, `experimental`, `offline`, `comment`, `upload-sarif`, `version`,
`working-directory`. Outputs: `grade`, `score`.

Prefer the raw CLI in your own pipeline? Run it and upload the SARIF yourself:

```yaml
- run: npx @mntglobal/vibecheck . --sarif out.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: out.sarif }
```

Either way your code never leaves the runner — the scan is local and deterministic (the only
network call is the opt-in OSV dependency lookup, which sends package names/versions only).

## Limitations (honestly)

v0.1 is heuristic pattern + AST analysis over JS/TS, not full inter-procedural taint tracking.
It flags *likely* issues with evidence you can verify — it is not a security audit or a
certification. For deep manual review, that's what [MnT](https://mntfuture.com) does.

## Development

```bash
pnpm install
pnpm test          # vitest
pnpm lint          # biome
pnpm build         # tsup
pnpm dev -- ./fixtures/lab-before   # run the CLI locally
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT © MnT (Magizh NexGen Technologies)

---

*Built by [MnT](https://mntfuture.com) — we make AI-built commerce secure & production-ready.
[Book a free architecture workshop →](https://mntfuture.com)*
