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
   D   50/100  · 2 files · 20ms
   1 critical

   CRITICAL  Hardcoded Stripe secret key [SEC-01]
    server.js:15
    const PAYMENT_API_KEY = "sk_live_…";
    → Move this secret to an environment variable and rotate the exposed key immediately.
```

> **Status: early (v0.1, Sprint 0).** The engine, the deterministic core, and the first check
> (SEC-01, hardcoded secrets) are live and tested. More checks land per the
> [build plan](../VIBECHECK-BUILD-PLAN.md) — each gated on a precision bar before it's on by default.

## Why

AI codegen ships fast and demos great — then leaks secrets, exposes admin routes, and trusts
client-supplied prices. Veracode's 2025 report found **45% of AI-generated code introduced an
OWASP Top-10 vulnerability.** `vibecheck` is the independent, commerce-tuned second opinion that
the AI which *wrote* the code can't reliably give.

## What it checks (growing)

8 categories, 100 points: **Secrets · Injection · Auth · Commerce-logic · Web · Performance ·
Production-hardening · Dependencies.** The commerce-logic checks (price/quantity tampering,
client-trusted totals) are the wedge no generic scanner covers.

**v0.1 ships the high-confidence, structural checks first.** Deeper flow-analysis checks ship
behind `--experimental` and graduate only after they pass a measured precision gate — because a
false "critical" is worse than none.

## How it works

- **Deterministic.** No AI required, no API key, no network. Same code = same grade → usable as a
  CI gate. (AI is an optional, opt-in power-up for later, deeper checks — never a dependency.)
- **Honest.** Every finding quotes the real code. If we can't map your framework's routes, the
  report says so — we never let "found nothing" read as "all clear."
- **Private.** The CLI runs entirely on your machine.

## Usage

```bash
npx @mntglobal/vibecheck <path>            # scan a directory
npx @mntglobal/vibecheck <path> --json     # machine-readable
npx @mntglobal/vibecheck <path> --ci --min-grade B   # exit 1 below the threshold
```

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
