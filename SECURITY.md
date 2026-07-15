# Security Policy

## Reporting a vulnerability

Please report security issues privately to **security@mntfuture.com** — do not open a public
issue. We aim to acknowledge within 48 hours (weekdays) and will keep you updated on the fix.

## vibecheck's own security posture

vibecheck is a security tool, so it holds itself to its own bar:

- **Deterministic core, no AI dependency.** The engine needs no API key and makes no network
  calls. Your code is never sent to any third-party service by the CLI.
- **Code never leaves your machine.** The CLI reads your files locally and reports locally.
- **Secrets are redacted in all output.** Findings show a secret's provider prefix and location,
  never the full value.
- **The scanner never executes your code.** v0.1 is static analysis only. (Live exploit
  verification is a deferred, separately-reviewed, localhost-only feature — never hosted.)

We dogfood: `vibecheck` is run against its own repository in CI.
