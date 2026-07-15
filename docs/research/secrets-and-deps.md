# vibecheck — Engine Inputs Research: Secrets Detection & Dependency Vulnerability Data

> Research deliverable for two concrete engine inputs:
> **Part A** — a curated secrets-detection ruleset (gitleaks/trufflehog-derived patterns + Shannon-entropy fallback).
> **Part B** — the dependency-vulnerability data source for the DEP-01 check (must work OFFLINE, MIT-compatible).
>
> **Access date for all sources: 2026-07-15.**
> **Discipline note:** Redistribution/licensing claims that could not be verified from a primary legal text are flagged **`UNVERIFIED — legal to confirm`**. Do not treat them as legal advice.

---

## Part A — Secrets detection ruleset

### A.1 Method & provenance

Patterns below are taken from the **open-source default rulesets** of two tools:

- **gitleaks** — single generated TOML ruleset (222 rules, `minVersion = "v8.25.0"` in the copy fetched). Each rule has `regex`, an optional `entropy` floor, `keywords`, and `allowlists`/`stopwords`.
  Source: `https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml` (raw: `https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml`) — accessed 2026-07-15.
- **trufflehog** — one Go detector per provider under `pkg/detectors/`, each combining a regex with (optionally) live credential **verification**.
  Source: `https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors` — accessed 2026-07-15.

Where gitleaks and trufflehog disagree, the table cites the tool the pattern was copied from. Regexes are reproduced verbatim from source so they can be transcribed into vibecheck's engine.

Severity is assigned **for a commerce app** (payment/store/cloud access weighted highest), not the tools' own wording:

| Severity | Meaning for vibecheck |
|---|---|
| **CRITICAL** | Live money/data access or full account/infra takeover (payment secret keys, cloud keys, DB creds with password, private keys). |
| **HIGH** | Strong account/service compromise (source control, email, AI spend, store admin, SMS). |
| **MEDIUM** | Context-dependent or scoped (JWTs, generic high-entropy hits, Google API keys whose scope is unknown). |
| **LOW/INFO** | Public-by-design values that are still worth surfacing (Stripe publishable key). |

### A.2 Provider secret pattern table

| # | Provider / secret type | Prefix / signature | Regex (verbatim from source) | Entropy floor | Severity | Source |
|---|---|---|---|---|---|---|
| 1 | **Stripe** secret / restricted key (`sk_live_`, `sk_test_`, `rk_live_`) | `sk_`/`rk_` + `test\|live\|prod` | `\b((?:sk\|rk)_(?:test\|live\|prod)_[a-zA-Z0-9]{10,99})(?:[\x60'"\s;]\|\\[nr]\|$)` | 2 | **CRITICAL** (live) / HIGH (test) | gitleaks `stripe-access-token` |
| 2 | **Stripe** live secret (alt, broader) | `sk_live_` / `rk_live_` | `[rs]k_live_[a-zA-Z0-9]{20,247}` | — | **CRITICAL** | trufflehog `stripe` |
| 3 | **Stripe** webhook signing secret (`whsec_`) | `whsec_` | `whsec_[a-zA-Z0-9]{32,}` *(not in gitleaks/trufflehog default; from Stripe key format — see A.3)* | ~3 | **HIGH** | Stripe docs (A.3) |
| 4 | **Stripe** publishable key (`pk_live_`) | `pk_live_` / `pk_test_` | `pk_(?:test\|live)_[a-zA-Z0-9]{10,99}` *(publishable = public by design)* | — | **LOW/INFO** | Stripe docs (A.3) |
| 5 | **AWS** access key ID | `AKIA`/`ASIA`/`ABIA`/`ACCA`/`A3T…` | `\b((?:A3T[A-Z0-9]\|AKIA\|ASIA\|ABIA\|ACCA)[A-Z2-7]{16})\b` | 3 | **CRITICAL** | gitleaks `aws-access-token` |
| 6 | **AWS** secret access key | (no prefix — 40-char base64, pair with an AKIA nearby) | idPat `\b((?:AKIA\|ABIA\|ACCA)[A-Z0-9]{16})\b` + secret `[A-Za-z0-9/+=]{40}` in context | — (entropy/context gated) | **CRITICAL** | trufflehog `aws/access_keys` |
| 7 | **GitHub** personal access token (classic) | `ghp_` | `ghp_[0-9a-zA-Z]{36}` | 3 | **HIGH** | gitleaks `github-pat` |
| 8 | **GitHub** OAuth token | `gho_` | `gho_[0-9a-zA-Z]{36}` | 3 | **HIGH** | gitleaks `github-oauth` |
| 9 | **GitHub** app / server token | `ghu_` / `ghs_` | `(?:ghu\|ghs)_[0-9a-zA-Z]{36}` | 3 | **HIGH** | gitleaks `github-app-token` |
| 10 | **GitHub** fine-grained PAT | `github_pat_` | `github_pat_\w{82}` | 3 | **HIGH** | gitleaks `github-fine-grained-pat` |
| 11 | **Google** API key | `AIza` | `\b(AIza[\w-]{35})(?:[\x60'"\s;]\|\\[nr]\|$)` | 4 | **MEDIUM–HIGH** (scope unknown) | gitleaks `gcp-api-key` |
| 12 | **OpenAI** API key (project / svc / admin / legacy) | `sk-`, `sk-proj-`, `sk-svcacct-`, `sk-admin-` (contains `T3BlbkFJ`) | `\b(sk-(?:proj\|svcacct\|admin)-(?:[A-Za-z0-9_-]{74}\|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}\|[A-Za-z0-9_-]{58})\b\|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\x60'"\s;]\|\\[nr]\|$)` | 3 | **HIGH** | gitleaks `openai-api-key` |
| 13 | **Anthropic** API key | `sk-ant-api03-` | `\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]\|\\[nr]\|$)` | — | **HIGH** | gitleaks `anthropic-api-key` |
| 14 | **Anthropic** admin key | `sk-ant-admin01-` | `\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]\|\\[nr]\|$)` | — | **HIGH** | gitleaks `anthropic-admin-api-key` |
| 15 | **Slack** bot token | `xoxb-` | `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*` | 3 | **HIGH** | gitleaks `slack-bot-token` |
| 16 | **Slack** user token | `xoxp-` / `xoxe-` | `xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}` | 2 | **HIGH** | gitleaks `slack-user-token` |
| 17 | **Slack** incoming webhook URL | `hooks.slack.com/…` | `(?:https?://)?hooks.slack.com/(?:services\|workflows\|triggers)/[A-Za-z0-9+/]{43,56}` | — | **MEDIUM** | gitleaks `slack-webhook-url` |
| 18 | **Private key block** (RSA/EC/PGP/OpenSSH/etc.) | `-----BEGIN … PRIVATE KEY-----` | `(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----` | — | **CRITICAL** | gitleaks `private-key` |
| 19 | **JWT** | `ey…` `.ey…` `.` | `\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)(?:[\x60'"\s;]\|\\[nr]\|$)` | 3 | **MEDIUM** (context) | gitleaks `jwt` |
| 20 | **npm** access token | `npm_` | `(?i)\b(npm_[a-z0-9]{36})(?:[\x60'"\s;]\|\\[nr]\|$)` | 2 | **HIGH** (supply chain) | gitleaks `npm-access-token` |
| 21 | **PostgreSQL** connection string w/ password | `postgres://` / `postgresql://` | `\b(?i)(postgres(?:ql)?)://\S+\b` (then parse `user:pass@host`) | — | **CRITICAL** (if creds embedded) | trufflehog `postgres` |
| 22 | **MongoDB** connection string w/ password | `mongodb://` / `mongodb+srv://` | `\b(mongodb(?:\+srv)?://(?P<username>\S{3,50}):(?P<password>\S{3,88})@(?P<host>[-.%\w]+(?::\d{1,5})?(?:,[-.%\w]+(?::\d{1,5})?)*)(?:/(?P<authdb>[\w-]+)?(?P<options>\?\w+=[\w@/.$-]+(?:&(?:amp;)?\w+=[\w@/.$-]+)*)?)?)(?:\b\|$)` | — | **CRITICAL** | trufflehog `mongodb` |
| 23 | **Generic JDBC** DB URI (MySQL/etc.) | `jdbc:<driver>:` | `(?i)jdbc:[\w]{3,10}:[^\s"'<>,{}[\]]{10,511}[^\s"'<>,{}[\]()&]` | — | **CRITICAL** (if creds embedded) | trufflehog `jdbc` |
| 24 | **Twilio** API key SID | `SK` + 32 hex | `SK[0-9a-fA-F]{32}` | 3 | **HIGH** | gitleaks `twilio-api-key` |
| 25 | **Twilio** Account SID (+ 32-hex auth token) | `AC` + 32 hex | sidPat `\bAC[0-9a-f]{32}\b` + auth token `\b[0-9a-f]{32}\b` | — | **HIGH** | trufflehog `twilio` |
| 26 | **SendGrid** API token | `SG.` | `\b(SG\.(?i)[a-z0-9=_\-\.]{66})(?:[\x60'"\s;]\|\\[nr]\|$)` | 2 | **HIGH** | gitleaks `sendgrid-api-token` |
| 27 | **PayPal / Braintree** OAuth client id + secret | id/secret pair | idPat `\b([A-Za-z0-9_\.]{7}-[A-Za-z0-9_\.]{72}\|[A-Za-z0-9_\.]{5}-[A-Za-z0-9_\.]{38})\b` + secret `\b([A-Za-z0-9_\.\-]{44,80})\b` | — | **HIGH** | trufflehog `paypaloauth` |
| 28 | **Shopify** admin API access token | `shpat_` | `shpat_[a-fA-F0-9]{32}` | 2 | **CRITICAL** (store admin) | gitleaks `shopify-access-token` |
| 29 | **Shopify** custom app token | `shpca_` | `shpca_[a-fA-F0-9]{32}` | 2 | **CRITICAL** | gitleaks `shopify-custom-access-token` |
| 30 | **Shopify** private app token | `shppa_` | `shppa_[a-fA-F0-9]{32}` | 2 | **CRITICAL** | gitleaks `shopify-private-app-access-token` |
| 31 | **Shopify** shared secret | `shpss_` | `shpss_[a-fA-F0-9]{32}` | 2 | **HIGH** | gitleaks `shopify-shared-secret` |

**Top ~15 for a commerce app (priority order for the default vibecheck ruleset):** (1) Stripe secret/restricted `sk_live_`/`rk_live_`; (2) Stripe webhook `whsec_`; (3) AWS access key `AKIA…` + secret; (4) DB connection strings `postgres://` / `mongodb+srv://` with embedded creds; (5) Private key blocks; (6) Shopify `shpat_`/`shpss_`; (7) GitHub tokens `ghp_`/`gho_`/`ghs_`/`github_pat_`; (8) npm token `npm_`; (9) SendGrid `SG.`; (10) Twilio `SK…`/`AC…`; (11) PayPal OAuth id+secret; (12) OpenAI `sk-`/`sk-proj-`; (13) Anthropic `sk-ant-`; (14) Slack `xox…`; (15) Google API key `AIza…`. JWT and Stripe publishable `pk_live_` round out as MEDIUM / INFO.

### A.3 Notes on Stripe `whsec_` and `pk_live_`

The gitleaks and trufflehog **defaults do not ship rules for `whsec_` (webhook signing secret) or `pk_live_` (publishable key)** — verified by grepping the fetched `gitleaks.toml` (`whsec`, `pk_live`, `publishable` → no matches) and the trufflehog `stripe` detector (`[rs]k_live_…` only). The task explicitly requires both, so:

- **`whsec_`** — the webhook endpoint secret. It IS sensitive (lets an attacker forge webhook events, e.g. fake "payment succeeded"). Format is `whsec_` + ~32+ base32/base64 chars. Suggested rule: `whsec_[a-zA-Z0-9]{32,}`, severity **HIGH**. **`UNVERIFIED — Stripe does not publish an exact charset/length spec`**; treat length/charset as approximate and gate on the `whsec_` prefix keyword. Source for prefix taxonomy: Stripe API keys docs, `https://docs.stripe.com/keys` — accessed 2026-07-15.
- **`pk_live_` / `pk_test_`** — publishable keys are **designed to ship in client-side code** and are not a leak per se. Flag as **LOW/INFO** ("publishable key committed — confirm it is intended for client use, not a mistyped secret key"). Suggested rule `pk_(?:test|live)_[a-zA-Z0-9]{10,99}`.

### A.4 Shannon-entropy fallback (generic high-entropy strings)

Prefix/keyword regexes miss **unknown or custom** secrets. Both tools add an entropy layer; vibecheck should mirror this as a **low-confidence, context-gated** fallback.

**How gitleaks does it.** Each rule can set an `entropy` floor = "the minimum Shannon entropy a regex group must have to be considered a secret" (gitleaks README, accessed 2026-07-15). The catch-all `generic-api-key` rule pairs a keyword-anchored regex (`access|api|auth|credential|creds|key|passwd|password|secret|token` … `= "…"`) with **`entropy = 3.5`** on the captured value — i.e. it only fires when a value is *both* assigned to a secret-looking variable *and* high-entropy. Source: `gitleaks.toml` `generic-api-key` rule — accessed 2026-07-15.

**How the classic trufflehog does it.** The original entropy engine scans every base64/hex run **>20 chars** and flags on Shannon entropy thresholds: **base64 strings > 4.5 bits/char**, **hex strings > 3.0 bits/char**. Source: legacy truffleHog (`dxa4481/truffleHog`, `truffleHog/truffleHog.py`, `BASE64_CHARS`/`HEX_CHARS` with `> 4.5` / `> 3` checks) — accessed 2026-07-15; secondary summary: AquilaX, "Detecting Obfuscated Malware in Source Code", `https://aquilax.ai/blog/obfuscated-malware-source-code-detection` — accessed 2026-07-15.

**Why those numbers (and a sensible threshold for vibecheck).** Shannon entropy `H = -Σ p·log2(p)` bits/char. Max entropy is charset-dependent: hex (16 symbols) → `log2(16) = 4.0`; base64 (64 symbols) → `log2(64) = 6.0`. The classic thresholds sit at ~75% of max (`3.0/4.0`, `4.5/6.0`). **Recommended vibecheck defaults:**

- Candidate tokens: contiguous `[A-Za-z0-9+/=_-]{20,}` runs.
- Flag **base64-like ≥ 4.5 bits/char**, **hex-like ≥ 3.0 bits/char** (align with the classic tool).
- Emit only at **MEDIUM** severity, and **only when context-gated** (token assigned to a `key|secret|token|password|credential|api…` identifier, à la gitleaks `entropy = 3.5`). Pure free-floating high-entropy strings → suppress or downgrade to INFO to keep the false-positive rate acceptable for AI-generated code (which is full of hashes, base64 assets, and minified blobs).

### A.5 False-positive reduction

Adopt gitleaks' layered allowlist model (README + `gitleaks.toml`, accessed 2026-07-15):

1. **Path allowlist** — skip lockfiles, `node_modules/`, `vendor/`, minified `*.min.js`, images/fonts/binaries, `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`. (gitleaks global `[allowlist].paths`.)
2. **Stopwords on the *extracted secret*** (not the whole match) — gitleaks ships a large stopword list (e.g. `000000`, `aaaaaa`, `example`, `xxxxxx`, dictionary words) plus a global `abcdefghijklmnopqrstuvwxyz`. Reject obvious dummies.
3. **Placeholder / dummy regexes** — drop values that are clearly not real: `sk_live_xxx`, `your-key-here`, `<your_api_key>`, `changeme`, `example`, `dummy`, `test`, all-same-char, `^[a-zA-Z_.-]+$` (gitleaks' `generic-api-key` allowlist rejects pure-word matches). trufflehog's `mongodb` detector similarly discards passwords matching `^[xX]+|\*+$`.
4. **Inline ignore** — honor a `gitleaks:allow`-style comment / `vibecheck-ignore` pragma for knowingly-committed test fixtures.
5. **Verification (optional, opt-in, online only)** — trufflehog's headline FP-killer is live credential verification. vibecheck is offline-first, so keep this **off by default**; optionally offer `--verify` later. Cite trufflehog verification design: `https://github.com/trufflesecurity/trufflehog` — accessed 2026-07-15.

---

## Part B — Dependency vulnerability data source (DEP-01)

### B.1 Requirement

DEP-01 flags known-vulnerable npm dependencies. Hard constraints: (a) **works fully offline** from a snapshot bundled per release; (b) **redistributable inside an MIT-licensed CLI** — licensing is the deciding constraint; (c) good **npm coverage**; (d) a **format we can match against `package-lock.json`** offline.

### B.2 Candidate comparison

| Source | License / redistribution | Format & bundleable? | npm coverage | Offline query | Verdict |
|---|---|---|---|---|---|
| **OSV.dev** (Google) | **Per-source**, all OSS/public-domain: npm records come from GHSA = **CC-BY 4.0**; other ecosystems CC0/MIT/Apache/BSD. Attribution required, redistribution allowed. | **OSV JSON schema**; full DB or per-ecosystem snapshot at `gs://osv-vulnerabilities/all.zip` and `…/<ECOSYSTEM>/all.zip` (e.g. `npm/all.zip`), also over HTTPS. **Purpose-built to bundle.** | Aggregates GHSA (the npm source of truth) → **≈ npm audit for npm**, plus more ecosystems. | **First-class.** OSV-Scanner ships `--offline` / `--download-offline-databases`; local layout `{db}/osv-scanner/npm/all.zip`. | ✅ **RECOMMENDED** |
| **GitHub Advisory Database (GHSA)** | **CC-BY 4.0** (repo README). Redistribution allowed with attribution. | **OSV format**, one JSON file per advisory in a **git-cloneable repo** → snapshot-able, but you build your own matcher. | **Source of truth for npm** (contains the full npm advisory corpus; powers `npm audit`). | No official matcher — you'd write range-matching yourself over the cloned files. | ✅ Strong upstream / fallback |
| **npm audit / registry advisory API** | Data = GHSA (CC-BY 4.0) underneath, but delivered via the **npm registry Bulk Advisory API** (`POST /-/npm/v1/security/advisories/bulk`), an **online service** governed by npm/GitHub registry ToS — **not designed for snapshotting/redistribution**; legacy endpoints being retired. | JSON API responses, **not a downloadable corpus**. | Full npm (same GHSA data). | ❌ Requires network per run; no supported offline bundle. | ❌ Fails offline constraint |
| **Snyk DB** | **Proprietary.** Commercial DB; redistribution/bundling not permitted for a free OSS tool. | Closed; API access gated by commercial terms. | Excellent (proprietary research). | ❌ Not redistributable. | ❌ Unusable for MIT OSS |

Sources (all accessed 2026-07-15): OSV data & per-source licenses — `https://google.github.io/osv.dev/data/`; OSV-Scanner offline mode — `https://google.github.io/osv-scanner/usage/offline-mode/`; GHSA license/format — `https://github.com/github/advisory-database`; GHSA powers npm audit — `https://github.blog/security/supply-chain-security/github-advisory-database-now-powers-npm-audit/`; npm audit bulk endpoint — `https://docs.npmjs.com/cli/v11/commands/npm-audit/`; Snyk DB — `https://snyk.io/product/vulnerability-database/`.

### B.3 Recommendation — **OSV.dev (npm ecosystem subset), primary**

Bundle the **`npm/all.zip` OSV snapshot per release** and match it against `package-lock.json` offline. Reasoning:

1. **Licensing (the deciding constraint).** OSV npm data inherits **CC-BY 4.0** from GHSA — an **attribution-only** license, fully compatible with shipping inside an **MIT** tool: vibecheck's code stays MIT, the bundled data stays CC-BY 4.0, and we satisfy CC-BY by adding an attribution/`NOTICE` line ("Vulnerability data from OSV.dev / GitHub Advisory Database, CC-BY 4.0"). No copyleft reaches our code. Other bundled ecosystems are CC0/MIT/Apache/BSD — all permissive. Contrast: **Snyk is proprietary (excluded)**; the **npm registry API** is an online service, not a redistributable corpus.
2. **Purpose-built offline story.** OSV publishes a ready-to-bundle `npm/all.zip`; OSV-Scanner already demonstrates the exact `--offline` pattern we need, so we can vendor the same snapshot and refresh it in CI each release.
3. **Coverage.** OSV **aggregates GHSA**, which is the source of truth that powers `npm audit` — so we match `npm audit`'s npm coverage without depending on its online API, and gain a clean, versioned schema.
4. **Format.** The **OSV JSON schema** gives structured `affected` ranges per package → straightforward semver range-matching against the lockfile's resolved versions, no scraping.

**Fallback / equivalent:** clone **GHSA** directly (same CC-BY 4.0, same OSV format) if we ever want to drop the aggregation layer — it is the identical npm corpus one hop upstream.

**`UNVERIFIED — legal to confirm`:** (a) the exact CC-BY 4.0 attribution wording/placement required when we bundle the `all.zip` snapshot in a released npm package; (b) whether any individual OSV *record* carries a non-CC-BY source license we must attribute separately (OSV is per-source — an npm-only snapshot should be GHSA/CC-BY, but confirm no mixed-license records slip into the npm ecosystem export); (c) that GitHub's registry ToS is not implicated once we take data via OSV rather than the npm API. Have legal confirm before first release.

---

## Appendix — Source list (all accessed 2026-07-15)

**Part A**
- gitleaks default ruleset (TOML, `minVersion v8.25.0`): https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
- gitleaks README (entropy, allowlists, stopwords): https://github.com/gitleaks/gitleaks/blob/master/README.md
- trufflehog detectors index: https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors
  - Stripe: https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/stripe/stripe.go
  - AWS: https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/aws/access_keys/accesskey.go
  - MongoDB: https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/mongodb/mongodb.go
  - Postgres: https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/postgres/postgres.go
  - JDBC: https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/jdbc/jdbc.go
  - PayPal OAuth: https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/paypaloauth/paypaloauth.go
  - Shopify: https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/shopify/shopify.go
  - Twilio: https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/twilio/twilio.go
- trufflehog (verification design): https://github.com/trufflesecurity/trufflehog
- Legacy truffleHog entropy thresholds (base64 > 4.5, hex > 3.0): https://github.com/dxa4481/truffleHog
- Entropy-threshold secondary reference: https://aquilax.ai/blog/obfuscated-malware-source-code-detection
- Stripe API keys / prefix taxonomy (`sk_`, `pk_`, `rk_`, `whsec_`): https://docs.stripe.com/keys

**Part B**
- OSV data sources, per-source licenses & bulk download: https://google.github.io/osv.dev/data/
- OSV-Scanner offline mode: https://google.github.io/osv-scanner/usage/offline-mode/
- OSV project: https://github.com/google/osv.dev
- GitHub Advisory Database (CC-BY 4.0, OSV format): https://github.com/github/advisory-database
- GHSA now powers npm audit: https://github.blog/security/supply-chain-security/github-advisory-database-now-powers-npm-audit/
- npm audit (bulk advisory endpoint): https://docs.npmjs.com/cli/v11/commands/npm-audit/
- Snyk Vulnerability Database (proprietary): https://snyk.io/product/vulnerability-database/
