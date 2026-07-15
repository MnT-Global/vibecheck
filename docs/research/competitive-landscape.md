# Competitive Landscape: Static-Analysis / Code-Scanning Tools vs. vibecheck

**Purpose:** Rigorous competitive teardown of the existing static-analysis / code-scanning landscape, so MnT can position **vibecheck** (a production-readiness + commerce-logic security auditor for AI-generated JS/TS e-commerce codebases) *adjacent* to the incumbents rather than head-on.

**Research date / access date for all sources:** 2026-07-15
**Author:** Competitive research pass (agent-assisted)

---

## 0. Source-confidence discipline

- **[PRIMARY]** = vendor's own docs / repo / pricing page, or the tool's source tree.
- **[SECONDARY]** = third-party blog, benchmark, or aggregator. Directionally useful, not authoritative.
- **[UNVERIFIED]** = could not confirm against a primary source; flagged explicitly.

Every factual claim below carries a source tag and a URL (see the Sources section). Where an incumbent *does* have some business-logic coverage, that is stated plainly — the goal is an honest map, not a flattering one.

---

## 1. Executive summary (the one-paragraph version)

The mature code-scanning market (Semgrep, Snyk Code, SonarQube, CodeQL) is built around **taint analysis of well-known OWASP vulnerability classes** — injection, XSS, path traversal, deserialization, crypto misconfig — plus secrets (gitleaks/trufflehog own that niche). Their rule taxonomies are organized **by language and by CWE/OWASP category, not by domain**. Across the incumbents, **e-commerce business-logic checks (price/quantity/discount tampering, client-trusted totals, order-level IDOR) are essentially absent from the shipping rule sets**, and the vendors say so: CodeQL's own limitation notes call out business-logic flaws as out of scope, and Semgrep's *only* route to IDOR/broken-authorization detection is a **paid, AI-hybrid, private-beta feature announced Nov 2025** — and even that targets *generic* route-auth IDOR, not commerce-semantic price/qty tampering. The new wave of "vibe-coding security" scanners (vibe-audit, AquilaX Vibe, VibeSecurity, Vibe App Scanner) correctly target AI-codegen *patterns* (hardcoded keys client-side, missing auth on generated routes) but **none check commerce logic**, and the credible ones are either immature OSS or closed SaaS. **That domain gap — commerce-logic bugs in AI-generated JS/TS storefronts, checked at the source, in an OSS tool with a founder-readable report — is vibecheck's wedge.** Where vibecheck should *not* pick a fight: cross-file taint-analysis depth and breadth, where Semgrep Pro / Snyk Code / CodeQL are years ahead.

---

## 2. Per-tool teardown

### 2.1 Semgrep (Community Edition / OSS + AppSec Platform + Registry)

**What it is:** Pattern-based SAST. Rules are YAML with metavariables/ellipsis that mirror the target code, downloaded from the Semgrep Registry. [PRIMARY: semgrep.dev, github.com/semgrep/semgrep-rules]

**Rule categories / taxonomy:** Rules in `semgrep-rules` are organized **by language** (the repo's top-level dirs are `ai, apex, bash, c, csharp, dockerfile, elixir, generic, go, html, java, javascript, json, kotlin, ocaml, php, python, ruby, rust, scala, solidity, swift, terraform, typescript, yaml`, plus `package_managers`, `problem-based-packs`). [PRIMARY: GitHub Contents API, semgrep-rules, 4,909 files in tree]. Rulesets are then mapped to **OWASP Top 10 / CWE Top 25** (`p/default`, `p/security-audit`, `p/owasp-top-ten`). [SECONDARY: docs summaries]

**Does it have ANY e-commerce / business-logic rules?** I grepped the **entire 4,909-file rule tree** for `price|cart|checkout|ecommerce|payment|discount|quantity|coupon|refund|invoice|order|mass|idor|bola|broken-access|authz`. Findings [PRIMARY: git trees API, semgrep-rules, accessed 2026-07-15]:
  - **Mass assignment:** exists, but ONLY for `csharp/dotnet/.../mass-assignment`, `python/django/.../mass-assignment`, `ruby/lang/.../unprotected-mass-assign`. **No JavaScript/TypeScript mass-assignment rule.** These are *framework-mechanical* (detecting unsafe binding of request params to a model), not commerce-semantic.
  - **"price":** the only hits are `solidity/security/oracle-price-update-not-restricted` — i.e. **DeFi smart-contract oracle manipulation**, not web-app checkout price.
  - **"checkout":** the only hits are `yaml/github-actions/.../pull-request-target-code-checkout` — i.e. **CI code checkout**, unrelated to shopping checkout.
  - **Broken authorization:** only `csharp/dotnet/.../missing-or-broken-authorization` and Solidity access-control rules. **No JS/TS order-IDOR / BOLA rule.**
  - **Zero rules** for cart, coupon, discount, refund, invoice, negative quantity, or client-trusted totals in a web-app context.
  - **Conclusion:** Semgrep OSS ships **no e-commerce business-logic rules for JS/TS.** Its nearest analogues are .NET/Django/Rails mass-assignment and Solidity DeFi rules — neither covers a Node/Express/Next.js storefront trusting a client-supplied price.

**Semgrep's IDOR / business-logic story (important nuance — do NOT overstate the gap):** Semgrep announced (blog dated **Nov 11, 2025**) an **AI-hybrid IDOR / broken-authorization / access-control detector** that enumerates routes and uses the Pro Engine + an LLM to flag handlers missing `requireAuth`/`checkPermissions`. Reported ~61% precision, "80% of participants uncovered real IDORs." **It is a PAID feature, in PRIVATE BETA, not in OSS**, and it targets *generic* route-auth IDOR — **not** commerce-semantic price/qty/discount tampering. [PRIMARY: semgrep.dev/blog/2025/ai-powered-detection-with-semgrep/]

**OSS vs paid split** [PRIMARY: docs.semgrep.dev/semgrep-pro-vs-oss]:
  - **Free (Community Edition):** single-file analysis, single-function taint + cross-function *constant propagation within a file*, community rules, **custom-rule authoring (identical to paid)**, IDE + pre-commit, SARIF output.
  - **Paid (AppSec Platform):** cross-file / cross-function taint, ~20k+ **Pro Rules** (Security Research team), **Semgrep Secrets** (validation + historical), **Supply Chain (SCA)** w/ reachability, **Assistant** (AI triage). **Team = $35/contributor/mo** [PRIMARY: semgrep.dev/pricing]. Note: Semgrep Code + Supply Chain are **free up to 10 contributors / 10 private repos**.
  - Third-party benchmark [SECONDARY, treat cautiously]: OSS CLI ~44–48% vuln detection vs Pro ~72–75% — the delta is the cross-file taint engine.

**Custom rules easy to write?** Yes — YAML pattern rules "5–10× shorter than ESLint/AST equivalents," and authoring is **identical in the free tier**. [SECONDARY: aicodereview.cc; consistent with PRIMARY docs]. **This matters for vibecheck: our commerce-logic checks could theoretically be authored as custom Semgrep rules — which is a "why not just Semgrep?" objection we must answer (see §6).**

**SARIF / GitHub Action:** Yes — `semgrep --sarif`, official GitHub Action. [PRIMARY]
**Targets AI-codegen patterns specifically?** No — general SAST (markets "AI-assisted" triage, but detection is not AI-codegen-pattern-aware).

---

### 2.2 Snyk Code (SAST)

**Detection categories:** SQL injection, XSS, command injection, path traversal, insecure authentication, plus **hardcoded secrets flagged inside SAST**. Semantic dataflow engine (ex-DeepCode) that traces taint **across multiple files**. [SECONDARY: appsecsanta.com/snyk-code, snyk.io]

**Business-logic coverage?** **None mentioned** anywhere on the plans page or in the category surveys. Snyk positions business-logic testing under **DAST** (runtime), not Snyk Code (SAST). [PRIMARY: snyk.io/plans — no business-logic mention; SECONDARY: startuphub survey confirms "No"]

**OSS vs paid:** Closed-source SaaS. **Free** = $0, **100 Snyk Code tests/month**; **Team** = $25/dev/mo (1,000 tests); **Ignite** ≈ $1,260/dev/yr (unlimited); **Enterprise** custom. [PRIMARY: snyk.io/plans]

**SARIF / GitHub Action:** Yes — `snyk code test --sarif-file-output=results.sarif`; official Action. [SECONDARY, but well-documented]
**Targets AI-codegen specifically?** Marketed as "tuned for machine-generated code" [SECONDARY: startuphub], but underlying categories are the generic OWASP set. Not commerce-aware.

---

### 2.3 SonarQube / SonarQube Cloud (formerly SonarCloud)

**Rule taxonomy:** Four issue types — **Bugs, Code Smells** (quality-first heritage), **Vulnerabilities, Security Hotspots**. Security rules split into **security-injection** (SQLi, deserialization, command injection) and **security-configuration** (bad crypto/TLS params, missing/misordered checks). **Hotspots** = security-sensitive code needing *manual review* (e.g., cookie `HttpOnly`), ranked by OWASP Top 10 / CWE Top 25; Sonar is gradually converting hotspots → vulnerabilities. [PRIMARY: docs.sonarsource.com — security-related-rules, security-hotspots]

**Business-logic / commerce coverage?** None. Sonar is fundamentally a **code-quality + injection/config** engine; no price/qty/order-IDOR rules. [PRIMARY docs taxonomy implies; SECONDARY confirms]

**OSS vs paid:** **Community Build** is free & open source — binaries under **LGPLv3**, but **bundled analyzers moved to the "Sonar Source-Available License v1.0 (SSALv1)" as of 29 Nov 2024** (source-available, not OSI-open). Branch analysis + PR decoration are **paid (Developer Edition, ~$15k+ perpetual / priced per million LOC)**. [PRIMARY: sonarsource.com/license, open-source-editions; SECONDARY: pricing aggregators]

**SARIF / GitHub Action:** **Imports** external SARIF (to ingest third-party analyzer results); native GitHub **PR decoration is a paid feature**, and community Actions exist to convert Sonar findings → SARIF for GitHub's security tab. So: SARIF *import* yes, first-class SARIF *export* to GitHub is not the free-tier default. [SECONDARY: GitHub Marketplace actions, Sonar community threads]
**Targets AI-codegen specifically?** Markets "AI Code Verification" but rules are generic.

---

### 2.4 gitleaks (secrets)

**Detection:** Secrets only — passwords, API keys, tokens — via **regex rules + Shannon entropy**. Fast, offline, single Go binary; ideal pre-commit. **Explicitly does nothing beyond secrets** (no vulns, no business logic). [PRIMARY: github.com/gitleaks/gitleaks]
**OSS vs paid:** **MIT**, fully open source, ~28k stars, no commercial CLI tier. [PRIMARY]
**SARIF / Action:** Yes — output formats json, csv, junit, **sarif**; widely used as a GitHub Action. [PRIMARY]
**Commerce logic / AI-codegen?** No / No.
**Overlap with vibecheck:** This is the one category (secrets) where vibecheck overlaps a best-in-class free tool. We should **not** claim to beat gitleaks on secrets breadth.

---

### 2.5 trufflehog (secrets, verified)

**Detection:** Secrets with **live verification** — **800+ detectors**, makes real API calls to confirm a credential is *currently active* (kills the revoked-key false-positive class). Scans git, S3, Docker, Slack, Jenkins, filesystems. [PRIMARY: github.com/trufflesecurity/trufflehog]
**OSS vs paid:** **AGPL-3.0** since v3 (open-core; Truffle Security sells enterprise). [PRIMARY/SECONDARY]
**SARIF / Action:** Output JSON, **SARIF**, CLI; official GitHub Action. [SECONDARY]
**Benchmark:** ~94% of *active* credentials detected in a 2025 real-world test. [SECONDARY: appsecsanta]
**Commerce logic / AI-codegen?** No / No.
**Overlap with vibecheck:** Same as gitleaks — trufflehog's verification is a moat on secrets. vibecheck's secrets check should be "table-stakes hygiene," not a headline.

---

### 2.6 GitHub CodeQL / Code Scanning

**Detection:** Whole-program **semantic dataflow / taint** ("treat code as data"), CWE-mapped queries. Deepest, most-published coverage for **Java, C/C++**; also C#, Go, JS/TS, Python, Ruby, Rust, Swift, Kotlin, GitHub Actions. **Does not support PHP, Scala.** [PRIMARY: docs.github.com — about-code-scanning-with-codeql]

**Business-logic limits (stated):** CodeQL is documented/understood to be **weak on business-logic vulnerabilities ("requires domain knowledge"), race conditions, and runtime-only bugs.** [SECONDARY: securityscientist.net — but consistent with GitHub's own framing that CodeQL finds pattern-expressible vulns, not domain rules]. **No commerce-logic queries** in the standard packs.

**OSS vs paid:** **Free for PUBLIC repos** (code scanning on by default). **Private/commercial repos require GitHub Code Security** (the former GHAS, split out Apr 1 2025) at **$49/active-committer/mo**. The `github/codeql` **query packs are open source (MIT/Apache)**, but the **CodeQL CLI/engine license restricts free use to public repos + research** — i.e., the *queries* are open, the *commercial engine use* is paid. [PRIMARY: docs.github.com/about-github-advanced-security, github.blog changelog 2025-03-04; SECONDARY: pricing aggregators]

**SARIF / Action:** **Native SARIF 2.1.0** — CodeQL is effectively the reference producer, and GitHub Code Scanning **ingests SARIF from any third-party tool** (this is the integration surface vibecheck should plug into). [PRIMARY: docs.github.com/sarif-support-for-code-scanning]
**Targets AI-codegen specifically?** No (Copilot Autofix does AI *remediation* of alerts, but detection isn't AI-codegen-pattern-aware).

---

### 2.7 The new wave: "AI-code / vibe-coding" security scanners (2025–2026)

This is the category vibecheck is *nearest* to — and the most important to differentiate from.

| Tool | Source vs runtime | OSS/paid | Commerce logic? | AI-codegen-aware? | Notes |
|---|---|---|---|---|---|
| **vibe-audit** (github.com/ApacheWang/vibe-audit) | Source | **MIT / OSS** | **No** | **Yes (explicit)** | 7 categories: secrets, injection, auth, config, deps, API security, data exposure. **No SARIF.** Extremely immature: **1 commit, 0 stars** at access. [PRIMARY] |
| **AquilaX Vibe** (aquilax.ai/vibe) | Source | **Paid SaaS** (Ultimate plan) | **No** | **Yes** — "AI origin detection," insecure defaults (JWT `alg:none`, permissive CORS), unsafe `eval`/pickle, hardcoded secrets | On-prem + 14-day trial; pricing undisclosed. [PRIMARY] |
| **VibeSecurity** (vibesecurity.net) | Runtime agents | Paid SaaS | No | Yes | "Real-time vulnerability scanning… detect and fix." [SECONDARY] |
| **Vibe App Scanner / `vas`** (vibeappscanner.com) | **Runtime (live app)** | Paid/freemium | No | Yes | Scans the *running* app, returns AI-applyable fix list via MCP. Not a source scan. [SECONDARY] |
| **Lovable "Security Scan"** | In-platform (LLM) | Bundled | No | Yes | LLM-based, inside the Lovable builder. [SECONDARY] |
| **Strix** (AI pentest) | **Runtime/DAST** | — | **Yes-ish** (finds negative-price race conditions, sequential-order IDOR *dynamically*) | Partly | Confirms commerce-logic bugs are found by **runtime AI-pentest**, needs a *running* app — not a CI source scan. [SECONDARY: coddykit, escape.tech] |

**Market survey [SECONDARY: startuphub.ai "20 AI security tools for vibe-coded apps 2026"]:** of 20 tools, **zero** check commerce/business logic; all are runtime/identity/network/quality SaaS. Only ~5 are "AI-native" (Snyk Code, Grego AI, Hunters, Abnormal), and those do generic vuln/threat detection.

**Why-now market context (for the pitch, not the teardown) [SECONDARY]:** Veracode found ~45% of AI-generated code contains vulnerabilities (>70% for Java); Georgia Tech scanned 43,000+ advisories on vibe-coded output; one survey of 5,600 vibe-coded apps found 2,000+ vulnerabilities, 400+ exposed secrets, 175 PII exposures. The problem is real and growing; the *commerce-logic* slice of it is unowned.

---

## 3. Comparison table (tools × coverage)

Legend: **Yes** = shipping, first-class · **Partial** = exists but shallow / framework-only / paid-gated · **No** = not covered · **(beta/paid)** noted inline.

| Tool | Secrets | Injection (SQLi/XSS/cmd) | Auth / access-control | **Commerce-logic** (price/qty/discount, order-IDOR) | AI-codegen-aware | OSS / free tier | SARIF |
|---|---|---|---|---|---|---|---|
| **Semgrep CE (OSS)** | Partial (pattern only; validation is paid) | Yes (single-file) | Partial (generic; deep IDOR is paid beta) | **No** (no JS/TS rules) | No | **Yes** (Semgrep Rules License) | **Yes** |
| **Semgrep AppSec (paid)** | Yes (validated) | Yes (cross-file taint) | Yes + **AI-IDOR (private beta)** | **No** (generic IDOR only, not commerce) | Marketed only | Partial free ≤10 devs | Yes |
| **Snyk Code** | Yes (in SAST) | Yes (cross-file dataflow) | Partial (generic) | **No** | Marketed only | Free (100 tests/mo) | Yes |
| **SonarQube CE** | Partial | Yes | Partial (hotspots/config) | **No** | No | **Yes** (LGPL + SSALv1 analyzers) | Import only |
| **gitleaks** | **Yes** (regex+entropy) | No | No | **No** | No | **Yes (MIT)** | Yes |
| **trufflehog** | **Yes** (verified, 800+) | No | No | **No** | No | **Yes (AGPL)** | Yes |
| **CodeQL / Code Scanning** | Separate product | Yes (whole-program) | Partial (generic) | **No** (docs: business logic out of scope) | No | Free public repos; paid private | **Native** |
| **vibe-audit** | Yes | Yes (regex) | Partial (missing-auth heuristic) | **No** | **Yes** | **Yes (MIT)** | No |
| **AquilaX Vibe** | Yes | Yes | Insecure-defaults | **No** | **Yes** | No (SaaS) | UNVERIFIED |
| **→ vibecheck (target position)** | Yes (hygiene, overlaps) | Heuristic (not a taint engine) | Heuristic (route-level) | **YES — the wedge** | **Yes (explicit)** | **Yes (OSS)** | Recommended: **Yes** |

*vibecheck's row is the **intended** position, not a shipped claim. SARIF is a recommendation, not a current capability assertion.*

---

## 4. THE GAP vibecheck FILLS (honest and specific)

**Where the incumbents genuinely do not look.** Every mature source scanner is organized around *language × CWE/OWASP class* and around *taint from an untrusted source to a dangerous sink*. Commerce-logic bugs don't fit that shape: a `total = req.body.total` in a Next.js API route is **syntactically clean, well-typed, injection-free, and secret-free** — it trips no injection rule, no secrets rule, no config rule. Confirmed by direct inspection: Semgrep's 4,909-rule tree has **no JS/TS rule** for price/qty/discount/cart/order-IDOR (its "price" rules are Solidity DeFi; its mass-assignment rules are .NET/Django/Rails only); CodeQL's own limitations put business logic out of scope; SonarQube and Snyk Code ship no commerce rules; gitleaks/trufflehog are secrets-only. The one incumbent moving toward logic flaws — **Semgrep's AI-hybrid IDOR detector — is paid, private-beta (Nov 2025), and generic** (route auth), not commerce-semantic. Meanwhile the tools that *do* catch price/negative-quantity/order-IDOR bugs are **manual pentesters/bug-bounty and runtime AI-pentest/DAST tools (e.g. Strix)** that need a *deployed, running* app. **No one is checking commerce logic at the source, in CI, in an OSS tool.** That intersection — *commerce-semantic bugs + JS/TS source + AI-codegen awareness + OSS + founder-readable report* — is empty. That is the wedge.

**Where vibecheck is NOT competitive (say this out loud).** vibecheck is **not** a taint engine and must not pretend to be one. Semgrep Pro, Snyk Code, and CodeQL do **cross-file / whole-program dataflow** that vibecheck will not match on injection/XSS breadth or on tracing tainted input across a large codebase — that is years of engineering and, for CodeQL/Semgrep-Pro, the core of their value. On **secrets**, gitleaks (fast/offline/MIT) and trufflehog (800+ verified detectors) are best-in-class and free; vibecheck's secrets check is hygiene overlap, not a differentiator. vibecheck's injection/auth findings will be **heuristic and pattern-level**, deliberately shallow — good enough to flag the obvious AI-codegen footguns, **not** a replacement for a real SAST taint run. Positioning must own this: *"run vibecheck for the commerce-logic and AI-slop checks the SAST tools skip; keep Semgrep/CodeQL for deep dataflow."*

---

## 5. Positioning guidance (how to describe vibecheck relative to Semgrep/Snyk — without disparaging them)

1. **Lead with the domain, not the technique.** "The commerce-logic + AI-codegen readiness check for JS/TS storefronts," not "a better SAST." The incumbents own *technique* (taint). vibecheck owns *domain* (checkout/cart/order logic) + *audience* (founders shipping AI-generated stores).

2. **Name them as complements, explicitly.** Recommended line: *"vibecheck is not trying to replace Semgrep, CodeQL, or Snyk — they do deep, cross-file taint analysis we don't. vibecheck catches the commerce-logic bugs and AI-codegen footguns those tools aren't built to look for: a checkout that trusts a client-supplied price, an order endpoint with no ownership check, a Stripe key shipped to the browser."* This is honest, defensible, and flattering-by-contrast without a knock.

3. **Turn the "just write a custom Semgrep rule" objection into the pitch.** Yes, a security engineer *could* author these as custom Semgrep rules — but (a) the target user is a **non-security founder** who won't, (b) there's **no curated commerce-logic ruleset** shipping anywhere, and (c) vibecheck bundles them with a **letter grade + prioritized, founder-readable report**, which raw Semgrep does not. Frame vibecheck as *"the opinionated commerce-logic ruleset + report that no one has packaged."*

4. **Be loud about OSS honesty.** Semgrep's best detection (cross-file, Pro rules, secrets validation, the IDOR beta) is **paid/gated**; Snyk Code and AquilaX are closed SaaS; SonarQube's analyzers moved to a source-available (non-OSI) license in 2024. vibecheck being **genuinely OSS, no paywalled core** is a clean contrast — state it factually, don't sneer.

5. **Claim AI-codegen awareness carefully — it's contested.** vibe-audit (OSS) and AquilaX Vibe (SaaS) already claim "understands AI patterns." vibecheck's differentiator over them is **specifically commerce logic**, which neither does. So the precise claim is: *"the only AI-codegen scanner that also checks e-commerce business logic,"* not *"the only AI-codegen scanner."*

6. **Integrate, don't wall off.** Emit **SARIF** and ship a **GitHub Action** so vibecheck sits *inside* the same Code Scanning tab as CodeQL/Semgrep — reinforcing "we're the commerce-logic layer you add," not a rival dashboard.

---

## 6. Open questions / UNVERIFIED items to close before publishing externally

- **[SECONDARY]** Semgrep OSS 44–48% vs Pro 72–75% detection rates come from a third-party benchmark (aicodereview.cc / dev.to), not Semgrep. Do not cite as fact in marketing without a primary benchmark.
- **[SECONDARY]** CodeQL "weak on business logic" is sourced to securityscientist.net and general understanding; it aligns with GitHub's framing but is not a single quotable GitHub-docs sentence. Soft-cite.
- **[UNVERIFIED]** AquilaX Vibe SARIF support — not confirmed.
- **[UNVERIFIED]** Whether any incumbent has added commerce-specific rules *after* the sources' publication dates (rule registries change; re-check `semgrep-rules` before any public claim of "zero commerce rules").
- **[TO DECIDE]** vibecheck's own SARIF/Action support is a *recommendation* here, not a shipped feature — confirm against VIBECHECK-BUILD-PLAN.md before stating it publicly.
- **Watch item:** Semgrep's AI-IDOR feature will likely **GA and possibly reach a free tier**. It's the incumbent move most likely to encroach — though on *generic* IDOR, not commerce semantics. Monitor the beta.

---

## 7. Sources (all accessed 2026-07-15)

**Semgrep**
- https://semgrep.dev/products/community-edition/ (CE overview) [PRIMARY]
- https://docs.semgrep.dev/semgrep-pro-vs-oss (OSS vs paid split) [PRIMARY]
- https://semgrep.dev/pricing/ (Team $35/contributor/mo; free ≤10 devs) [PRIMARY]
- https://github.com/semgrep/semgrep-rules + GitHub Contents/Trees API (4,909-file rule tree; language-based dirs; grep for commerce terms) [PRIMARY]
- https://semgrep.dev/blog/2025/ai-powered-detection-with-semgrep/ (AI-hybrid IDOR, paid private beta, dated 2025-11-11) [PRIMARY]
- https://aicodereview.cc/blog/is-semgrep-free/ ; https://dev.to/rahulxsingh/... (OSS vs Cloud, detection benchmark) [SECONDARY]

**Snyk Code**
- https://snyk.io/plans/ (tiers; Free 100 Code tests/mo; Team $25/dev/mo; no business-logic mention) [PRIMARY]
- https://appsecsanta.com/snyk-code (detection categories, SARIF) [SECONDARY]

**SonarQube / Cloud**
- https://docs.sonarsource.com/sonarqube-cloud/standards/managing-rules/security-hotspots [PRIMARY]
- https://docs.sonarsource.com/sonarqube-server/.../security-related-rules (injection vs configuration rules) [PRIMARY]
- https://www.sonarsource.com/license/ ; https://www.sonarsource.com/open-source-editions/sonarqube-community-edition/ (LGPLv3 + SSALv1 analyzers, Nov 2024) [PRIMARY]
- https://github.com/marketplace/actions/sonarqube-to-github-security-tab-sarif ; Sonar community SARIF threads [SECONDARY]

**gitleaks / trufflehog**
- https://github.com/gitleaks/gitleaks (MIT, secrets-only, SARIF/json/csv/junit) [PRIMARY]
- https://github.com/trufflesecurity/trufflehog (AGPL-3, 800+ detectors, verification, SARIF) [PRIMARY]
- https://appsecsanta.com/secret-scanning-tools/gitleaks-vs-trufflehog ; https://www.jit.io/resources/appsec-tools/trufflehog-vs-gitleaks... (comparison, 94% verified benchmark) [SECONDARY]

**CodeQL / GitHub Code Scanning**
- https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning-with-codeql (languages; no PHP/Scala) [PRIMARY]
- https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning (native SARIF 2.1.0) [PRIMARY]
- https://github.blog/changelog/2025-03-04-introducing-github-secret-protection-and-github-code-security/ (Code Security $49/committer/mo, Apr 1 2025) [PRIMARY]
- https://www.securityscientist.net/blog/12-questions-and-answers-about-codeql-github/ (business-logic limitation) [SECONDARY]

**AI-code / vibe-coding scanners**
- https://github.com/ApacheWang/vibe-audit (MIT, 7 categories, no commerce logic, 1 commit/0 stars) [PRIMARY]
- https://aquilax.ai/vibe (paid SaaS, AI-origin detection, no commerce logic) [PRIMARY]
- https://vibesecurity.net/ ; https://vibeappscanner.com/ (runtime scanners) [SECONDARY]
- https://www.startuphub.ai/ai-news/insights/2026/ai-security-tools-vibe-coded-apps-2026 (20-tool survey; zero do business logic) [SECONDARY]
- https://www.invicti.com/blog/web-security/vibe-coding-security-checklist... ; https://checkmarx.com/blog/security-in-vibe-coding/ ; https://www.ox.security/blog/vibe-coding-security/ (context/stats) [SECONDARY]
- https://research.gatech.edu/bad-vibes-ai-generated-code-vulnerable-researchers-warn (Georgia Tech, 43k advisories) [SECONDARY]

**Commerce-logic vulnerability domain (proves the wedge is real & tool-unowned)**
- https://owasp.org/www-project-web-security-testing-guide/latest/.../10-Business_Logic_Testing (OWASP WSTG business-logic + payment tests) [PRIMARY]
- https://www.intigriti.com/blog/news/top-6-price-manipulation-vulnerabilities-ecommerce [SECONDARY]
- https://cybri.com/blog/a-guide-to-e-commerce-business-logic-flaws/ ; https://trustedsec.com/blog/theft-from-online-shopping-carts-past-and-present [SECONDARY]
- https://www.coddykit.com/pages/blog-detail?...strix... (AI-pentest finds negative-price/order-IDOR at runtime) [SECONDARY]
