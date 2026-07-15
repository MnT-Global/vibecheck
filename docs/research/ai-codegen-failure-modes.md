# AI-Codegen Failure Modes — Real-World Evidence for `vibecheck` Checks

**Purpose:** Ground every `vibecheck` check in *documented, dated* evidence so our checks
target real failure modes (not hypotheticals) and each check can cite a real-world example
in the README / launch content / report footnotes.

**Compiled for:** [VIBECHECK-BUILD-PLAN.md](../../../VIBECHECK-BUILD-PLAN.md) §4.3 check catalog
**Research date / access date for all URLs below:** 2026-07-15
**Discipline note:** Hard data (peer-reviewed studies, vendor reports with stated methodology,
CVEs) is labelled **[HARD DATA]**. First-person / single-app stories are **[ANECDOTE]**.
Claims we could not confirm against a primary or credible secondary source are flagged
**[UNVERIFIED]**. We do not fabricate incident details.

---

## 0. TL;DR — What the evidence says

- **Best single hard-data stat (use this one):** Veracode's *2025 GenAI Code Security Report*
  (July 30, 2025) tested **100+ LLMs across 4 languages** and found **45% of AI-generated code
  samples failed security tests and introduced an OWASP Top 10 vulnerability.** Newer/bigger
  models did **not** improve security. XSS was defended in only ~14% of cases (**failed 86%**).
  Primary PDF: <https://www.veracode.com/wp-content/uploads/2025_GenAI_Code_Security_Report_Final.pdf>
- **Best real-world enterprise trend stat:** Apiiro (Fortune-50 repos, Dec 2024–Jun 2025)
  saw monthly security findings rise **~1,000 → 10,000 (10x)** as AI coding scaled, with
  **privilege-escalation paths +322%** and **secret exposure ~2x**.
- **Best "vibe-coded store got wrecked" launch anecdote:** the **Enrichlead / Cursor** incident
  (March 2025) — a 100%-AI-built SaaS whose paywall had no server-side enforcement and whose
  API keys sat in the frontend; attackers bypassed subscriptions and maxed the keys. This maps
  1:1 to our COM-01 + SEC-02 checks.
- **Most-common failure modes in AI commerce output (ranked, drives weighting):**
  **1) Secrets exposed to the client, 2) Broken access control (missing auth + permissive/disabled
  RLS + IDOR/BOLA), 3) No server-side commerce validation, 4) XSS/SSRF, 5) Injection.**
  Secrets + access-control together account for the overwhelming majority of *documented*
  vibe-coded incidents.
- **Caution on the "2.74x" number MnT keeps citing:** see §1.2 — it is real but **commonly
  mis-attributed and conflated**. Cite the Veracode **45%** as the primary; treat 2.74x carefully.

---

# PART A — HARD DATA: quantitative studies on AI-code vulnerability rates

## 1.1 Veracode — *2025 GenAI Code Security Report* **[HARD DATA]**
- **Date:** July 30, 2025 (a Spring-2026 update reaffirmed the findings).
- **Method:** 100+ LLMs, 4 languages (Java, Python, C#, JavaScript), OWASP-mapped tasks.
- **Headline:** **45%** of code samples failed security tests / introduced OWASP Top 10 vulns.
- **By language:** Java **72%** fail, C# **45%**, JavaScript **43%**, Python **38%**.
- **By weakness:** **XSS (CWE-80) failed in 86%** of relevant samples; **Log Injection (CWE-117)
  in 88%**. (SQL injection, weak crypto also prominent.)
- **Key kicker:** newer/larger models generate more *functionally correct* code but security
  performance is **flat** — this is a structural problem, not a "wait for GPT-N" problem.
- Blog: <https://www.veracode.com/blog/genai-code-security-report/> ·
  Report landing: <https://www.veracode.com/resources/analyst-reports/2025-genai-code-security-report/> ·
  Spring 2026 update: <https://www.veracode.com/blog/spring-2026-genai-code-security/>
- **Why it matters for us:** directly justifies the *weighting* of Web-Exposure (XSS) and the
  premise that AI code ships vulnerable by default. This is our cleanest, most authoritative cite.

## 1.2 The "2.74x more vulnerabilities" figure — **[HARD DATA, but attribution is messy]**
- The oft-quoted "**2.74x** more vulnerabilities in AI code" is **most credibly traced to a
  CodeRabbit analysis** of vulnerability density in AI-generated vs. human-written pull requests
  across thousands of repos — i.e., real production code that humans *chose to commit*.
- **Problem:** dozens of secondary blogs attribute 2.74x to *Veracode's* report and **conflate the
  two**. Our own primary read of Veracode surfaced the **45%** figure, not 2.74x.
- **Recommendation:** In launch copy, lead with **Veracode's 45%** (fully primary-verified).
  If you use 2.74x, attribute it to CodeRabbit and call it "PR-level vulnerability density,"
  not Veracode. **[UNVERIFIED]** as a Veracode statistic.
- Example secondary sources (content-farm tier, do not cite as primary): unyform.ai, softwareseni.com.

## 1.3 Apiiro — *4x Velocity, 10x Vulnerabilities* **[HARD DATA — enterprise telemetry]**
- **Date/scope:** Deep Code Analysis across tens of thousands of repos at Fortune-50 enterprises,
  **Dec 2024 – Jun 2025**.
- **Findings:** AI-assisted devs commit **3–4x faster**; monthly security findings rose from
  **~1,000 to >10,000 (10x)** over six months. **Privilege-escalation paths +322%**,
  **architectural design flaws +153%**. AI-assisted devs exposed **Azure Service Principals /
  Storage Access Keys at ~2x** the rate of non-AI devs. Syntax errors −76% and logic bugs −60%
  (AI is good at *local* correctness) **but** deeper architectural/authz flaws went *up*.
- <https://apiiro.com/blog/4x-velocity-10x-vulnerabilities-ai-coding-assistants-are-shipping-more-risks/>
- **Why it matters:** the single best evidence that the danger is **access-control + secrets**
  (the flaws needing cross-file reasoning), which is exactly where our AUTH + SEC checks aim.

## 1.4 Stanford — *Do Users Write More Insecure Code with AI Assistants?* **[HARD DATA — academic]**
- Perry, Srinivasan, Chatterjee, Boneh — **ACM CCS 2023** (arXiv 2211.03622).
- 47 participants, 5 security tasks, 3 languages. Participants with an AI assistant wrote
  **significantly less secure code on 4 of 5 tasks** (notably **SQL injection** and string
  encryption) — **and were more likely to *believe* their code was secure** ("false sense of
  security"). <https://arxiv.org/abs/2211.03622>
- **Why it matters:** justifies vibecheck's entire existence — the builder cannot self-assess.

## 1.5 NYU — *Asleep at the Keyboard? (GitHub Copilot)* **[HARD DATA — academic]**
- Pearce, Ahmad, Tan, Dolan-Gavitt, Karri — **IEEE S&P 2022** (arXiv 2108.09293).
- 89 scenarios → **1,689 generated programs, ~40% vulnerable** (mapped to MITRE Top-25 CWEs).
  <https://arxiv.org/abs/2108.09293>
- **Why it matters:** the foundational "~40% of AI completions are vulnerable" anchor citation.

## 1.6 GitClear — *AI Copilot Code Quality 2025* **[HARD DATA — maintainability]**
- **Date:** Feb 2025; **211M changed lines over 5 years** (incl. Google/Microsoft/Meta repos).
- **8x increase (2024)** in commits containing **5+ duplicated lines**; **copy-paste exceeded
  moved/refactored code for the first time**; refactored code fell from ~25% (2021) to <10% (2024);
  churn (code revised within 2 weeks) rose to **7.9%**. Cloned blocks correlate with **15–50% more
  defects**. <https://www.gitclear.com/ai_assistant_code_quality_2025_research>
- **Why it matters:** supports PROD/maintainability framing ("demos fine, rots fast") and the
  paid-cleanup upsell. Note: this is quality/tech-debt data, **not** a direct vuln count.

## 1.7 Escape.tech — *State of Security of Vibe-Coded Apps* **[HARD DATA — field scan]**
- **Date:** Oct 29, 2025. Scanned **5,600+ live vibe-coded apps** (Lovable ~4,000, Create.xyz ~449,
  Base44 ~159, Vibe Studio, Bolt.new).
- **>2,000 vulnerabilities, 400+ exposed secrets, 175 PII exposures** (medical records, IBANs,
  phones, emails). Dominant classes: **exposed Supabase anon JWTs in JS bundles, misconfigured/
  disabled RLS, missing/weak auth on API endpoints.** "**Most vulnerabilities were exposed without
  authentication**." <https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/>
- **Why it matters:** field proof (not lab) that Secrets + Access-Control dominate real output.

## 1.8 Wiz Research — *Common Security Risks in Vibe-Coded Apps* **[HARD DATA — field scan]**
- **~1 in 5 (20%)** organizations using vibe-coding platforms carry systemic risk. Four recurring
  classes: **(1)** client-side auth logic with credentials embedded in JS; **(2)** hardcoded
  third-party API keys (e.g. OpenAI) in client code; **(3)** permissive/disabled Supabase **RLS**
  leaking PII; **(4)** unauthenticated internal dashboards deployed publicly (found via Lovable
  fingerprinting). <https://www.wiz.io/blog/common-security-risks-in-vibe-coded-apps>
- **Why it matters:** independent second field study agreeing with Escape.tech on the top-4.

## 1.9 Tenzai — *Bad Vibes: secure-coding capabilities of AI coding agents* **[HARD DATA — benchmark]**
- **Date:** Dec 2025. Built **15 apps** (3 each) with **Cursor, Claude Code, OpenAI Codex, Replit,
  Devin** from identical prompts. **69 vulnerabilities**; **every agent shipped broken auth + SSRF**;
  **100% introduced SSRF**; **0% included CSRF protection or CSP/HSTS security headers.**
  <https://blog.tenzai.com/bad-vibes-comparing-the-secure-coding-capabilities-of-popular-coding-agents/>
  (Coverage: CSO Online, InfoWorld.)
- **Why it matters:** rare *hard* data for our thinner categories — SSRF (WEB-02) and missing
  security headers (DEP-02) — "100%" and "0%" are launch-grade numbers.

## 1.10 Spracklen et al. — *We Have a Package for You!* (package hallucination) **[HARD DATA — academic]**
- **USENIX Security 2025.** 16 models, **576,000 code samples**. **~19.7% of recommended packages
  were hallucinated** (commercial 5.2%, open-source **21.7%**). **43% of fake names recurred across
  all 10 re-runs** (predictable → weaponizable as "**slopsquatting**" supply-chain attacks).
  <https://www.usenix.org/system/files/usenixsecurity25-spracklen.pdf>
- **Why it matters:** the dependency-layer AI-specific failure mode (DEP-01) with a clean stat.

> **Numbers we could NOT verify to a primary source — do not cite as fact:**
> OX Security's "**62% of AI-generated code ships with vulnerabilities**" is a *headline only* —
> it is **not substantiated in the article body**, which instead quotes other orgs. **[UNVERIFIED]**.
> Likewise a "**15% of Bolt apps hardcoded API keys**" figure circulates in search summaries but we
> found **no primary source** — **[UNVERIFIED]**. A "Carnegie Mellon: only 10.5% passes security
> review" and a "Georgetown CSET 86% XSS" appear as *secondary attributions* (the 86% XSS is really
> Veracode's — likely a conflation). **[UNVERIFIED]** as attributed.

---

# PART B — DOCUMENTED INCIDENTS (2024–2026)

## B.1 Lovable — CVE-2025-48757 (default/broken RLS) **[HARD DATA — CVE]**
- **Insufficient Row-Level Security** let **remote *unauthenticated* attackers read/write arbitrary
  database tables** of generated sites. CWE-863 (improper authorization). **CVSS 9.3 (critical,**
  MITRE-assigned). Affects Lovable through **Apr 15, 2025**; CVE recorded **May 29, 2025**.
- **Nuance to state honestly:** the record is **vendor-DISPUTED** — Lovable argues customers own
  their app data. Cite it, but note the dispute. <https://nvd.nist.gov/vuln/detail/CVE-2025-48757>
- Associated researcher reporting (via marketplace scans) put roughly **170 of ~1,645** showcased
  Lovable apps leaking data through this class (~1 in 10) — present as *researcher-reported*, not
  primary-verified here.

## B.2 Lovable — April 2026 BOLA / source-code + credential exposure **[HARD DATA — reported by The Next Web]**
- A **Broken Object-Level Authorization** flaw let **any free account** reach other users' profiles,
  **project source code, and Supabase database credentials in as few as 5 API calls**, plus Stripe
  customer IDs and AI conversation history. Affected **projects created before Nov 2025**.
- **Timeline:** reported to Lovable's bug bounty **Mar 3, 2026**; **unpatched for existing projects
  for 48 days**; public disclosure **Apr 20, 2026**; company initially denied, then partial apology.
- **Named victim:** *Connected Women in AI* (Danish nonprofit) — exposed real records (names, job
  titles, LinkedIn, Stripe IDs) tied to people at Accenture Denmark, Nvidia, Microsoft, Uber, Spotify.
  <https://thenextweb.com/news/lovable-vibe-coding-security-crisis-exposed>
- **[UNVERIFIED] sub-claim:** a separate search summary cited "**18,697 records incl. UC Berkeley/UC
  Davis students**." The primary article we read names the *Danish nonprofit* case instead — do **not**
  repeat the Berkeley figure without a source.

## B.3 Enrichlead — "my 100%-AI SaaS is under attack" (Cursor) **[ANECDOTE — but perfectly on-brand]**
- **March 2025.** Leonel Acevedo (@leojr94 / "@nickcreated") shipped Enrichlead built entirely in
  **Cursor**, "zero hand-written code." Within days: **subscriptions bypassed, API keys maxed out,
  database filling with junk.** Root cause: a **paywall UI with no server-side enforcement**, **API
  keys in the frontend**, **no DB access controls** — ~15,000 lines of AI code he couldn't audit.
  <https://techstartups.com/2025/03/26/when-vibe-coding-goes-wrong/>
- **Why it matters:** *the* canonical demo-fine-then-robbed story. Maps to **COM-01** (client-trusted
  paywall/price) + **SEC-02** (client secrets) + **AUTH-01**. Strong README opener.

## B.4 RedAccess — 380,000 vibe-coded apps scanned **[HARD DATA — reported by VentureBeat / Security Boulevard]**
- **Early May 2026.** Israeli firm RedAccess scanned **~380,000** apps on vibe-coding platforms;
  **~5,000 were leaking sensitive corporate/personal data.** ~40% of the vulnerable set exposed
  medical records, financials, corporate-strategy docs, or CS chat transcripts. Verified examples:
  a shipping firm's vessel schedules, UK clinical-trial status, a Brazilian bank's internal
  financials, a UK retailer's customer-service chat logs.
  <https://venturebeat.com/security/vibe-coded-apps-shadow-ai-s3-bucket-crisis-ciso-audit-framework> ·
  <https://securityboulevard.com/2026/05/thousands-of-vibe-coded-apps-exposing-corporate-personal-data-redaccess/>
- **Why it matters:** the "at ecosystem scale" number for slides/launch.

## B.5 Tea app — unauthenticated Firebase bucket **[HARD DATA — breach; AI-attribution UNVERIFIED]**
- **July 2025.** A legacy **Firebase Storage bucket with no authentication** exposed **~72,000 images**
  (13,000 selfies + government photo IDs; 59,000 from posts/DMs); later ~1.1M private messages.
  Discovered by 4chan users; legacy data never secured/deleted.
  <https://cyberinsider.com/tea-app-suffers-data-breach-exposing-72000-users-photos-and-private-messages/>
- **Honesty flag:** Tea is **not confirmed to be "vibe-coded."** Include it only as a real-world
  example of the *exact failure class* vibecheck flags — **unauthenticated cloud data store** (SEC/AUTH).

---

# PART C — MAPPED TO THE 8 `vibecheck` CATEGORIES

Each category: the recurring pattern → **how common in AI commerce output** → 1–3 dated real examples.

## 1. Secrets & Credential Exposure — build-plan weight 20 (highest)
**Pattern:** hardcoded provider keys (`sk_live_`, OpenAI, AWS), Supabase **anon/service** keys and
`.env` values shipped in the **client bundle** or committed to the repo.
**Prevalence: #1 (near-universal).** Appears in essentially every field scan and incident below.
- Escape.tech (Oct 29 2025): **400+ exposed secrets** across 5,600 apps; exposed Supabase JWTs in JS
  bundles. <https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/>
- Wiz: hardcoded OpenAI/third-party keys in client code as one of the top-4 classes.
  <https://www.wiz.io/blog/common-security-risks-in-vibe-coded-apps>
- Apiiro: AI devs exposed Azure Service Principals / Storage keys **~2x** non-AI devs.
  <https://apiiro.com/blog/4x-velocity-10x-vulnerabilities-ai-coding-assistants-are-shipping-more-risks/>
- Enrichlead (Mar 2025): API keys in the frontend, promptly maxed out. **[ANECDOTE]**

## 2. Injection & Code Execution — weight 18
**Pattern:** string-built SQL/NoSQL from input; `eval`/`new Function`; `child_process` interpolation.
**Prevalence: high, but often lower-confidence to detect statically single-file.**
- Veracode 2025: SQL injection among top OWASP failures; **XSS failed 86%**, log injection 88%.
  <https://www.veracode.com/blog/genai-code-security-report/>
- Stanford CCS 2023: AI-assisted participants significantly worse on **SQL injection** specifically.
  <https://arxiv.org/abs/2211.03622>

## 3. Access Control & Auth — weight 15  ← *arguably the #1 real-incident driver*
**Pattern:** admin/API route with **no auth check**; **permissive or disabled RLS**; **IDOR/BOLA**
(object id straight from input); client-side "auth"; permissive CORS.
**Prevalence: #1–#2 and the most *damaging* — it is what actually gets breached.**
- Lovable **CVE-2025-48757** — unauth read/write of arbitrary tables via broken RLS, **CVSS 9.3**
  (vendor-disputed). <https://nvd.nist.gov/vuln/detail/CVE-2025-48757>
- Lovable **BOLA** (Apr 2026) — free account → other users' source + DB creds.
  <https://thenextweb.com/news/lovable-vibe-coding-security-crisis-exposed>
- Wiz: permissive/disabled RLS **and** unauthenticated internal dashboards (2 of its top-4).
- Apiiro: **privilege-escalation paths +322%.** Tenzai: **every agent shipped broken auth.**

## 4. Commerce-Logic Integrity — weight 15  ← *the MnT wedge (no generic SAST covers it)*
**Pattern:** price/total **trusted from the client**; quantity unvalidated (negative/zero/overflow →
price theft); no server-side inventory check; discount/coupon applied without server validation;
paywall enforced only in the UI.
**Prevalence: HIGH in reality, but under-quantified** — logic flaws don't show up in generic vuln
scans, which is precisely why this is our differentiator (and why we honestly weight it 15, not 25).
- **Enrichlead / Cursor (Mar 2025)** — paywall with **no server-side enforcement**, subscriptions
  bypassed. The definitive documented commerce-logic failure. **[ANECDOTE]**
  <https://techstartups.com/2025/03/26/when-vibe-coding-goes-wrong/>
- Contextual hard data: Stanford's "false sense of security" explains *why* builders ship these
  unknowingly. No public dataset quantifies client-trusted-price rates in AI stores → **honest gap;
  our own AI Cleanup Lab benchmark (negative-qty exploit) is the demonstration asset.**

## 5. Web Exposure (XSS / SSRF / path traversal) — weight 10
**Pattern:** input echoed into HTML unescaped (reflected XSS); server fetches a user-supplied URL
(SSRF); user input into `fs` paths.
**Prevalence: XSS = extremely common (strong hard data); SSRF = universal in fresh agent output.**
- Veracode 2025: **XSS defended in only ~14% (failed 86%).** <https://www.veracode.com/blog/genai-code-security-report/>
- Tenzai (Dec 2025): **100% of AI agents introduced SSRF**; 0% shipped CSP/HSTS.
  <https://blog.tenzai.com/bad-vibes-comparing-the-secure-coding-capabilities-of-popular-coding-agents/>

## 6. Performance & Scale — weight 8  ← *weakest external evidence; keep it honest*
**Pattern:** synchronous I/O on the request hot path (`readFileSync`/`writeFileSync` in a handler);
full-dataset read/parse per request; N+1 / unbounded queries.
**Prevalence: widely *asserted* ("demos fine, dies at real traffic") but thinly *documented*
externally.** Treat most of this as **[ANECDOTE / logical]**, not hard data.
- Best evidence is *indirect*: GitClear's copy-paste/duplication surge (clones correlate with
  15–50% more defects). <https://www.gitclear.com/ai_assistant_code_quality_2025_research>
- **Our own asset is the strongest proof:** the AI Cleanup Lab load test (sync-I/O handler:
  **680 → 33k req/s** after fix). Use the Lab as the demonstration; don't overclaim external data.

## 7. Production Hardening — weight 9
**Pattern:** no rate limiting anywhere; missing input validation on mutating endpoints; stack traces
leaked to client; debug mode on / secrets in logs.
**Prevalence: high — AI "happy-path" code omits hardening by default.**
- Tenzai (Dec 2025): **0% of AI-built apps included CSRF protection or security headers.**
  <https://blog.tenzai.com/bad-vibes-comparing-the-secure-coding-capabilities-of-popular-coding-agents/>
- Escape.tech: "most vulnerabilities exposed **without authentication**" — i.e., zero gatekeeping.
- Zuplo, "Vibe Coding Makes Fast APIs — Not Safe Ones" (missing rate limits/authz on AI APIs) —
  **[ANECDOTE/practitioner]**: <https://zuplo.com/learning-center/vibe-coding-api-security>

## 8. Dependencies & Config — weight 5
**Pattern:** known-vulnerable deps; missing security headers (no helmet/CSP); **hallucinated package
names** (slopsquatting); no tests.
**Prevalence: moderate, but the AI-*specific* one (hallucinated packages) is uniquely ours to flag.**
- Spracklen et al., USENIX Security 2025: **~19.7% of AI-recommended packages hallucinated**; 43%
  recur predictably → slopsquatting supply-chain risk.
  <https://www.usenix.org/system/files/usenixsecurity25-spracklen.pdf>
- Tenzai: 0% security headers (also a DEP-02 signal).

---

# PART D — PRIORITIZATION (drives check weighting)

**Ranked by documented frequency + severity in *AI-generated commerce* output:**

| Rank | Failure mode | Category | Evidence strength | Note |
|---|---|---|---|---|
| 1 | Secrets exposed to client / committed | **Secrets** | **Strong** (Escape, Wiz, Apiiro, Enrichlead) | Highest-confidence static detection too → keep weight 20 |
| 2 | Broken access control (no-auth routes, permissive/disabled RLS, IDOR/BOLA) | **Access-Control/Auth** | **Strong** (2 Lovable CVEs/incidents, Wiz, Apiiro +322%, Tenzai) | *Most-breached in the wild.* Consider it co-#1; weight 15 is defensible but could argue higher |
| 3 | No server-side commerce validation (price/qty/paywall) | **Commerce-Logic** | **Real but under-quantified** (Enrichlead; logic flaws invisible to generic SAST) | The wedge. Weight 15 is honest given static-detection difficulty |
| 4 | XSS | **Web-Exposure** | **Strong** (Veracode 86%) | Best-quantified single weakness |
| 4 | SSRF / missing CSRF+headers | **Web-Exposure / Prod-Hardening** | **Strong** (Tenzai 100% / 0%) | Fresh-agent output near-guaranteed |
| 6 | Injection (SQLi, eval, cmd) | **Injection** | **Strong** (Veracode, Stanford) | Classic; weight 18 justified |
| 7 | Hallucinated / vulnerable dependencies | **Dependencies** | **Moderate** (USENIX 19.7%) | AI-specific angle worth surfacing |
| 8 | Blocking I/O / no rate limiting / scale | **Performance / Prod-Hardening** | **Weak external; strong internal (our Lab)** | Keep low weight (8); prove via Lab, not external stats |

**Weighting verdict:** the build-plan weights (Secrets 20 · Injection 18 · Auth 15 · Commerce 15 ·
Web 10 · Perf 8 · Prod 9 · Dep 5) are **well-aligned with the evidence.** The one data-driven nudge
to discuss with CTO: **Access-Control/Auth is the #1 driver of *actual breaches*** (both Lovable
incidents, Wiz, Apiiro's +322% priv-esc), even though Secrets is #1 by *static-scan count*. If we
ever rebalance, move points *toward* AUTH, not away. Performance (8) is correctly the lowest —
external hard data is thin; lean on our own load-test benchmark for that category's credibility.

---

# PART E — SOURCE LEDGER (all accessed 2026-07-15)

**Quantitative studies**
- Veracode 2025 GenAI Code Security Report — <https://www.veracode.com/blog/genai-code-security-report/>
  (PDF: <https://www.veracode.com/wp-content/uploads/2025_GenAI_Code_Security_Report_Final.pdf>)
- Apiiro, *4x Velocity, 10x Vulnerabilities* — <https://apiiro.com/blog/4x-velocity-10x-vulnerabilities-ai-coding-assistants-are-shipping-more-risks/>
- Stanford (Perry et al.), CCS 2023 — <https://arxiv.org/abs/2211.03622>
- NYU (Pearce et al.), IEEE S&P 2022 — <https://arxiv.org/abs/2108.09293>
- GitClear AI Copilot Code Quality 2025 — <https://www.gitclear.com/ai_assistant_code_quality_2025_research>
- Spracklen et al. (package hallucination), USENIX Security 2025 — <https://www.usenix.org/system/files/usenixsecurity25-spracklen.pdf>

**Field scans / benchmarks**
- Escape.tech, State of Security of Vibe-Coded Apps (Oct 29 2025) — <https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/>
- Wiz Research, Common Security Risks in Vibe-Coded Apps — <https://www.wiz.io/blog/common-security-risks-in-vibe-coded-apps>
- Tenzai, Bad Vibes (Dec 2025) — <https://blog.tenzai.com/bad-vibes-comparing-the-secure-coding-capabilities-of-popular-coding-agents/>

**Incidents**
- Lovable CVE-2025-48757 — <https://nvd.nist.gov/vuln/detail/CVE-2025-48757>
- Lovable BOLA (Apr 2026), The Next Web — <https://thenextweb.com/news/lovable-vibe-coding-security-crisis-exposed>
- Enrichlead / Cursor (Mar 2025), Tech Startups — <https://techstartups.com/2025/03/26/when-vibe-coding-goes-wrong/>
- RedAccess 380k scan (May 2026), VentureBeat — <https://venturebeat.com/security/vibe-coded-apps-shadow-ai-s3-bucket-crisis-ciso-audit-framework>
  · Security Boulevard — <https://securityboulevard.com/2026/05/thousands-of-vibe-coded-apps-exposing-corporate-personal-data-redaccess/>
- Tea app Firebase leak (Jul 2025) — <https://cyberinsider.com/tea-app-suffers-data-breach-exposing-72000-users-photos-and-private-messages/>

**Flagged / do-not-cite-as-primary**
- OX Security "62%" (headline only, unsubstantiated in body) — <https://www.ox.security/blog/vibe-coding-security/>
- "2.74x" as a Veracode stat (actually CodeRabbit; frequently conflated) — treat as **[UNVERIFIED]** when attributed to Veracode
- "15% of Bolt apps hardcoded keys," "18,697 records / UC Berkeley," "CMU 10.5%," "CSET 86% XSS" — **[UNVERIFIED]** secondary attributions
