# vibecheck — Detection Rules Specification (R0)

**Status:** R0 — **CTO-reviewed (conditionally approved), edits applied** · **Date:** July 15, 2026 · **Owner:** OSS pod · **Gate:** Kansha (CTO) gives final sign-off before Sprint 1 scoring locks.
**Parent:** [VIBECHECK-BUILD-PLAN.md](../../VIBECHECK-BUILD-PLAN.md) §4.3, §6 · **CTO review:** [cto-review-r0.md](cto-review-r0.md) (decisions this doc now reflects)

This document generalizes the AI Cleanup Lab's 7 demo-specific SAST rules
(`~/MnT Website/ai-cleanup-lab/lab/scan.js`) into **stack-agnostic, AST-based detection
specs** for all 28 vibecheck checks, and specifies the `ScanContext` the loader must build
for those checks to run as pure functions.

> **The R0 job in one line:** the Lab proves *what* to look for; this doc pins *how* to detect
> it on code we've never seen — structurally (tree-sitter AST), not by matching the Lab's
> literal strings.

---

## 1. How to read this doc

Each check specifies:

- **ID / category / severity / max deduction** — severity drives the score deduction; a
  category's points are capped (§4.4 of the build plan).
- **Detects** — the real-world failure mode (1 line).
- **Detection (AST)** — the concrete tree-sitter target: node types + structural conditions.
  This is what Sprint 1/2 implements. Written against **tree-sitter-javascript /
  -typescript** node names.
- **`appliesTo`** — the stack-neutrality gate: when this check is N/A → `info`, excluded
  from the denominator (never a silent `fail`).
- **Tier / Confidence** (CTO review ADR-001) — **structural** = tree-sitter (syntax) is
  *sufficient*; emits `high` confidence, **on by default, ships in v0.1.0**. **flow** = needs
  cross-file/dataflow tree-sitter can't give; capped at `medium`, **`--experimental` / off by
  default**, graduates to on-by-default **per check** only after it passes the §3.1 precision gate
  (then ships in a v0.1.x with a published precision number). The tier is a structural property of
  what the check needs, not a preference — see §1.2 for the authoritative split.
- **Evidence** — what we quote in the report (always the *actual code*, `file:line`, ≤120 chars;
  secret VALUES redacted — key name + location only).
- **Fix** — the one-line remediation (mirrors the Lab's `after/server.js` patterns where relevant).
- **FP risk** — known false-positive traps + how the rule suppresses them.
- **Lab provenance** — which Lab rule (if any) this generalizes.

**Honesty policy (brand-critical):** this is heuristic pattern + AST **single-file** analysis,
not inter-procedural taint tracking. Every finding carries a confidence level and quotes the
code so a human can verify. A false *critical* damages a security brand worse than agentready's
false grade did — so when in doubt, a rule emits `medium` confidence or nothing, never a
confident critical.

---

## 1.1 Evidence base & weighting rationale (R0 research)

The check set and weights are grounded in documented AI-codegen failure data, not intuition
([`docs/research/ai-codegen-failure-modes.md`](research/ai-codegen-failure-modes.md)):

- **Anchor stat (use this one in launch copy):** Veracode *2025 GenAI Code Security Report*
  (Jul 30 2025) — **45% of AI-generated code samples failed security tests / introduced an OWASP
  Top-10 vuln** across 100+ LLMs; **XSS failed in 86%** of cases; no improvement in newer models.
- **Failure modes ranked by documented frequency × severity → CTO-revised weights:** (1) **Secrets**
  exposed to client / committed — near-universal → **20 pts**; (2) **Broken access control** (no-auth
  routes, disabled Supabase RLS, IDOR/BOLA) — the mode *most often actually breached* → **17 pts**
  (↑ from 15 per this data); (3) **Injection** → **16 pts**; (4) **No server-side commerce validation**
  (client-trusted price/qty/paywall) — our wedge → **15 pts**; (5) **XSS/SSRF** → 10; Prod 9, Perf 8,
  Deps 5. Weights are a calibration parameter — **re-locked after the fixture corpus is scored**.
- **Headline real incidents** (for README/checks/launch): **Enrichlead** (100%-AI SaaS via Cursor,
  Mar 2025) — paywall enforced only client-side + API keys in the frontend → subscriptions bypassed,
  keys drained (maps 1:1 to **COM-01 + SEC-02**); **Lovable CVE-2025-48757** (CVSS 9.3, broken RLS,
  unauth DB read/write — *vendor-disputed, cite with that caveat*); an **Apr 2026 BOLA** (free
  account → others' source + Supabase creds); **Apiiro** telemetry — security findings **10×** as AI
  scaled, priv-esc **+322%**.
- **CTO weighting note:** the data's one nudge — if rebalancing, move points *toward* AUTH
  (access-control drives the real breaches). Reflected in open question §13.2.

> ⚠️ **Correction for MnT marketing:** the **"2.7×/2.74× more vulnerabilities"** stat currently on
> mntfuture.com traces to **CodeRabbit**, not Veracode, and is often mis-attributed. Lead launch
> content with **Veracode's 45%** instead. ("62%", "15% of Bolt keys", "18,697 records" —
> unverifiable, do not use.)

---

## 1.2 Check tiers & v0.1.0 scope (authoritative — CTO review ADR-001/F2)

The tier split below is the single source of truth. Per-check bodies (§4–11) map by their
**Confidence** field — `high` = **[STRUCTURAL]** (on by default, v0.1.0), `medium` = **[FLOW]**
(`--experimental`) — and the handful of checks that split across tiers (SEC-01 entropy layer,
SEC-02, WEB-01) carry an explicit **Tier** line noting which case is which.

**Structural tier — high confidence, on by default, ships in v0.1.0 (~12 checks):**
SEC-01, SEC-03, SEC-04, SEC-02 *(public-prefix case only)*, INJ-01, INJ-03, AUTH-03, AUTH-04,
**COM-02** *(the provable commerce flagship)*, WEB-01 *(JSX/DOM-sink case)*, PERF-01, PROD-03,
DEP-03 *(info)*. Secrets run the **provider-pattern layer only** — the entropy layer is `[FLOW]`.

**Flow tier — `medium`, `--experimental` / off by default, graduates per §3.1, ships v0.1.x/v0.2:**
AUTH-01, AUTH-02, SEC-02 *(response-flow case)*, SEC-01 *(entropy layer)*, COM-01, COM-03, COM-04,
INJ-02, INJ-04, WEB-01 *(server-template case)*, WEB-02, WEB-03, PERF-02, PERF-03, PROD-01, PROD-02,
PROD-04, DEP-01, DEP-02.

**Why the split is structural, not arbitrary:** the flow tier asks questions tree-sitter's syntax
tree cannot answer on its own — "does any middleware *anywhere* guard this route?" (AUTH-01),
"does this secret *reach* a client bundle?" (SEC-02), "does this value *flow* from `req.body`?"
(COM-01/INJ-02/WEB-01-server). Those need cross-file/dataflow analysis. v0.1 ships the checks
tree-sitter proves; the rest earn their way on via measured precision (§3.1). **v0.2 escalation:**
if the flow tier's precision misses the gate with tree-sitter heuristics, add a scoped scope-tracker
(`@typescript-eslint/scope-manager` or `oxc`) behind the same `Check` interface — additive, not a
rewrite (the pure-function boundary makes the swap local).

> **Deferred out of v0.1 entirely (CTO F4):** the `prove` mode (live exploit probes) and `perf` mode
> (load test). They fire/execute the target app — a legal/abuse/support surface with no deadline.
> They return post-launch behind a separately-reviewed, localhost-only safety model. The
> provenance mapping (§12) keeps the design; the *feature* is not in the v0.1 CLI.

---

## 2. The ScanContext contract (what the loader MUST build)

Checks are **pure functions** `(ctx: ScanContext) => Finding[]`. All I/O — file walk, clone,
git, parse — happens once, up front, in the loader. A check that reads the filesystem is a bug
(the agentready discipline). For the checks below to work, the loader must populate:

```ts
interface ScanContext {
  root: string;                      // scan root (temp clone dir for a git URL)
  files: SourceFile[];               // every in-scope source file
  routes: Route[];                   // extracted HTTP handlers (framework-aware)
  manifests: Manifest[];             // package.json(s) + parsed lockfile
  stack: StackProfile;               // detected frameworks + surfaces (drives appliesTo)
  env: EnvUsage;                     // process.env.* refs, public-prefixed vars
  clientFiles: Set<string>;          // files reachable by the browser (SEC-02 boundary)
  gitHistory?: GitBlob[];            // opt-in only (--git-history); populated iff options.gitHistory
  options: { allowPrivate; gitHistory; experimental; ... };  // gitHistory + experimental default false
}

interface SourceFile {
  path: string; lang: 'js'|'ts'|'jsx'|'tsx'|'json'|'env'|'other';
  text: string; ast?: TSTree;        // tree-sitter tree (undefined for non-parsed types)
  lines: number; isClient: boolean;  // isClient = in clientFiles
}

interface Route {                    // the spine of AUTH/COM/PROD/PERF checks
  method: string; path: string;
  file: string; line: number;
  handlerNode: TSNode;               // the handler function body AST
  framework: 'express'|'next-app'|'next-pages'|'fastify'|'koa'|'hono'|'remix'|'unknown';
  isMutating: boolean;               // POST/PUT/PATCH/DELETE or Next action
  looksSensitive: boolean;           // path matches /admin|/internal|/orders|/users|/checkout|…
}

interface Finding {
  id; category; severity; confidence;
  file; line; column;
  evidence: string;                  // actual code, truncated, secrets redacted
  fix: string; docsUrl: string;
}
```

### 2.1 Route/handler extraction (loader responsibility — the hard part)

Most non-secrets checks depend on a good `routes[]`. The loader detects handlers per framework:

| Framework | Detection signal |
|---|---|
| **Express / Connect / Router** | `call_expression` where callee is `<id>.get|post|put|patch|delete|use|all` with a string path + a function arg |
| **Next.js App Router** | files named `route.{ts,js}` under `app/**` exporting `GET/POST/…`; server actions (`'use server'` + exported async fn) |
| **Next.js Pages API** | files under `pages/api/**` with a default-exported handler |
| **Fastify** | `fastify.route({...})` / `.get('/x', …)` |
| **Koa / Hono / Remix** | `router.get`, Hono `app.get`, Remix `loader`/`action` exports |

`framework: 'unknown'` + no routes found → the whole class of route-dependent checks becomes
`appliesTo=false` for that surface (a pure static site scores only Secrets/Deps/Web-template
categories). This is the stack-neutrality guarantee, enforced at the data layer.

**F8 honesty rule (CTO review) — the load-bearing safeguard:** route extraction is a *first-class,
fixture-tested* loader component, not a helper — the flow tier's accuracy lives here. When the
loader sees **server-side source but extracts zero routes** (an unrecognized framework/router), it
must emit an explicit report-level `info`: *"couldn't map routes for framework X — auth / commerce /
perf checks may be incomplete."* A silent under-report reads as "all clear," the worst possible
outcome for a security tool. (This is the agentready soft-404 lesson: "found nothing" must never be
presented as "nothing is wrong.")

### 2.2 Client-boundary detection (for SEC-02)

`clientFiles` = files that end up in the browser bundle. Heuristics:
- Next.js: files with `'use client'`; everything under `pages/` except `pages/api/`; `components/**`
  imported by client trees. Server-only: `app/api/**`, `route.ts`, `'use server'`, `lib/server/**`.
- Vite/CRA/Remix: `src/**` client by default; explicit server entrypoints excluded.
- Env: `NEXT_PUBLIC_*`, `VITE_*`, `PUBLIC_*`, `REACT_APP_*` are **client-exposed by definition**.

Imperfect by nature — SEC-02 findings are therefore `high` confidence only when the secret is a
known provider pattern in a `clientFiles` path, else `medium`.

---

## 3. Confidence & false-positive discipline

Shared suppression rules every check applies (implemented once in a `shared/` helper):

- **Test/example/placeholder allowlist** — skip files matching `*.test.*`, `*.spec.*`,
  `**/__tests__/**`, `**/examples/**`, `**/fixtures/**`, `**/*.stories.*`, `**/mocks/**`, and
  values that are obvious dummies (`xxx`, `changeme`, `your-key-here`, `sk_test_…`, `example.com`,
  all-same-char, `<...>` templates). *(agentready lesson: soft-404s / placeholders everywhere —
  validate content, don't trust the surface.)*
- **Comment / string-literal awareness** — via AST we know a match is real code vs a comment vs a
  doc string. Regex-only tools can't; we can, so we suppress commented-out code.
- **Vendored-code skip** — `node_modules`, `dist`, `build`, `.next`, `out`, `vendor`, minified
  (`*.min.js`) never scanned. *(agentready gotcha: biome hangs on `.next`; same ignore list.)*
- **Dedup** — same rule + same normalized location = one finding.

### 3.1 Precision gate (CTO review F1 — the missing acceptance criteria, now a CI gate)

No check ships on-by-default without passing this on the fixture corpus (§14). It is the hard
release condition — a security tool that cries wolf is worse than none:

- **Zero false criticals** on the clean / well-built fixtures. A single false critical is a
  launch-blocker.
- **`lab-before` scores F · `lab-after` scores ≥ B** — reproduced in CI on every commit (regression gate).
- **False-positive rate ≤ 10%** on the clean fixtures for any on-by-default check. A check that
  exceeds it drops back to `--experimental` until fixed — this is exactly how a flow-tier check
  *graduates* (§1.2).
- **Every finding on the AI-codegen fixtures is manually confirmed** true/false and recorded, so we
  have a **real precision number per check** at launch — published in the roadmap ("honesty over
  hype," as data).

---

## 4. Category 1 — Secrets & Credential Exposure (20 pts)

### SEC-01 · Hardcoded provider keys · **critical**
- **Tier:** (a) provider layer = **[STRUCTURAL]**, high confidence, v0.1.0. (b) entropy layer =
  **[FLOW] `--experimental`, off by default** (CTO F5 — AI code is the worst-case corpus for entropy
  false positives: it's saturated with example hashes, base64 data-URIs, mock tokens).
- **Detects:** live API keys / tokens committed in source.
- **Detection:** two-layer. (a) **Provider-pattern layer (default)** — regex over `string` literal
  nodes for known signatures (Stripe `sk_live_`, AWS `AKIA…`, etc.) — deterministic, high precision.
  (b) **Entropy layer (`--experimental`)** — string literals ≥20 chars assigned to an identifier/prop
  whose name matches `/key|secret|token|password|passwd|pwd|auth|credential|api[-_]?key/i` and whose
  Shannon entropy exceeds threshold. AST-gated so we only flag *assignments*, not arbitrary
  high-entropy strings; still off by default until the clean fixtures prove an acceptable FP rate.
- **Provider pattern table (default ruleset — top priority for commerce):** regexes transcribed
  verbatim from gitleaks v8.25.0 (`config/gitleaks.toml`) + trufflehog `pkg/detectors/`; full
  31-row table with sources in [`docs/research/secrets-and-deps.md`](research/secrets-and-deps.md) §A.2.

  | Provider | Signature | Severity |
  |---|---|---|
  | Stripe secret/restricted | `(?:sk\|rk)_(?:test\|live\|prod)_[a-zA-Z0-9]{10,99}` | **critical** (live) |
  | Stripe webhook secret | `whsec_[a-zA-Z0-9]{32,}` *(len UNVERIFIED — Stripe docs)* | high |
  | Stripe publishable | `pk_(?:test\|live)_[a-zA-Z0-9]{10,99}` | **low/info** (public by design) |
  | AWS access key id | `(?:AKIA\|ASIA\|ABIA\|ACCA\|A3T[A-Z0-9])[A-Z2-7]{16}` (+ 40-char secret in context) | **critical** |
  | DB URI w/ creds | `(postgres(?:ql)?\|mongodb(?:\+srv)?\|mysql\|redis)://user:pass@…` | **critical** |
  | Private key block | `-----BEGIN [A-Z ]*PRIVATE KEY-----` | **critical** |
  | Shopify admin/custom/private | `shp(?:at\|ca\|pa)_[a-fA-F0-9]{32}` · shared `shpss_…` | **critical** (admin) |
  | GitHub tokens | `gh[posu]_[0-9a-zA-Z]{36}` · `github_pat_\w{82}` | high |
  | npm token | `npm_[a-z0-9]{36}` | high (supply chain) |
  | SendGrid / Twilio | `SG\.[\w\-\.]{66}` · `SK[0-9a-fA-F]{32}` / `AC[0-9a-f]{32}` | high |
  | OpenAI / Anthropic | `sk-…T3BlbkFJ…` / `sk-ant-(api03\|admin01)-…` | high |
  | Slack / Google | `xox[bpe]-…` · `AIza[\w-]{35}` | high / medium |
  | JWT | `ey[\w]{17,}\.ey[\w/\\_-]{17,}\.[\w/\\_-]{10,}` | medium (context) |

  **Entropy fallback (SEC-01 layer b):** mirror gitleaks' context-gated model — flag base64-like
  runs ≥ 4.5 bits/char and hex-like ≥ 3.0 bits/char (≈75% of the 6.0/4.0 charset maxima), **only**
  when assigned to a `key|secret|token|password|credential|api…`-named identifier, emitted at
  **medium**. Free-floating high-entropy strings (hashes, base64 assets, minified blobs — endemic
  in AI output) → suppressed. FP reduction: path allowlist, stopwords on the *extracted* value,
  placeholder regexes (`sk_live_xxx`, `your-key-here`, `changeme`, all-same-char), `vibecheck-ignore`
  pragma.
- **`appliesTo`:** always (every codebase can leak a secret).
- **Evidence:** `checkout.ts:14  const PAYMENT_API_KEY = "sk_live_51Mn…"` → **value redacted to
  provider + first 6 chars**; never print the full secret.
- **Fix:** move to an environment variable; rotate the exposed key immediately.
- **FP risk:** test keys (`sk_test_`), placeholder/dummy values, example files → suppressed via §3
  allowlist + entropy gate. Public/publishable keys (`pk_live_`) are **`low`** severity, not
  critical (they're meant to be public) — the rule distinguishes secret vs publishable prefixes.
- **Lab provenance:** `hardcoded-secret` (Lab matched only `sk_live_[A-Za-z0-9]+`; we generalize
  to a full provider set + entropy).

### SEC-02 · Secret reachable by the client · **critical**
- **Tier:** cases (a) + (c) = **[STRUCTURAL]** (high, v0.1.0 — a provider secret in a client path /
  a public-prefixed env var is a structural fact). Case (b) response-flow = **[FLOW]
  `--experimental`** (needs single-file taint). v0.1.0 ships (a)+(c) only.
- **Detects:** a secret value that reaches the browser — returned in an HTTP response, embedded in
  a `clientFiles` module, or exposed via a public-prefixed env var.
- **Detection:** (a) a SEC-01 match located in a `clientFiles` path → **high**. (b) a
  server secret (`process.env.X` where `X` is NOT public-prefixed) referenced in a response body:
  find `res.json/res.send/return Response.json` whose argument object (AST `object` node) contains
  a property whose value flows from a secret-named env read → **medium** (single-file flow only).
  (c) `process.env.NEXT_PUBLIC_*` / `VITE_*` assigned from something that looks secret-named →
  **high** (public prefix = definitionally shipped to client).
- **`appliesTo`:** always.
- **Evidence:** the response/return statement, or the public-prefixed env line.
- **Fix:** never return secrets to clients; keep them server-side; use a public-prefixed var only
  for genuinely public values. *(the Lab's `after/` stopped returning `key` in the checkout body.)*
- **FP risk:** publishable keys are fine on the client — cross-check against the SEC-01 publishable
  list before flagging.
- **Lab provenance:** the Lab's checkout leaked `key: PAYMENT_API_KEY` in the response — this is
  that class, generalized.

### SEC-03 · Committed `.env` / credentials file · **high** · **[STRUCTURAL]** high
- **Detects:** an env/credential file tracked in the repo (or, opt-in, present in git history).
- **Detection:** file-name match (`.env`, `.env.local`, `.env.production`, `*.pem`, `id_rsa`,
  `*.keystore`, `credentials.json`, `serviceAccount*.json`) that is (a) present in the working tree
  **and not** git-ignored [default], or (b) found in `gitHistory` blobs [**opt-in `--git-history`**].
  Parse `.env` bodies with SEC-01's secret layer for the actual leaked values.
- **`appliesTo`:** always. The working-tree pass is the v0.1.0 default; the **history pass runs only
  when `options.gitHistory` is set** (`--git-history`, OFF by default — CTO F7) and a `.git` dir
  exists. **Hosted mode = working-tree only, always.** (Full-history scan is slow/memory-heavy and
  wrong for clone→scan→delete.)
- **Evidence:** the tracked path (+ "also in git history since <commit>" when applicable).
- **Fix:** remove from tracking, add to `.gitignore`, rotate anything it contained, scrub history.
- **FP risk:** `.env.example` / `.env.sample` / `.env.template` are conventional & safe → allowlisted.
- **Lab provenance:** none (new — the most common real AI-slop leak per `docs/research/ai-codegen-failure-modes.md`).

### SEC-04 · Private keys / connection strings in source · **high** · high
- **Detects:** PEM private-key blocks and DB/service connection URIs with embedded credentials.
- **Detection:** regex over string/template literals + raw text for `-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`
  and URI patterns `(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:@\s]+:[^@\s]+@`
  (i.e. a URI that carries `user:password@`).
- **`appliesTo`:** always.
- **Evidence:** the key header line / the URI with **password segment redacted**.
- **Fix:** env var; rotate; never commit private keys.
- **FP risk:** localhost URIs without a real password, `user:@`, `:password@` placeholder → the
  regex requires a non-empty, non-dummy password segment.
- **Lab provenance:** generalizes `hardcoded-secret` to non-provider secrets.

---

## 5. Category 2 — Injection & Code Execution (16 pts)

### INJ-01 · Dynamic code from input · **critical** · high
- **Detects:** RCE via `eval` / `new Function` / `vm` built from non-constant data.
- **Detection:** `call_expression` to `eval`; `new_expression` of `Function`; `vm.runIn…`,
  `vm.compileFunction` — where **at least one argument is not a static string literal** (contains
  an `identifier`, `template_string` with substitutions, or `binary_expression` concatenation). A
  constant-only `new Function('return 1')` is `info`, not a finding (structural constant check).
- **`appliesTo`:** always.
- **Evidence:** the `eval(...)` / `new Function(...)` call site.
- **Fix:** remove dynamic evaluation; use a lookup table / safe parser / explicit logic.
- **FP risk:** constant arguments (suppressed); known-safe DSL evaluators are still flagged but at
  the developer's judgement — evidence makes it verifiable.
- **Lab provenance:** `code-injection` (Lab: `/new Function\(|[^.\w]eval\(/`; we add the
  non-constant-argument gate to kill FPs on constant uses).

### INJ-02 · SQL / NoSQL injection · **critical** · medium
- **Detects:** queries built by string concatenation / interpolation of input.
- **Detection:** find query sinks — `.query(`, `.raw(`, `.$queryRawUnsafe(`, `.execute(`,
  template-tagged SQL, Mongo `.find/.$where` — whose argument is a `template_string` **with
  substitutions** or a `binary_expression` of `+` that includes a non-literal (esp. one traceable
  to `req`/`params`/`body`/`query` within the same function). Parameterized calls (placeholder +
  values array) are safe → not flagged.
- **`appliesTo`:** a DB client is present in `manifests` (pg, mysql2, mongodb, knex, sequelize,
  prisma-`$queryRawUnsafe`, drizzle-`sql.raw`) OR any query-sink call exists; else `info`.
- **Evidence:** the interpolated query string.
- **Fix:** parameterized queries / query builders / prepared statements.
- **FP risk:** interpolating a constant table name, or an already-escaped builder → `medium`
  confidence, and the rule prefers input-traceable interpolation. ORMs' safe methods excluded.
- **Lab provenance:** none (the Lab store was file-JSON, no SQL — new, high-value for real stores).

### INJ-03 · Command injection · **high** · high
- **Detects:** shell execution built from input.
- **Detection:** `child_process.exec/execSync` (shell:true implied) with a non-literal argument;
  `spawn/execFile` with `shell:true` and interpolated args. `exec` with a pure string literal → `low`.
- **`appliesTo`:** `child_process` imported/required; else N/A.
- **Evidence:** the exec/spawn call.
- **Fix:** `execFile` with an args array and no shell; validate/allowlist inputs.
- **FP risk:** constant commands → downgraded. 
- **Lab provenance:** none (new).

### INJ-04 · Unsafe deserialization / prototype pollution · **medium** · medium
- **Detects:** untrusted data into dangerous deserializers / recursive-merge sinks.
- **Detection:** `call_expression` to known-dangerous sinks — deprecated `node-serialize.unserialize`,
  `js-yaml.load` (non-`safeLoad`/legacy), `_.merge`/`Object.assign` into `{}` from
  request-derived objects, direct writes to `obj[userKey]` where `userKey` is input and no
  `__proto__`/`constructor` guard exists nearby.
- **`appliesTo`:** relevant sink present; else N/A.
- **Evidence:** the sink call.
- **Fix:** safe loaders (`yaml.load` in modern js-yaml is safe; avoid `node-serialize`); guard
  merge keys; `Object.create(null)` / `Map` for user-keyed data.
- **FP risk:** high without real taint tracking → **`--experimental` until fixture-validated**;
  emits `medium` at most.
- **Lab provenance:** none (new).

---

## 6. Category 3 — Access Control & Auth (17 pts)

### AUTH-01 · Sensitive route with no auth check · **critical** · medium
- **Detects:** an admin/sensitive endpoint served with no authentication.
- **Detection:** for each `Route` where `looksSensitive` (path matches
  `/admin|/internal|/orders?|/users?|/customers?|/payments?|/refunds?|/settings|/config`) OR
  `isMutating` on a sensitive resource: scan the handler body AST + its middleware chain for any
  **auth signal** — a reference to `req.user|req.auth|session|getServerSession|verify(JWT)|
  authorize|requireAuth|isAuthenticated|Authorization header read|token comparison|clerk/next-auth/
  passport/lucia middleware`. Absent any signal → finding.
- **`appliesTo`:** ≥1 sensitive route exists; else N/A (a marketing site has none).
- **Evidence:** the route definition line + "no auth check found in handler or middleware".
- **Fix:** require an authenticated session / bearer token; check authorization, not just authn.
- **FP risk:** auth applied by a global/app-level middleware the single-file view misses → the
  loader records app-level `.use(authMiddleware)` into the route's middleware chain to reduce this;
  still **`medium`** confidence because global-guard patterns vary. This is explicitly a
  "verify this" finding, framed as such.
- **Lab provenance:** `broken-access-control` (Lab: `routeBlock('/admin/orders')` lacks
  `authorization|ADMIN_TOKEN|token !==`; we generalize the route-set + auth-signal vocabulary).

### AUTH-02 · Missing authorization / IDOR · **high** · medium
- **Detects:** authenticated but not *authorized* — an object fetched by an id straight from
  input with no ownership check.
- **Detection:** in a route handler, a DB read keyed by `req.params.id|req.query.id|body.id` whose
  result is returned without a nearby comparison to `req.user.id|session.userId|ownerId`.
- **`appliesTo`:** routes + a DB/data layer present.
- **Evidence:** the id-keyed fetch + return.
- **Fix:** scope queries to the authenticated principal; verify ownership before returning.
- **FP risk:** high → `medium`, `--experimental` until validated on fixtures.
- **Lab provenance:** none (new — very common in AI-generated CRUD).

### AUTH-03 · Hardcoded / default credentials · **high** · high
- **Detects:** an auth decision compared against a literal or an env var with an insecure default.
- **Detection:** `binary_expression` `===`/`!==`/`==` comparing a request-derived token/password to
  a **string literal**; or `process.env.X || "<literal-default>"` where `X` names a token/secret and
  the default is a real-looking value (the Lab's `ADMIN_TOKEN || "admin-2024"`).
- **`appliesTo`:** always.
- **Evidence:** the comparison / defaulted env line.
- **Fix:** no in-source credentials; no insecure fallback defaults; fail closed if the env var is unset.
- **FP risk:** comparisons to non-secret constants (`role === 'admin'`) excluded by the token/secret
  name gate.
- **Lab provenance:** the Lab's `after/` used `ADMIN_TOKEN || "admin-2024"` — ironically itself a
  weak-default smell; vibecheck flags exactly this.

### AUTH-04 · Permissive CORS · **medium** · high
- **Detects:** `Access-Control-Allow-Origin: *` combined with credentials, or reflected origin.
- **Detection:** `cors({ origin: true|'*', credentials: true })`; manual
  `setHeader('Access-Control-Allow-Origin','*')` alongside `…-Allow-Credentials','true'`; or origin
  reflected straight from `req.headers.origin` with credentials.
- **`appliesTo`:** an HTTP server / API surface exists.
- **Evidence:** the CORS config / header lines.
- **Fix:** an explicit origin allowlist; never `*` with credentials.
- **FP risk:** `*` without credentials on a genuinely public read-only API → **`low`**, not medium.
- **Lab provenance:** none (new).

---

## 7. Category 4 — Commerce Logic Integrity (15 pts) ⭐ the wedge

*No generic SAST tool checks these — **verified in R0** ([`competitive-landscape.md`](research/competitive-landscape.md)):
a grep of Semgrep's entire 4,909-file rule tree found **zero JS/TS rules** for price/quantity/
discount/cart/order-IDOR; CodeQL puts business logic explicitly out of scope; Snyk/SonarQube ship
none; the closest OSS "vibe-coding" scanner (`vibe-audit`) and a 20-tool 2026 survey check none.
This category is the moat. Detection here is heuristic (`medium`) by nature — commerce logic
requires understanding a checkout flow — so evidence-quoting and honest confidence matter most.
Anchored on the Lab's negative-quantity vuln, extended across the buy flow.*

> **v0.1.0 leads with COM-02 only (CTO review F3).** COM-02 is **[STRUCTURAL]** — the Lab's exact,
> structurally-detectable negative-qty/price-tamper exploit → high confidence, on by default. It is
> the commerce flagship and the *provable* claim: *"detects the price/quantity-tampering class
> generic SAST misses."* **COM-01/03/04 are [FLOW] `--experimental` ("beta, expanding")** — real but
> lower-confidence; we do **not** market "full commerce-logic coverage" until they pass §3.1. The
> wedge paradox — the category we sell hardest is the lowest-confidence — is managed by leading with
> the one commerce check we can prove.

### COM-01 · Price / total trusted from the client · **critical** · medium
- **Detects:** the server computes an order total from a client-supplied price/amount instead of
  looking it up server-side.
- **Detection:** in a checkout/cart/order/payment route (`looksSensitive` or path matches
  `/checkout|/cart|/order|/pay|/charge`), a total/amount that flows from `body.price|body.amount|
  body.total|body.unitPrice` (rather than from a product looked up by id in a server data source);
  esp. a Stripe/PayPal charge whose `amount` comes from the request body.
- **`appliesTo`:** a checkout/payment route exists.
- **Evidence:** the line where `amount/total` is read from the request or passed to the charge call.
- **Fix:** derive price from the server-side product record; never trust client amounts.
- **FP risk:** medium — quote the flow so the dev can confirm.
- **Lab provenance:** adjacent to the Lab's checkout (which at least looked price up by id — the
  anti-pattern is trusting `body.price`).

### COM-02 · Quantity / amount not validated · **high** · high
- **Detects:** negative/zero/overflow/non-integer quantity or amount → price theft (buy −5, get
  a refund).
- **Detection:** in a checkout/cart route, a `qty|quantity|amount|count` read from the request that
  reaches an arithmetic/order op **without** a validating guard nearby — no `Number.isInteger`, no
  `< 1`/`<= 0`/`> max` range check, no zod/joi/yup schema on that field.
- **`appliesTo`:** a checkout/cart/order route exists.
- **Evidence:** the unvalidated `qty` usage (`const total = prod.price * qty` with no guard).
- **Fix:** validate as an integer in a sane range (the Lab's `after/`: `Number.isInteger(qty) && 1–99`).
- **FP risk:** low — the "no validation node in the handler" check is reliable; **high** confidence.
- **Lab provenance:** `missing-input-validation` (Lab: `/checkout` block lacks `Number.isInteger`).
  This is the flagship commerce check and the exact Lab exploit.

### COM-03 · No server-side inventory / availability check · **medium** · medium
- **Detects:** an order is created without verifying stock/availability server-side.
- **Detection:** an order-create/persist op in a checkout route with no read of a
  `stock|inventory|quantityAvailable|available` field between product lookup and order creation.
- **`appliesTo`:** a checkout/order route + a product/inventory data model exists.
- **Evidence:** the order-create call with no preceding stock check.
- **Fix:** check and decrement inventory transactionally before confirming.
- **FP risk:** high (inventory may live in an external system) → `medium`, `--experimental`.
- **Lab provenance:** none (new commerce-logic extension).

### COM-04 · Discount / coupon applied without server validation · **medium** · medium
- **Detects:** a discount/coupon/promo taken from the request and applied without server validation.
- **Detection:** a `discount|coupon|promo|voucher|percentOff` value from `body`/`query` used in the
  total computation with no lookup/validation against a server coupon source.
- **`appliesTo`:** discount/coupon vocabulary appears in a checkout/cart route.
- **Evidence:** the client-supplied discount applied to the total.
- **Fix:** validate coupon codes server-side; compute the discount from the trusted record.
- **FP risk:** medium → `--experimental` until validated.
- **Lab provenance:** none (new).

---

## 8. Category 5 — Web Exposure (10 pts)

### WEB-01 · Reflected / stored XSS · **high**
- **Tier:** cases (b)+(c) — **[STRUCTURAL]** (high, v0.1.0): `dangerouslySetInnerHTML={{__html:
  <non-constant>}}` and `el.innerHTML = <non-constant>` are structural sinks. Case (a)
  server-template interpolation = **[FLOW] `--experimental`** (needs input-trace). v0.1.0 ships (b)+(c).
- **Detects:** untrusted input rendered into HTML without escaping.
- **Detection:** (a) server: a `template_string` used as an HTML response body
  (`res.send/res.end/new Response`, `content-type: text/html`) that contains a `${…}` substitution
  traceable to input and not wrapped in an escaper (`escapeHtml|esc|DOMPurify|he.encode`). (b)
  React/JSX: `dangerouslySetInnerHTML={{ __html: <non-constant> }}`. (c) `el.innerHTML = <input>`.
- **`appliesTo`:** an HTML-producing surface exists (server HTML responses OR JSX/DOM).
- **Evidence:** the interpolated HTML sink.
- **Fix:** HTML-escape output; sanitize with DOMPurify; avoid `dangerouslySetInnerHTML`.
- **FP risk:** interpolating already-escaped or constant/non-user values → `medium`; the input-trace
  raises confidence when the value comes from `req`/props/state.
- **Lab provenance:** `reflected-xss` (Lab: literal `/<h1>Results for \$\{q\}/`; we generalize to
  any input-derived HTML template substitution + JSX/DOM sinks).

### WEB-02 · SSRF · **high** · medium
- **Detects:** the server fetches a URL supplied by the user.
- **Detection:** `fetch/axios/got/http.request` whose URL argument flows from
  `req.query|body|params` with no host allowlist/validation nearby.
- **`appliesTo`:** a server surface makes outbound requests.
- **Evidence:** the outbound call with the request-derived URL.
- **Fix:** allowlist hosts; resolve+validate the IP; block internal ranges. *(this is literally the
  agentready SSRF lesson — vibecheck detects in others what agentready had to fix in itself.)*
- **FP risk:** medium → quote the flow.
- **Lab provenance:** none (new; notable given agentready's own C1 SSRF finding).

### WEB-03 · Path traversal · **medium** · medium
- **Detects:** user input flows into a filesystem path.
- **Detection:** `fs.readFile/readFileSync/createReadStream/sendFile` / `path.join` whose argument
  includes `req.query|params|body` with no normalization + base-dir containment check.
- **`appliesTo`:** filesystem access with request-derived paths.
- **Evidence:** the fs call with the tainted path.
- **Fix:** normalize + confine to a base dir; reject `..`; prefer an id→path map.
- **FP risk:** medium.
- **Lab provenance:** none (new).

---

## 9. Category 6 — Performance & Scale (8 pts)

### PERF-01 · Synchronous I/O on the request hot path · **high** · high
- **Detects:** blocking `*Sync` I/O inside a request handler → serializes the event loop.
- **Detection:** any `readFileSync|writeFileSync|existsSync|readdirSync|execSync|
  <crypto>Sync|deflateSync` call whose enclosing function is (transitively) a `Route.handlerNode`.
  Boot-time / module-scope sync I/O is fine → **only flag inside handler bodies** (the Lab's
  `handlerOf` insight, done structurally via the route map).
- **`appliesTo`:** ≥1 server route exists.
- **Evidence:** the `*Sync` call + its route.
- **Fix:** async I/O; or load-once-at-boot + serve from memory (the Lab's `after/` — 680 → 33k req/s).
- **FP risk:** low — the handler-scope gate is reliable; **high** confidence.
- **Lab provenance:** `sync-fs-on-hot-path` (Lab: `/readFileSync|writeFileSync/` in `handlerOf(src)`;
  we generalize the sync-call set + use the real route map instead of a string slice).

### PERF-02 · Full-dataset read/parse per request · **medium** · medium
- **Detects:** re-reading + `JSON.parse`-ing an entire data file (or unbounded `find()`) on every request.
- **Detection:** inside a handler, a `JSON.parse(readFileSync(...))` pattern, or a DB `find()`/
  `findMany()` with no `limit|take|WHERE` returning a whole collection, executed per-request.
- **`appliesTo`:** routes + a data layer.
- **Evidence:** the per-request full read.
- **Fix:** load-once + index in memory (the Lab's `byId`/`byCat` Maps); paginate DB reads.
- **FP risk:** medium.
- **Lab provenance:** the Lab's `db()` re-parsed the 733 KB store every request — generalized.

### PERF-03 · N+1 / unbounded query · **low** · medium
- **Detects:** a DB query inside a loop, or list endpoints with no pagination.
- **Detection:** an `await <db>.…` call whose enclosing node is a `for|while|.map|.forEach` body; or
  a collection fetch with no `limit`/`take`/pagination in a list route.
- **`appliesTo`:** a DB/data layer + routes.
- **Evidence:** the query inside the loop.
- **Fix:** batch/join; add pagination.
- **FP risk:** medium → `low` severity keeps score impact small.
- **Lab provenance:** none (new).

---

## 10. Category 7 — Production Hardening (9 pts)

### PROD-01 · No rate limiting · **medium** · medium
- **Detects:** a public mutating/auth surface with no rate limiter anywhere.
- **Detection:** **repo-level** — no dependency on a known limiter (`express-rate-limit`,
  `@upstash/ratelimit`, `rate-limiter-flexible`, `@fastify/rate-limit`, `hono` limiter, Next
  middleware limiter) AND no hand-rolled fixed-window limiter pattern (a `Map` keyed by IP with a
  time window — the Lab's `limited()`), while ≥1 mutating/auth route exists.
- **`appliesTo`:** ≥1 mutating or auth route exists; a static site → N/A (**the exact
  stack-neutrality guard** — don't ding a brochure site for "no rate limiting").
- **Evidence:** "no rate limiter found; N mutating routes exposed" (repo-level, not a single line).
- **Fix:** add a limiter on auth + mutating endpoints.
- **FP risk:** a limiter at the edge (Cloudflare/WAF/API gateway) the code can't see → framed as
  "no *application-level* limiter", `medium`.
- **Lab provenance:** `no-rate-limit` (Lab: `!/limited\(/`; we generalize to the dependency +
  pattern set and gate on route existence).

### PROD-02 · Missing input validation on mutating endpoints · **medium** · medium
- **Detects:** a mutating handler that reads `req.body` fields with no schema/validation.
- **Detection:** an `isMutating` route whose handler reads ≥1 `body.*` field and has **no**
  validation signal (zod/joi/yup/valibot/ajv/class-validator parse, or manual `typeof`/`Number.isInteger`/
  range guards) before use.
- **`appliesTo`:** ≥1 mutating route.
- **Evidence:** the unvalidated `body` usage.
- **Fix:** validate request bodies with a schema at the boundary.
- **FP risk:** medium (validation can be centralized) — the loader records middleware validators to reduce it.
- **Lab provenance:** generalizes `missing-input-validation` beyond checkout to all mutating routes
  (COM-02 is the commerce-specific, higher-severity special case).

### PROD-03 · Internal errors leaked to the client · **low** · high
- **Detects:** raw error / stack returned in a response.
- **Detection:** `res.send/json/end` or `Response` whose argument includes `err.message|err.stack|
  String(e)|e.toString()` (the Lab's `error: ${e.message}` and `error: String(e.message)`).
- **`appliesTo`:** a server surface.
- **Evidence:** the error-leaking response line.
- **Fix:** log server-side; return a generic message + correlation id.
- **FP risk:** low — **high** confidence.
- **Lab provenance:** the Lab returned `e.message` to clients — flagged.

### PROD-04 · Debug mode on / secrets in logs · **low** · medium
- **Detects:** debug flags hardwired on, or secrets written to logs.
- **Detection:** `NODE_ENV === 'development'` forced / `debug: true` on a framework config in a
  non-dev file; `console.log/logger.info` whose argument references a secret-named var or
  `process.env.<secret>`.
- **`appliesTo`:** always.
- **Evidence:** the debug flag / logging line.
- **Fix:** gate debug by real env; never log secrets.
- **FP risk:** medium.
- **Lab provenance:** none (new).

---

## 11. Category 8 — Dependencies & Config (5 pts)

### DEP-01 · Known-vulnerable dependencies · **high** · **[FLOW-tier ship] `--experimental` / v0.1.x**
- **Tier:** not a v0.1.0 structural check — ships in a v0.1.x once the fetch-cache + matcher are
  solid (CTO F6). High confidence once shipped, but deferred to keep v0.1.0 lean.
- **Detects:** declared dependencies with known CVEs/advisories.
- **Detection:** parse the lockfile (`package-lock.json`/`pnpm-lock.yaml`/`yarn.lock`) → resolved
  name@version set → semver-match against an OSV advisory DB. **Data source: OSV.dev npm subset**
  (`gs://osv-vulnerabilities/npm/all.zip`), **fetch-on-first-run + local cache, NOT bundled** (CTO
  F6 — the snapshot is 10s of MB; bundling it guts the `npx` DX and it goes stale between releases).
  Offline + uncached → a helpful "run once online to fetch the advisory DB" message. **Chosen on
  licensing (the deciding constraint):**
  OSV's npm records inherit **CC-BY 4.0** from GHSA — attribution-only, cleanly compatible with an
  MIT tool (code stays MIT, data stays CC-BY behind a `NOTICE` line). It aggregates GHSA, the source
  of truth that powers `npm audit`, so coverage ≈ `npm audit` **without** its online-only API. Snyk
  DB (proprietary) and the npm registry API (online-only, not redistributable) both rejected. Full
  analysis: [`docs/research/secrets-and-deps.md`](research/secrets-and-deps.md) §B. `--verbose` shows
  GHSA ids. ⚠️ *Legal to confirm before first release: exact CC-BY attribution wording + no
  mixed-license records in the npm export.*
- **`appliesTo`:** a lockfile exists (else "no lockfile — can't resolve exact versions", `info`).
- **Evidence:** `pkg@ver — GHSA-xxxx (high): <title>`.
- **Fix:** upgrade to the patched range.
- **FP risk:** dev-only deps → lower weight than runtime deps; unreachable advisories noted honestly.
- **Lab provenance:** none (Lab was zero-dependency — new, and important since real stores aren't).

### DEP-02 · Missing security headers · **low** · medium
- **Detects:** an HTML-serving app with no security headers / CSP.
- **Detection:** an HTML surface exists but no `helmet()` dep/usage and no manual
  `Content-Security-Policy|X-Frame-Options|Strict-Transport-Security` header setting / Next
  `headers()` security config.
- **`appliesTo`:** the app serves HTML (SSR/SSG/HTML responses); a pure JSON API → N/A.
- **Evidence:** "HTML served; no CSP / security headers found".
- **Fix:** add helmet / Next security headers / a CSP.
- **FP risk:** headers set at the edge → framed as "no app-level headers", `low`.
- **Lab provenance:** none (new).

### DEP-03 · No tests present · **info** · high
- **Detects:** no test suite — a production-readiness signal, not a vuln.
- **Detection:** no `*.test.*`/`*.spec.*`/`__tests__`/`cypress`/`playwright` files and no test
  script in `package.json`.
- **`appliesTo`:** always, but **`info` severity → 0-weight**, reported as a readiness note, never a
  score deduction (honesty: absence of tests isn't a security hole).
- **Evidence:** "no test files or test script detected".
- **Fix:** add tests for the checkout + auth paths first.
- **Lab provenance:** none (new; the strategy lists "missing tests" as a readiness signal).

---

## 12. Lab-rule → vibecheck-check provenance (the "70%" made concrete)

| Lab rule (`scan.js`) | Lab detection (demo-specific) | vibecheck check(s) | Generalization |
|---|---|---|---|
| `code-injection` | `/new Function\(|eval\(/` | **INJ-01** | + non-constant-argument gate, `vm` sinks |
| `hardcoded-secret` | `/sk_live_[A-Za-z0-9]+/` | **SEC-01, SEC-02, SEC-04** | full provider set + entropy + client-boundary + PEM/URIs |
| `broken-access-control` | `routeBlock('/admin/orders')` lacks auth tokens | **AUTH-01** | framework route map + auth-signal vocabulary + sensitive-path set |
| `reflected-xss` | literal `<h1>Results for ${q}` | **WEB-01** | any input-derived HTML template + JSX/DOM sinks |
| `sync-fs-on-hot-path` | `/readFileSync|writeFileSync/` in `handlerOf` | **PERF-01** | full sync-call set + real route map |
| `missing-input-validation` | `/checkout` lacks `Number.isInteger` | **COM-02, PROD-02** | all mutating routes; commerce-specific negative-qty special case |
| `no-rate-limit` | `!/limited\(/` | **PROD-01** | limiter dependency + pattern set + route-existence gate |
| *(exploit.js 5 probes)* | live attacks on Lab routes | **`prove` mode — DEFERRED (post-v0.1, CTO F4)** | re-templated per route; localhost-only; separately reviewed |
| *(loadtest.js)* | throughput on Lab routes | **`perf` mode — DEFERRED (post-v0.1)** | optional; not a static check |

**New checks with no Lab precedent** (real-store necessities surfaced in R0): SEC-03, INJ-02,
INJ-03, INJ-04, AUTH-02, AUTH-03, AUTH-04, COM-01, COM-03, COM-04, WEB-02, WEB-03, PERF-02,
PERF-03, PROD-03, PROD-04, DEP-01, DEP-02, DEP-03. → The Lab is a genuine head-start on
methodology + 7 anchor rules + fixtures, but **18 of 28 checks are net-new** — matches §2's
honest reality-check.

---

## 13. CTO decisions (the six open questions — RESOLVED)

All six were answered in the CTO review ([cto-review-r0.md](cto-review-r0.md)) and are now
reflected throughout this doc. Recorded here for the sign-off trail:

1. **Confidence gating** — ✅ **Yes, and wider.** The whole **flow tier** + the **entropy layer**
   (§4 SEC-01) + **git-history** (SEC-03) are all `--experimental`/off by default. Graduation is
   per-check, earned via the §3.1 precision gate — not by calendar.
2. **Score weighting** — ✅ **Secrets 20 · Auth 17 · Injection 16 · Commerce 15 · Web 10 · Perf 8 ·
   Prod 9 · Deps 5** (AUTH↑ per breach data §1.1). Weights are a calibration parameter → **re-locked
   after the fixture corpus is scored**; Commerce **not** inflated for marketing.
3. **Publishable keys** (`pk_live_`) — ✅ **`low/info`.** (§4 SEC-01.)
4. **git-history pass** — ✅ **OFF / opt-in `--git-history` (CLI only); hosted = working-tree only.**
   (§4 SEC-03.)
5. **Dependency data source** — ✅ **OSV.dev npm subset (CC-BY 4.0), fetch-cache not bundled** (§11
   DEP-01, CTO F6); DEP-01 ships v0.1.x. Legal confirms CC-BY attribution wording before release.
6. **`prove` mode safety** — ✅ **Deferred out of v0.1 entirely** (CTO F4); returns post-launch behind
   a separately-reviewed, localhost-only model. (§1.2, §12.)

**Kansha's remaining sign-off** is now a yes/no on this revised spec + the precision-gate acceptance
criteria (§3.1), not an open-question review.

---

## 14. Fixture corpus plan (gather in Sprint 0 via `record-fixture`)

R0 pins *what* fixtures we need; Sprint 0's `record-fixture` mode captures them (cloning real
repos is a scaffold task, not a research one). The accuracy gate = these fixtures scoring as
expected:

| Fixture | Role | Expected |
|---|---|---|
| `lab-before` (from `ai-cleanup-lab/before`) | **anchor: vulnerable** | lights up SEC-01/02, INJ-01, AUTH-01/03, COM-02, WEB-01, PERF-01/02, PROD-01/02/03 → **F** |
| `lab-after` (from `ai-cleanup-lab/after`) | **anchor: hardened (regression gate)** | near-clean → **A/B**; any regression here fails CI |
| 2–3 real AI-codegen commerce repos (Lovable/Bolt/Cursor/v0 output, public) | real-world true-positives | graded, findings manually confirmed |
| 1–2 well-built commerce repos (e.g. a clean Next.js/Medusa starter) | **false-positive gate** | high grade, ~zero criticals |
| 1 static marketing site (no server) | **stack-neutrality gate** | route-dependent categories → `info`/excluded, not `fail` |

---

## R0 status

**Research folded in (all sources dated 2026-07-15):**
- ✅ `docs/research/secrets-and-deps.md` → SEC-01 provider table + entropy fallback; DEP-01 = OSV.dev npm (CC-BY 4.0)
- ✅ `docs/research/competitive-landscape.md` → wedge verified (Semgrep 0 commerce rules); positioning locked
- ✅ `docs/research/ai-codegen-failure-modes.md` → §1.1 evidence base, weighting nudge, real incidents, stat correction

**R0 complete · CTO review done (conditionally approved) · review edits applied to this doc.**
Two-tier model (§1.2), precision gate (§3.1), F8 route-honesty (§2.1), weights (§13.2), deferrals
(`prove`/entropy/git-history), and the COM-02-led commerce framing (§7) are all folded in.

**Remaining before Sprint 1:** Kansha's final yes/no on this revised spec + §3.1 gate; CEO name
ratify; legal OSV CC-BY wording. **Sprint 0** scaffold (loader + tests + WASM-serverless spike +
SEC-01) is engine-neutral and can start in parallel now. **Sprint 1** builds the §1.2 **structural
tier** against the §14 fixtures; **Sprint 2** ships v0.1.0; **Sprint 3** graduates the flow tier.
