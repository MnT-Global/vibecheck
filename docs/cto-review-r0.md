# CTO Review — vibecheck R0 Spec (`rules.md`)

**Reviewer:** Acting CTO (Kansha's sign-off seat) · **Date:** July 15, 2026
**Artifact under review:** [`rules.md`](rules.md) + [`VIBECHECK-BUILD-PLAN.md`](../../VIBECHECK-BUILD-PLAN.md)
**Verdict:** 🟡 **CONDITIONALLY APPROVED** — proceed to **Sprint 0 scaffold now**; **5 changes are
mandatory before Sprint 1 scoring locks.** This is *not* a clean sign-off. The spec is strong on
taxonomy and honest framing, but it under-specifies the two things that decide whether a
security-brand tool lives or dies: **the accuracy ceiling of its flow-dependent checks**, and
**how we measure false positives before we ship.**

---

## 0. Why not a clean approval

The spec's own honesty policy is correct ("false critical hurts a security brand worse than
agentready's false grade"). But the plan then lists **28 checks** — and ~16 of them are, by the
spec's own admission, `medium`-confidence heuristics over a **single-file, syntax-only (tree-sitter)**
view of code, for problems (auth coverage, secret-reaches-client, price-trusted-from-client) that
are inherently **cross-file data-flow** problems. Marketing leads with the commerce wedge — which
is exactly the lowest-confidence tier. That gap between *what we sell* and *what we can reliably
detect* is the whole risk. Everything below closes it.

---

## Part 1 — ADR-001: Analysis engine & the confidence ceiling

**Status:** Accepted (with a v0.2 escalation trigger)

### Context
Checks are pure functions over a `ScanContext`. The spec picks **tree-sitter** for the AST. But
tree-sitter gives **syntax only** — no types, no scope resolution, no cross-file symbol/dataflow.
Our marquee checks need exactly what tree-sitter lacks:
- **AUTH-01/02** — "does *any* middleware in the chain, possibly registered in another file, guard
  this route?" = cross-file.
- **SEC-02** — "does this secret *reach* a client bundle?" = module-graph reachability.
- **COM-01 / INJ-02 / WEB-01(server)** — "does this value *flow* from `req.body`?" = intra- (often
  inter-) procedural taint.

The spec quietly pushes the hard problem **into the loader** (route + middleware-chain + client-
boundary extraction). That doesn't remove the difficulty — it relocates it to an un-speced,
un-tested component. **This is the central architecture risk, and it was hand-waved.**

### Options

| Option | Complexity | Accuracy on flow checks | Speed | Multi-lang | Serverless (hosted) |
|---|---|---|---|---|---|
| **A. tree-sitter only** (current spec) | Low | **Low–Med** (syntax only; you hand-build every flow heuristic) | Fast | Yes (Python next) | WASM — **unproven, must validate** |
| **B. TS compiler API / ts-morph** | High | High (types, scope, cross-file refs) | Slow, heavy | JS/TS **only** | Heavy cold-start |
| **C. Hybrid — tree-sitter for structural checks + a scoped intra-file scope-tracker (`@typescript-eslint/scope-manager` or `oxc`) for the flow-tier** | Med | Med–High where it counts | Fast-ish | JS/TS deep, others structural-only | Validate early |

### Decision
**Adopt A (tree-sitter) for v0.1 as the single engine, but make the confidence ceiling explicit and
structural, not aspirational:**

1. **Two check classes, enforced in code:**
   - **Structural checks** (tree-sitter is *sufficient* and near-exact): SEC-01/03/04, INJ-01,
     INJ-03, AUTH-03/04, COM-02, PERF-01, PROD-03, WEB-01(JSX `dangerouslySetInnerHTML`/`innerHTML`
     sinks), DEP-03. These may emit **`high`** confidence and are **on by default**.
   - **Flow checks** (need dataflow tree-sitter can't give): AUTH-01/02, SEC-02(response-flow case),
     COM-01/03/04, INJ-02, INJ-04, WEB-01(server-template case)/02/03, PERF-02/03, PROD-01/02/04.
     Capped at **`medium`**, **`--experimental` / off by default** until a fixture proves precision.
2. **v0.2 escalation trigger (written now):** if, on the fixture corpus, the flow-tier's precision
   is < the §3 gate with tree-sitter heuristics, we add **Option C's scope-tracker** for the JS/TS
   flow checks in v0.2 — *not* a rewrite, an additive analyzer behind the same `Check` interface.
   The pure-function-over-ScanContext boundary makes this swap local. That optionality is the
   reason to keep the engine boundary clean now.

### Consequences
- ✅ v0.1 ships fast, the structural tier is genuinely reliable, the interface survives a v0.2
  engine upgrade.
- ⚠️ The loader's route/middleware/client-boundary extractor is now a **first-class, spec'd,
  fixture-tested component** — not an incidental helper. **Sprint 0 must include its own test
  suite.** (New action item.)
- ⚠️ **tree-sitter-WASM on the hosted serverless runtime is unproven** and agentready already taught
  us this exact lesson (undici custom lookup hung on Vercel). → **Mandatory Sprint 0 spike**
  (§4.C) before any hosted work.

---

## Part 2 — Critical findings (ranked; each has a required change)

### 🔴 F1 — No measurable precision gate. *(blocks Sprint 1 sign-off)*
The spec says "high-confidence only" but defines **no numeric acceptance criteria**. "We tried to
be accurate" is not a gate a CTO can sign. **Required:** add §3's precision gate to `rules.md` and
make it a CI gate. A check cannot graduate from `--experimental` to on-by-default until it passes.

### 🔴 F2 — v0.1.0 scope is too wide for the brand bar. *(blocks — scope change)*
28 checks, ~16 of them medium/flow. The strategy's own rule is "one sloppy repo kills 'senior by
default'." **Required:** v0.1.0 ships the **structural tier only** (~12 checks, §5). The flow tier
ships progressively in v0.1.x/v0.2 as fixtures validate each. Fewer, exact checks > many shaky ones.

### 🟠 F3 — The commerce wedge is the *lowest*-confidence tier, but marketing leads with it.
COM-01/03/04 are `medium`/experimental. If a founder runs vibecheck *for* the commerce magic and
gets a false positive (or a missed bug), the wedge backfires and the launch narrative dies.
**Required:** lead the commerce story with **COM-02 only** (negative-qty / price-tamper — it's the
Lab's exact exploit and is **structurally detectable = high confidence**). Market it precisely:
*"detects the price/quantity-tampering class that generic SAST misses"* — provable — **not** "full
commerce-logic coverage." COM-01/03/04 are "beta, expanding," honestly labelled.

### 🟠 F4 — `prove` mode is a launch liability, not a v0.1 feature.
A tool that fires real RCE/injection payloads at a target is a legal, abuse, and support surface we
do not need to ship value. Localhost-gating reduces but doesn't erase it. **Decision (§4.6): defer
`prove` out of v0.1 entirely.** Ship the static scanner; add `prove` post-launch behind a hardened,
separately-reviewed safety model. It's a great differentiator with no deadline pressure.

### 🟠 F5 — The secrets **entropy layer** is default-on in the worst-possible corpus.
Our target input — AI-generated code — is saturated with example hashes, base64 data-URIs, and
mock tokens: the exact false-positive fuel for entropy detection. **Required:** entropy fallback is
**`--experimental`, off by default** in v0.1. The provider-pattern layer (deterministic, high
precision) is the default secrets engine. Turn entropy on only after the clean fixtures prove an
acceptable FP rate.

### 🟡 F6 — DEP-01's bundled OSV snapshot will bloat `npx` and is stale-by-design.
The OSV npm `all.zip` is large (verify: likely 10s of MB). Bundling it into the published package
guts the "`npx` and go" DX and it's stale between releases. **Decision:** DEP-01 uses **fetch-on-
first-run + local cache** (osv-scanner's own pattern), with a helpful message if offline and
uncached — **not** a bundled snapshot. If that's not ready for v0.1.0, **defer DEP-01 to v0.1.x**.
Keep the CLI lean.

### 🟡 F7 — Git-history secret scan: unbounded cost, wrong default.
`git log -p` on a real repo is slow/memory-heavy and, for hosted clone→scan→delete-in-minutes,
can blow the time budget. **Decision (§4.4): default OFF**, opt-in `--git-history` (CLI only);
hosted mode is **working-tree only**, always.

### 🟡 F8 — Loader route-extraction fragility = silent false negatives.
If the loader fails to recognize a framework's routing (custom router, a meta-framework, an unusual
Hono/Elysia setup), every route-dependent check silently under-reports — a **false sense of
safety**, the worst outcome for a security tool. **Required:** when the loader finds source that
looks server-side but extracts **zero routes**, the report must emit an explicit **`info`:
"couldn't map routes for framework X — auth/commerce/perf checks may be incomplete."** Honesty over
a silent pass. (This is the agentready soft-404 lesson: never let "found nothing" read as "all clear.")

---

## Part 3 — Decisions on the six open questions (`rules.md` §13)

| # | Question | **CTO decision** |
|---|---|---|
| 1 | Confidence gating — medium checks behind `--experimental`? | **Yes, and wider:** the entire **flow tier** (ADR-001), the **entropy layer** (F5), and **git-history** (F7) are all `--experimental`/off by default. Graduation is earned per-check via the §3 precision gate, not by calendar. |
| 2 | Score weighting | **Don't hand-tune pre-data — weights are a calibration parameter, not architecture.** Encode the one evidenced nudge now (breach data → AUTH): **Secrets 20 · Auth 17 · Injection 16 · Commerce 15 · Web 10 · Perf 8 · Prod 9 · Deps 5.** Re-lock all weights *after* the fixture corpus is scored. Do **not** inflate Commerce for marketing (F3). |
| 3 | Publishable-key (`pk_live_`) severity | **`low/info`.** Accepted. It's public by design; flag only as "confirm this isn't a mistyped secret key." |
| 4 | Git-history default | **OFF / opt-in (CLI only); hosted = working-tree only.** (F7.) |
| 5 | Dependency data source | **OSV.dev npm subset (CC-BY 4.0) accepted** — but via **fetch-and-cache, not a bundled snapshot** (F6); DEP-01 may slip to v0.1.x. Legal confirms CC-BY attribution wording before the check ships. |
| 6 | `prove`-mode safety | **Deferred out of v0.1 (F4).** Revisit post-launch with a dedicated safety review; localhost-only default was necessary but not sufficient reason to ship it in the first release. |

---

## Part 4 — New mandatory gates (added to the release checklist)

### §3 Precision gate (the missing acceptance criteria) — **add to `rules.md`**
On the fixture corpus (§14), before any check is on-by-default:
- **Zero false criticals** on the clean/well-built fixtures. (A single false critical is a launch-blocker.)
- **`lab-after` scores ≥ B**; **`lab-before` scores F** — reproduced in CI on every commit (regression gate).
- **False-positive rate ≤ 10%** on the clean fixtures for any on-by-default check; a check exceeding
  it drops back to `--experimental`.
- Every finding on the AI-codegen fixtures is **manually confirmed** true/false and recorded, so we
  have a real precision number per check at launch (and can publish it — "honesty over hype" as data).

### §4.C tree-sitter-WASM serverless spike — **Sprint 0, before hosted work**
Prove grammar-WASM loads and runs inside the target hosted runtime (Vercel/Node serverless) with an
acceptable cold-start, on a real file, in CI. Explicitly closing the agentready "engine-broke-on-
serverless" class of failure *before* Sprint 5, not during it.

### Loader test suite — **Sprint 0**
Route/middleware/client-boundary extraction gets its own fixture-driven tests (per ADR-001). This
component is now load-bearing; treat it like one.

---

## Part 5 — Revised v0.1.0 scope (the cut list)

**Ships in v0.1.0 (structural tier — high confidence, on by default):**
Secrets **SEC-01, SEC-03, SEC-04** (+ SEC-02 public-prefix case only) · Injection **INJ-01, INJ-03**
· Auth **AUTH-03, AUTH-04** · Commerce **COM-02** (the flagship, provable) · Web **WEB-01 JSX/DOM-sink
case** · Perf **PERF-01** · Prod **PROD-03** · Deps **DEP-03** (info). **≈ 12 checks, 6 categories,
each reliable.** Secrets provider-pattern layer only (no entropy). This is a genuinely strong,
honest first release.

**Ships progressively in v0.1.x / v0.2 (flow tier — as each passes §3):**
AUTH-01/02, SEC-02(response-flow), COM-01/03/04, INJ-02/04, WEB-01(server)/02/03, PERF-02/03,
PROD-01/02/04, DEP-01/02, entropy layer, `prove` mode. Each graduates with a published precision
number. The public roadmap shows this ladder — turning our honesty into a feature.

**Scoring with a partial check set:** the stack-neutral denominator (already spec'd) handles this
cleanly — un-shipped checks are simply absent from the denominator, so early grades stay fair and
comparable. Confirm this in the scorer's tests.

---

## Part 6 — Conditions to clear before Sprint 1 (sign-off checklist)

- [ ] `rules.md` updated: add the **§3 precision gate**; mark the **flow tier + entropy + git-history**
      as `--experimental`/off-by-default (ADR-001, F1, F5, F7); re-label the **commerce story around
      COM-02** (F3); set weights per Q2; **defer `prove`** (F4) and **DEP-01→fetch-cache/v0.1.x** (F6).
- [ ] `rules.md` §2: promote loader route-extraction to a spec'd component + **F8 "routes-unmapped"
      honesty `info`**.
- [ ] Build plan: move **v0.1.0 scope to the Part-5 cut list**; add the **WASM-serverless spike** and
      **loader test suite** to Sprint 0; move `prove`/`perf` and DEP-01 down the roadmap.
- [ ] Legal: OSV CC-BY attribution wording (Q5).
- [ ] Then: **Sprint 0 scaffold proceeds in parallel now** (it's engine-neutral); **Sprint 1 starts
      once the above edits land.**

**Bottom line:** the thinking is sound and the wedge is real (verified). The plan's failure mode was
optimism about detection accuracy on the flow-dependent checks and an over-wide v0.1. Narrow the
first release to what tree-sitter can prove, gate everything else on measured precision, kill the
`prove`-mode risk for now — and this becomes a launch that *strengthens* the "we make commerce
secure" brand instead of betting it on heuristics. **Conditionally approved on that basis.**
