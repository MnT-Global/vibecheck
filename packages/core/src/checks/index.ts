import type { Check, ScanContext } from "../types.js";
import { auth01 } from "./auth-01.js";
import { auth03 } from "./auth-03.js";
import { auth04 } from "./auth-04.js";
import { com01 } from "./com-01.js";
import { com02 } from "./com-02.js";
import { dep03 } from "./dep-03.js";
import { inj01 } from "./inj-01.js";
import { inj02 } from "./inj-02.js";
import { inj03 } from "./inj-03.js";
import { perf01 } from "./perf-01.js";
import { perf02 } from "./perf-02.js";
import { prod01 } from "./prod-01.js";
import { prod03 } from "./prod-03.js";
import { prod04 } from "./prod-04.js";
import { sec01 } from "./sec-01.js";
import { sec02 } from "./sec-02.js";
import { sec03 } from "./sec-03.js";
import { sec04 } from "./sec-04.js";
import { web01 } from "./web-01.js";
import { web02 } from "./web-02.js";
import { web03 } from "./web-03.js";

/** Every check known to the engine. Structural = on by default; flow = experimental-only. */
export const ALL_CHECKS: Check[] = [
  // structural tier (on by default)
  sec01,
  sec02,
  sec03,
  sec04,
  inj01,
  inj03,
  perf01,
  prod03,
  com02,
  auth03,
  auth04,
  web01,
  dep03,
  // flow tier (--experimental)
  auth01,
  com01,
  inj02,
  web02,
  web03,
  perf02,
  prod01,
  prod04,
];

/** Checks active for this scan: structural always, flow only under --experimental (ADR-001). */
export function activeChecks(ctx: ScanContext): Check[] {
  return ALL_CHECKS.filter((c) => c.tier === "structural" || ctx.options.experimental);
}
