import type { Check, ScanContext } from "../types.js";
import { com02 } from "./com-02.js";
import { dep03 } from "./dep-03.js";
import { inj01 } from "./inj-01.js";
import { perf01 } from "./perf-01.js";
import { prod03 } from "./prod-03.js";
import { sec01 } from "./sec-01.js";
import { sec04 } from "./sec-04.js";

/** Every check known to the engine. Structural = on by default; flow = experimental-only. */
export const ALL_CHECKS: Check[] = [sec01, sec04, inj01, perf01, prod03, com02, dep03];

/** Checks active for this scan: structural always, flow only under --experimental (ADR-001). */
export function activeChecks(ctx: ScanContext): Check[] {
  return ALL_CHECKS.filter((c) => c.tier === "structural" || ctx.options.experimental);
}
