import type { Check, ScanContext } from "../types.js";
import { sec01 } from "./sec-01.js";

/** Every check known to the engine. Structural = on by default; flow = experimental-only. */
export const ALL_CHECKS: Check[] = [sec01];

/** Checks active for this scan: structural always, flow only under --experimental (ADR-001). */
export function activeChecks(ctx: ScanContext): Check[] {
  return ALL_CHECKS.filter((c) => c.tier === "structural" || ctx.options.experimental);
}
