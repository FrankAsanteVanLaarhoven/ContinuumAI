/**
 * Comparative v0.2 — vendor-neutral model-family SLOTS and pre-registered sampling.
 *
 * Concrete model identifiers and revisions are PINNED at execution time under separate
 * review — never hard-coded here — so this protocol stays provider-neutral and auditable,
 * and so the attribution boundary is preserved. At least one slot MUST be locally/privately
 * hosted. Temperature and sampling are fixed in advance (pre-registered below); multiple
 * stochastic seeds are swept per experimental cell.
 */

export interface FamilySlot {
  slot: "A" | "B" | "C";
  description: string;
  hosting: "hosted" | "local";
  /** Pinned at execution time (must be non-null before any run; null here by design). */
  model_id: string | null;
  revision: string | null;
}

export const FAMILY_SLOTS: FamilySlot[] = [
  { slot: "A", description: "Frontier hosted model — family 1", hosting: "hosted", model_id: null, revision: null },
  { slot: "B", description: "Frontier hosted model — materially different family 2", hosting: "hosted", model_id: null, revision: null },
  { slot: "C", description: "Open-weights model — locally / privately hosted", hosting: "local", model_id: null, revision: null },
];

/** Pre-registered sampling, fixed BEFORE any run. Confirmed at protocol review. */
export const FIXED_SAMPLING = {
  temperature: 0.7, // > 0 so seeds expose genuine stochasticity; fixed in advance
  top_p: 1.0,
  max_output_tokens: 512,
} as const;

/** Multiple stochastic seeds swept per (baseline × workload × model) cell. */
export const SEEDS: readonly number[] = [11, 23, 37, 101, 233] as const;

/** True once concrete identifiers are pinned; execution MUST assert this first. */
export function slotsPinned(slots: FamilySlot[] = FAMILY_SLOTS): boolean {
  return slots.every((s) => s.model_id !== null && s.revision !== null) && slots.some((s) => s.hosting === "local");
}
