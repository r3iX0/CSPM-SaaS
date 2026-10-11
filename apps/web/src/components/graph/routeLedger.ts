import type { RouteHistory } from "@/lib/types";

/** How a live route stands in the ledger, for its row (DECISIONS.md §249). */
export type LedgerMark = "new" | "reopened" | "rerouted";

/**
 * Each open route's mark, by key. Rerouted wins, because it is the one that
 * says a change moved the attacker rather than stopped them; then reopened,
 * which is also new; then new. A route the ledger has no episode for -- one no
 * single scan sees whole (§244) -- has no mark rather than a wrong one.
 */
export function ledgerMarks(history: RouteHistory | undefined): Map<string, LedgerMark> {
  const marks = new Map<string, LedgerMark>();
  for (const episode of history?.routes ?? []) {
    if (episode.status === "CLOSED") continue;
    if (episode.rerouted_at) marks.set(episode.key, "rerouted");
    else if (episode.reopened) marks.set(episode.key, "reopened");
    else if (episode.status === "NEW") marks.set(episode.key, "new");
  }
  return marks;
}
