/**
 * How sure Cleave is, said in words (DECISIONS.md §262).
 *
 * The API decides the level and dates it; this only phrases it, so every place
 * that shows confidence -- a findings row, a finding's rail, a route -- says the
 * same sentence for the same reason.
 */
import type { Strings } from "@/i18n/en";
import { formatDate, formatRelative } from "@/lib/format";
import type { ConfidenceInfo, ConfidenceLevel, ContextField } from "@/lib/types";

export const CONFIDENCE_LEVELS = ["HIGH", "MEDIUM", "LOW"] as const;

export function isConfidenceLevel(value: string): value is ConfidenceLevel {
  return (CONFIDENCE_LEVELS as readonly string[]).includes(value);
}

export function confidenceLabel(t: Strings, level: ConfidenceLevel): string {
  switch (level) {
    case "HIGH":
      return t.confidence.high;
    case "MEDIUM":
      return t.confidence.medium;
    case "LOW":
      return t.confidence.low;
  }
}

function fieldLabel(t: Strings, field: ContextField): string {
  switch (field) {
    case "criticality":
      return t.confidence.fieldCriticality;
    case "data_sensitivity":
      return t.confidence.fieldSensitivity;
  }
}

/** "criticality", or "criticality and data sensitivity". */
function fieldList(t: Strings, fields: readonly ContextField[]): string {
  const names = fields.map((field) => fieldLabel(t, field));
  if (names.length <= 1) return names.join("");
  return `${names.slice(0, -1).join(", ")} ${t.confidence.and} ${names.at(-1) ?? ""}`;
}

/**
 * One sentence per shortfall, evidence first. `route` phrases a guessed target
 * as a route's caveat rather than an asset's.
 */
export function confidenceReasons(
  t: Strings,
  info: ConfidenceInfo,
  { route = false }: { route?: boolean } = {},
): string[] {
  const age = formatRelative(info.observed_at);
  return info.reasons.map((reason) => {
    switch (reason.code) {
      case "EVIDENCE_STALE":
        return t.confidence.reasonStale.replace("{age}", age);
      case "EVIDENCE_AGING":
        return t.confidence.reasonAging.replace("{age}", age);
      case "CONTEXT_UNKNOWN":
        return t.confidence.reasonUnknown.replace("{fields}", fieldList(t, reason.fields));
      case "CONTEXT_INFERRED":
        return route
          ? t.confidence.reasonInferredRoute
          : t.confidence.reasonInferred.replace("{fields}", fieldList(t, reason.fields));
    }
  });
}

/** When it was read, and until when that counts as current -- or from when it does not. */
export function confidenceWindow(t: Strings, info: ConfidenceInfo): string {
  const read = t.confidence.read.replace("{age}", formatRelative(info.observed_at));
  const edge =
    info.freshness === "FRESH"
      ? t.confidence.currentUntil.replace("{date}", formatDate(info.fresh_until))
      : t.confidence.staleFrom.replace("{date}", formatDate(info.stale_at));
  return `${read} · ${edge}`;
}

/** Whether any reason is about the evidence, which a rescan answers. */
export function needsRescan(info: ConfidenceInfo): boolean {
  return info.reasons.some(
    (reason) => reason.code === "EVIDENCE_STALE" || reason.code === "EVIDENCE_AGING",
  );
}

/** Whether any reason is about context, which a declaration answers. */
export function needsContext(info: ConfidenceInfo): boolean {
  return info.reasons.some(
    (reason) => reason.code === "CONTEXT_UNKNOWN" || reason.code === "CONTEXT_INFERRED",
  );
}

/** The one-line account a screen reader hears beside the mark. */
export function confidenceSummary(
  t: Strings,
  info: ConfidenceInfo,
  { route = false }: { route?: boolean } = {},
): string {
  const reasons = confidenceReasons(t, info, { route });
  const head = `${t.confidence.label}: ${confidenceLabel(t, info.level)}`;
  return reasons.length > 0 ? `${head}. ${reasons.join(" ")}` : `${head}. ${t.confidence.settled}`;
}

/** A route's shortfall in a word: how old it is, or that its target was guessed. */
export function routeConfidenceWord(t: Strings, info: ConfidenceInfo): string {
  if (info.freshness === "STALE") return t.confidence.routeStale;
  if (info.freshness === "AGING") return t.confidence.routeAging;
  return t.confidence.routeGuessed;
}
