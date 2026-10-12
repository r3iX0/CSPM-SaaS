import { useT } from "@/i18n";
import { confidenceLabel, confidenceSummary } from "@/lib/confidence";
import { cn } from "@/lib/format";
import type { ConfidenceInfo, ConfidenceLevel } from "@/lib/types";

const FILLED: Record<ConfidenceLevel, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };
const BAR_HEIGHT = ["h-1.5", "h-2.5", "h-3"] as const;
const BAR_FILL: Record<ConfidenceLevel, string> = {
  HIGH: "bg-foreground/70",
  MEDIUM: "bg-muted-foreground",
  LOW: "bg-unknown",
};

/**
 * How sure Cleave is, as three rising bars (DECISIONS.md §262).
 *
 * Not a pill, and nothing from the severity scale. Severity is how bad a thing
 * is and confidence is how far that can be trusted today; drawn in the same
 * shape and colours, a "Low" confidence would read as a low-severity finding.
 * Bars are the shape people already read as signal strength, and LOW fills its
 * one bar in the colour the product gives a gap in knowledge (`unknown`), so it
 * is told apart by count as well as colour.
 *
 * The whole account -- level and every reason -- is the mark's accessible name,
 * so a screen reader hears why, not just "Low".
 */
export function ConfidenceMark({
  confidence,
  showLabel = true,
  label,
  route = false,
  className,
}: {
  confidence: ConfidenceInfo;
  /** The level in words beside the bars. Off where a column already says what it is. */
  showLabel?: boolean;
  /** Words to show instead of the level, where a shortfall says more ("Stale"). */
  label?: string;
  /** Phrase the reasons as a route's rather than a finding's. */
  route?: boolean;
  className?: string;
}) {
  const t = useT();
  const filled = FILLED[confidence.level];
  return (
    <span
      role="img"
      aria-label={confidenceSummary(t, confidence, { route })}
      data-confidence={confidence.level}
      className={cn(
        "inline-flex items-center gap-1.5 text-caption whitespace-nowrap",
        confidence.level === "LOW" ? "text-unknown" : "text-muted-foreground",
        className,
      )}
    >
      <span className="flex h-3 items-end gap-px" aria-hidden>
        {BAR_HEIGHT.map((height, bar) => (
          <span
            key={height}
            className={cn(
              "w-[3px] rounded-full",
              height,
              bar < filled ? BAR_FILL[confidence.level] : "bg-border",
            )}
          />
        ))}
      </span>
      {showLabel && <span aria-hidden>{label ?? confidenceLabel(t, confidence.level)}</span>}
    </span>
  );
}
