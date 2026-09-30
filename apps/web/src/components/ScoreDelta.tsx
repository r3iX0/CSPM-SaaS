import { useT } from "@/i18n";
import { useValueChange } from "@/lib/motion";

/**
 * Movement since the previous reading.
 *
 * Four states, not two, and the distinctions are the point. The delta used to
 * be an estimate that reconstructed a prior score by adding back every fix ever
 * verified, so it could only ever be positive — and this rendered a green up
 * arrow unconditionally. Measuring it against the previous reading makes a
 * decline possible for the first time, at which point a hard-coded ↑ is a plain
 * untruth about the direction a customer's posture moved.
 *
 * "No previous scan" is kept separate from "no change" because they are
 * different facts: one is a comparison that could not be made, the other a
 * comparison that came out level.
 *
 * In its own module rather than beside `ScoreTrend`, and that is a bundling
 * decision rather than tidiness. This is a sentence and an arrow; that one
 * imports Recharts. While they shared a file, every page reaching for a delta
 * pulled the whole charting library behind it -- which is how 396 kB of chart
 * code ended up on the findings list, a page with no chart on it.
 */
export function ScoreDelta({ delta }: { delta: number | null }) {
  const t = useT();
  // A new delta nudges its arrow once, the way it points. Keyed on the change
  // count, so the keyframe replays for a new reading and never for a refetch
  // or a remount (DECISIONS.md §178).
  const { changes } = useValueChange(delta);

  if (delta === null) {
    return <p className="text-xs text-muted-foreground">{t.dashboard.noPreviousScan}</p>;
  }
  if (delta === 0) {
    return <p className="text-xs text-muted-foreground">No change since last scan</p>;
  }

  const improved = delta > 0;
  return (
    <p
      className={
        improved
          ? "inline-flex items-center gap-1 rounded-full border border-ok-border bg-ok-bg px-2 py-px text-caption font-medium tabular-nums text-ok"
          : "inline-flex items-center gap-1 rounded-full border border-critical-border bg-critical-bg px-2 py-px text-caption font-medium tabular-nums text-critical"
      }
    >
      <span
        key={changes}
        aria-hidden="true"
        className={
          changes > 0
            ? improved
              ? "inline-block animate-[cg-nudge-up_360ms_ease-out]"
              : "inline-block animate-[cg-nudge-down_360ms_ease-out]"
            : "inline-block"
        }
      >
        {improved ? "\u2191" : "\u2193"}
      </span>{" "}
      {Math.abs(delta)}{" "}
      {improved ? t.dashboard.sinceLastScan : t.dashboard.scoreWorse}
    </p>
  );
}
