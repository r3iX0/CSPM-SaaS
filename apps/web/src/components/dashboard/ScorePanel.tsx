import type { CSSProperties, ReactNode } from "react";

import type { PostureReading } from "@/lib/types";
import { ScoreDelta } from "@/components/ScoreDelta";
import { Sparkline } from "@/components/charts/Sparkline";
import { useCountUp, useValueChange } from "@/lib/motion";
import { useT } from "@/i18n";
import { InfoTip } from "@/components/common/InfoTip";
import { cn } from "@/lib/format";

/** What a score *means*, so the number is not left to speak for itself. */
function band(score: number): { label: string; tone: string; color: string } {
  if (score >= 85) return { label: "Good", tone: "text-ok", color: "var(--sev-ok)" };
  if (score >= 60)
    return { label: "Needs attention", tone: "text-medium", color: "var(--sev-medium)" };
  if (score >= 40) return { label: "Poor", tone: "text-high", color: "var(--sev-high)" };
  return { label: "Critical", tone: "text-critical", color: "var(--sev-critical)" };
}

/**
 * The dashboard's anchor: where the posture stands, and what that means today.
 *
 * One panel rather than two cards, because they are one thought -- a score
 * without its direction is a number somebody has to remember last week's value
 * to use.
 *
 * The score is a ring filled to the number in its band's colour, with the rest
 * of the circle left muted (the Cleave redesign). The ring is decoration around
 * the digits, which stay the loudest thing on the page; the proportion is also
 * a `meter`, so it is not a picture only.
 *
 * The trend is a sparkline in the same colour, washed underneath. It has no
 * axes and no hover -- the exact figures are the score and the delta beside it
 * -- and it is only drawn once there are two readings to draw between: a line
 * through one point would claim a direction nobody measured.
 */
export function ScorePanel({
  score,
  delta,
  history,
  today,
}: {
  score: number;
  delta: number | null;
  history: PostureReading[];
  /** "What that means today": the figures the page leads with, as stat chips. */
  today?: ReactNode;
}) {
  const t = useT();
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const { label, tone, color } = band(clamped);
  // Counts to the score on mount and whenever it actually changes -- never on a
  // refetch that returned the same number, which would make a page nobody
  // touched twitch every twenty seconds.
  const shown = Math.round(useCountUp(clamped));
  const series = history.map((reading) => reading.security_score);
  // The trend redraws when a new reading joins it: the sparkline draws itself
  // when its <svg> is inserted, so a new key is a new drawing (§178).
  const trend = useValueChange(series.join(","));

  return (
    <section
      aria-labelledby="posture-score"
      className="grid gap-px overflow-hidden rounded-xl bg-border ring-1 ring-foreground/10 lg:grid-cols-[280px_minmax(0,1fr)]"
    >
      <div className="flex flex-col items-center gap-3 bg-card px-5 py-5 text-center">
        <div className="flex items-center gap-1 self-start">
          <h2 id="posture-score" className="text-body font-semibold">
            {t.dashboard.score}
          </h2>
          <InfoTip label={t.dashboard.scoreExplainLabel}>{t.dashboard.scoreExplain}</InfoTip>
        </div>

        {/* The sweep and the colour are registered properties (index.css), so
            a new score turns the ring and crossfades its band rather than
            swapping in one frame. */}
        <div
          className="relative size-32 shrink-0 rounded-full transition-[--score-angle,--score-color] duration-600 ease-out"
          style={
            {
              "--score-angle": `${clamped * 3.6}deg`,
              "--score-color": color,
              background: "conic-gradient(var(--score-color) var(--score-angle), var(--muted) 0)",
            } as CSSProperties
          }
          role="meter"
          aria-valuenow={clamped}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="Security score"
          aria-valuetext={`${clamped} of 100, ${label.toLowerCase()}`}
        >
          <div className="absolute inset-3 flex flex-col items-center justify-center rounded-full bg-card">
            <span className={cn("text-display leading-none font-semibold tabular-nums", tone)}>
              {shown}
            </span>
            <span className="mt-1 text-caption text-muted-foreground">/ 100</span>
          </div>
        </div>

        <p className={cn("text-body font-medium", tone)}>{label}</p>
        <ScoreDelta delta={delta} />
      </div>

      <div className="flex min-w-0 flex-col gap-4 bg-card px-5 py-5">
        <div className="flex items-baseline justify-between gap-3">
          <h3 className="text-body font-semibold">{t.dashboard.today}</h3>
          {/* The history is the last readings by count, one per scan, not a
              window of days: several scans a day cover hours, weekly ones
              months. So the span is said in scans. */}
          {series.length >= 2 && (
            <span className="text-caption tabular-nums text-muted-foreground">
              Last {series.length} scans
            </span>
          )}
        </div>
        {today}

        <div className="mt-auto">
          {series.length >= 2 ? (
            <>
            {/* What the line is, and where it went. Drawn in the score's own
                band colour with no axis, a red line climbing read as a
                warning rather than as a score of 1 becoming 3 (§189). */}
            <p className="mb-1 flex items-baseline justify-between gap-3 text-caption text-muted-foreground">
              <span>Security score</span>
              <span className="tabular-nums">
                {Math.round(series[0])} → {Math.round(series[series.length - 1])}
              </span>
            </p>
            <Sparkline
              key={trend.changes}
              values={series}
              label="Security score"
              tone={color}
              fill
              className="h-16 w-full"
            />
            </>
          ) : (
            <p className="text-xs text-muted-foreground">
              One scan so far. The trend starts at the next one.
            </p>
          )}
        </div>
      </div>
    </section>
  );
}
