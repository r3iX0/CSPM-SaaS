import { useEffect, useState } from "react";

import type { Slice } from "@/components/charts/DonutLegend";
import { CIRCUMFERENCE, RADIUS, THICKNESS, ringArcs } from "@/components/charts/ring";
import { DURATION, usePrefersReducedMotion } from "@/lib/motion";
import { cn } from "@/lib/format";

/**
 * A ring, used only where the data is genuinely a whole divided into parts.
 *
 * That restriction is the whole reason this component is small. A ring encodes
 * one thing well — this share of that total — and encodes comparison badly, so
 * it is right for "how much of the estate reached a verdict" and wrong for
 * ranking four severities against each other. Anything ranked is a bar
 * elsewhere in this app.
 *
 * At most four slices, each carrying a written label beside the ring rather
 * than only a colour: these are status colours, and a status must never be
 * communicated by hue alone.
 *
 * Hand-drawn SVG rather than Recharts (DECISIONS.md §149). Once the redesign
 * took the axis charts off the overview this was the only chart left, and it
 * cost every page that drew one ninety-odd kilobytes of charting runtime for
 * a circle. Each segment is one stroked arc, and says what it is in a
 * `<title>`, so pointing at it still reads the share.
 */
export function Donut({
  slices,
  centerValue,
  centerLabel,
  ariaLabel,
  className,
  valueClassName,
}: {
  slices: Slice[];
  centerValue: string;
  centerLabel: string;
  ariaLabel: string;
  className?: string;
  /** The centre figure, sized to the ring: the 64px coverage ring reads 14.5px. */
  valueClassName?: string;
}) {
  const reduced = usePrefersReducedMotion();
  // Drawn from nothing once, on mount, and never again: a ring that re-swept
  // on every poll would be movement that means nothing.
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    const frame = requestAnimationFrame(() => setMounted(true));
    return () => cancelAnimationFrame(frame);
  }, []);
  const drawn = reduced || mounted;

  const total = slices.reduce((sum, slice) => sum + slice.value, 0);
  const arcs = ringArcs(slices);

  return (
    <div className={cn("relative", className)} role="img" aria-label={ariaLabel}>
      <svg viewBox="0 0 100 100" className="size-full -rotate-90" aria-hidden>
        {/* The track, so an empty whole still reads as a ring of nothing
            rather than as a missing chart. */}
        <circle
          cx={50}
          cy={50}
          r={RADIUS}
          fill="none"
          stroke="var(--muted)"
          strokeWidth={THICKNESS}
        />
        {arcs.map((arc) => (
          <circle
            key={arc.slice.key}
            data-slice={arc.slice.key}
            cx={50}
            cy={50}
            r={RADIUS}
            fill="none"
            stroke={arc.slice.tone}
            strokeWidth={THICKNESS}
            strokeDasharray={`${drawn ? arc.length : 0} ${CIRCUMFERENCE}`}
            strokeDashoffset={-arc.offset}
            style={
              reduced ? undefined : { transition: `stroke-dasharray ${DURATION.chart}ms ease-out` }
            }
          >
            {/* The share, not only the count: a ring's whole claim is "this
                much of that", and "12" alone answers a question the chart was
                not asked. */}
            <title>
              {`${arc.slice.label} · ${arc.slice.value}${
                total ? ` · ${Math.round((arc.slice.value / total) * 100)}%` : ""
              }`}
            </title>
          </circle>
        ))}
      </svg>

      {/* The headline sits in the hole, in text ink rather than a series
          colour: the ring carries identity, the number carries the value. */}
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className={cn("text-xl leading-none font-semibold tabular-nums", valueClassName)}>
          {centerValue}
        </span>
        <span className="mt-0.5 text-micro leading-tight text-muted-foreground">{centerLabel}</span>
      </div>
    </div>
  );
}
