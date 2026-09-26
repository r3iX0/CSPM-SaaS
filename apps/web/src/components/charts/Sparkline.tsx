import { useId, useMemo } from "react";

import { usePrefersReducedMotion } from "@/lib/motion";

/**
 * A line small enough to sit inside a number.
 *
 * Hand-written SVG rather than a charting library, for the reason the project
 * already applies to `ScoreRing`: this draws one polyline in a 24px band, and
 * pulling in a chart runtime per tile would cost more than the tiles do.
 *
 * **No axes, no grid, no tooltip, and that is a decision rather than an
 * omission.** A sparkline's job is shape — is this going up — and the exact
 * values are the large number printed beside it. It also lives inside a link on
 * the severity strip, and a hover layer inside a click target is a way of
 * making a row that cannot be clicked confidently. The series is instead
 * described to assistive technology in words, which is what a screen reader
 * needs from it anyway.
 */
export function Sparkline({
  values,
  label,
  tone = "currentColor",
  fill = false,
  className,
}: {
  values: number[];
  /** What the line is of, for the reader who cannot see it. */
  label: string;
  tone?: string;
  /**
   * A wash under the line, the tone at 18% fading to nothing. For a sparkline
   * that stands alone (the overview's trend); one sitting inside a number
   * stays a bare line.
   */
  fill?: boolean;
  className?: string;
}) {
  const reduced = usePrefersReducedMotion();
  // useId gives ":r1:", which a url() reference cannot hold.
  const gradientId = `spark-${useId().replace(/:/g, "")}`;
  const clipId = `${gradientId}-clip`;

  const path = useMemo(() => {
    if (values.length < 2) return null;

    const width = 100;
    const height = 24;
    const max = Math.max(...values);
    const min = Math.min(...values);
    // A flat series is drawn flat, in the middle, rather than divided by zero
    // into a line that leaps between the top and bottom of the box.
    const span = max - min || 1;

    return values
      .map((value, index) => {
        const x = (index / (values.length - 1)) * width;
        const y = height - ((value - min) / span) * (height - 4) - 2;
        return `${index === 0 ? "M" : "L"}${x.toFixed(2)},${y.toFixed(2)}`;
      })
      .join(" ");
  }, [values]);

  // Two readings is the least that can show movement. Below it the honest
  // answer is nothing at all, not a dot implying a direction.
  if (!path) return null;

  const first = values[0];
  const last = values[values.length - 1];
  const direction = last > first ? "risen" : last < first ? "fallen" : "held";

  return (
    <svg
      viewBox="0 0 100 24"
      preserveAspectRatio="none"
      className={className}
      role="img"
      aria-label={`${label}: ${direction} from ${first} to ${last} across the last ${values.length} readings`}
    >
      <defs>
        {fill && (
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={tone} stopOpacity={0.18} />
            <stop offset="100%" stopColor={tone} stopOpacity={0} />
          </linearGradient>
        )}
        {/* Drawn on, once, on mount, by uncovering it left to right. Not a
            dash animation: `pathLength` does not survive `non-scaling-stroke`
            under a stretched viewBox, and Chrome drew the line with holes in
            it. Reduced motion gets the finished line rather than a slow one. */}
        {!reduced && (
          <clipPath id={clipId}>
            <rect x="-2" y="-2" height="28" width="0">
              <animate
                attributeName="width"
                from="0"
                to="104"
                dur="700ms"
                fill="freeze"
                calcMode="spline"
                keySplines="0 0 0.58 1"
                keyTimes="0;1"
              />
            </rect>
          </clipPath>
        )}
      </defs>
      <g clipPath={reduced ? undefined : `url(#${clipId})`}>
        {fill && (
          <path d={`${path} L100,24 L0,24 Z`} fill={`url(#${gradientId})`} stroke="none" />
        )}
        <path
          d={path}
          fill="none"
          stroke={tone}
          strokeWidth={1.5}
          strokeLinecap="round"
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
        />
      </g>
    </svg>
  );
}
