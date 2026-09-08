import {
  Bar,
  BarChart,
  CartesianGrid,
  XAxis,
  YAxis,
} from "recharts";

import {
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { DURATION, usePrefersReducedMotion } from "@/lib/motion";

export type ActivityWeek = {
  week: string;
  detected: number;
  resolved: number;
  reopened: number;
};

/**
 * The three series, named and coloured once.
 *
 * `ChartConfig` is what makes the tooltip and the legend agree: both read the
 * label and the swatch from here rather than from props passed twice, so a
 * series cannot be "Verified fixed" in one and "resolved" in the other.
 *
 * The colours are the severity scale, not the neutral chart ramp, because these
 * are statuses rather than arbitrary categories -- raised is the problem
 * colour, fixed is the good one, and a fix that did not hold is critical,
 * because that is what it is.
 */
const CONFIG = {
  detected: { label: "Raised", color: "var(--sev-medium)" },
  resolved: { label: "Verified fixed", color: "var(--sev-ok)" },
  reopened: { label: "Came back", color: "var(--sev-critical)" },
} satisfies ChartConfig;

/**
 * What happened, week by week: raised, fixed, and come back.
 *
 * **Reopenings are never subtracted from fixes.** A fix that regressed
 * happened; netting the two would hide exactly the pattern a security team
 * needs to see, and would let a bad week average into an unremarkable one.
 *
 * Grouped rather than stacked. Stacking would make the height of a week mean
 * "amount of activity", which is not a quantity anybody acts on; side by side,
 * the comparison the reader wants — did we fix more than came back — is a
 * comparison of two adjacent lengths.
 */
export function ActivityBars({ weeks }: { weeks: ActivityWeek[] }) {
  const reduced = usePrefersReducedMotion();

  const data = weeks.map((week) => ({
    ...week,
    label: new Date(week.week).toLocaleDateString(undefined, {
      day: "numeric",
      month: "short",
    }),
  }));

  return (
    // `aspect-auto` because the height is fixed by the panel this sits in; the
    // primitive's default aspect ratio would fight it.
    <ChartContainer config={CONFIG} className="aspect-auto h-40 w-full">
      <BarChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -24 }} barGap={2}>
        <CartesianGrid
          stroke="var(--border)"
          strokeDasharray="2 4"
          vertical={false}
        />
        <XAxis
          dataKey="label"
          tick={{ fontSize: 11 }}
          tickLine={false}
          axisLine={{ stroke: "var(--border)" }}
          minTickGap={16}
        />
        <YAxis
          allowDecimals={false}
          tick={{ fontSize: 11 }}
          tickLine={false}
          axisLine={false}
          width={40}
        />
        <ChartTooltip
          cursor={{ fill: "var(--muted)", opacity: 0.4 }}
          content={
            <ChartTooltipContent
              labelFormatter={(value) => `Week of ${value}`}
            />
          }
        />
        {/* Three series, so a legend is not optional: identity must never be
            carried by colour alone. */}
        <ChartLegend content={<ChartLegendContent />} />
        {(["detected", "resolved", "reopened"] as const).map((key) => (
          <Bar
            key={key}
            dataKey={key}
            name={key}
            fill={`var(--color-${key})`}
            radius={[3, 3, 0, 0]}
            isAnimationActive={!reduced}
            animationDuration={DURATION.chart}
          />
        ))}
      </BarChart>
    </ChartContainer>
  );
}
