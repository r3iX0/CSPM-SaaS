import { Cell, Pie, PieChart } from "recharts";

import type { Slice } from "@/components/charts/DonutLegend";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
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
 */
export function Donut({
  slices,
  centerValue,
  centerLabel,
  ariaLabel,
  className,
}: {
  slices: Slice[];
  centerValue: string;
  centerLabel: string;
  ariaLabel: string;
  className?: string;
}) {
  const reduced = usePrefersReducedMotion();
  const total = slices.reduce((sum, slice) => sum + slice.value, 0);

  // Built from the slices rather than declared, because a donut's categories
  // are data here -- which severities are present, which verdicts were
  // reached -- and the tooltip has to name whatever arrived.
  const config: ChartConfig = Object.fromEntries(
    slices.map((slice) => [slice.key, { label: slice.label, color: slice.tone }]),
  );

  return (
    <div className={cn("relative", className)} role="img" aria-label={ariaLabel}>
      <ChartContainer config={config} className="aspect-auto size-full">
        <PieChart>
          <Pie
            data={slices}
            dataKey="value"
            nameKey="label"
            innerRadius="70%"
            outerRadius="100%"
            startAngle={90}
            endAngle={-270}
            // A 2px gap of the surface between segments, so two adjacent
            // colours never read as one wedge.
            paddingAngle={slices.length > 1 ? 1.5 : 0}
            // A slice worth one finding out of four hundred still has to be
            // visible: a ring that silently drops the small share is the same
            // omission as a table that truncates without saying so.
            minAngle={slices.length > 1 ? 4 : 0}
            stroke="var(--card)"
            strokeWidth={2}
            isAnimationActive={!reduced}
            animationDuration={DURATION.chart}
          >
            {slices.map((slice) => (
              <Cell key={slice.key} fill={slice.tone} />
            ))}
          </Pie>
          <ChartTooltip
            cursor={false}
            content={
              <ChartTooltipContent
                nameKey="label"
                hideLabel
                // The share, not only the count: a ring's whole claim is "this
                // much of that", and a tooltip reading "12" alone answers a
                // question the chart was not asked.
                formatter={(value, name) => (
                  <>
                    <span className="text-muted-foreground">{name}</span>
                    <span className="ml-auto font-mono font-medium tabular-nums">
                      {Number(value)}
                      {total
                        ? ` · ${Math.round((Number(value) / total) * 100)}%`
                        : ""}
                    </span>
                  </>
                )}
              />
            }
          />
        </PieChart>
      </ChartContainer>

      {/* The headline sits in the hole, in text ink rather than a series
          colour: the ring carries identity, the number carries the value. */}
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-xl font-semibold leading-none tabular-nums">
          {centerValue}
        </span>
        <span className="mt-0.5 text-[10px] leading-tight text-muted-foreground">
          {centerLabel}
        </span>
      </div>
    </div>
  );
}
