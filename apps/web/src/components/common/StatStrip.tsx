import type { ReactNode } from "react";

import { cn } from "@/lib/format";

export type Stat = {
  label: string;
  value: ReactNode;
  /** Painted in the critical tone. Only for a number that is a problem. */
  alert?: boolean;
  hint?: ReactNode;
};

/**
 * A row of headline numbers above a list.
 *
 * The questions somebody opening a page actually asks -- how many, how much,
 * how late -- answered before the rows, so they are not counted by eye. One
 * component so every page that has such a row draws it the same way: the same
 * label size, the same figure weight, the same dividers.
 */
export function StatStrip({ stats, className }: { stats: Stat[]; className?: string }) {
  return (
    <dl
      className={cn(
        "grid grid-cols-2 overflow-hidden rounded-xl border border-border bg-card",
        stats.length >= 4 ? "sm:grid-cols-4" : "sm:grid-cols-3",
        "divide-border max-sm:[&>*:nth-child(n+3)]:border-t sm:divide-x",
        className,
      )}
    >
      {stats.map((stat) => (
        <div key={stat.label} className="px-5 py-4">
          <dt className="text-xs text-muted-foreground">{stat.label}</dt>
          <dd
            className={cn(
              "mt-1 text-2xl font-semibold tracking-tight tabular-nums",
              stat.alert ? "text-critical" : "text-foreground",
            )}
          >
            {stat.value}
          </dd>
          {stat.hint && <p className="mt-0.5 text-xs text-muted-foreground">{stat.hint}</p>}
        </div>
      ))}
    </dl>
  );
}
