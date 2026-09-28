import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";

import { cn } from "@/lib/format";
import type { Level } from "@/lib/types";

export type Stat = {
  label: string;
  value: ReactNode;
  /** Painted in the critical tone. Only for a number that is a problem. */
  alert?: boolean;
  /**
   * Painted in a level's tone -- the severity counts above a findings list,
   * each in its own colour. The figure is coloured, never the cell: a strip of
   * tinted cells would read as five alarms rather than five counts.
   */
  tone?: Level;
  /** A 12px glyph before the label, from `lib/icons.ts`. */
  icon?: LucideIcon;
  hint?: ReactNode;
};

const TONE: Record<Level, string> = {
  CRITICAL: "text-critical",
  HIGH: "text-high",
  MEDIUM: "text-medium",
  LOW: "text-low",
  UNKNOWN: "text-unknown",
};

/** Literal classes, so Tailwind sees every one it has to generate. */
const COLUMNS: Record<number, string> = {
  2: "sm:grid-cols-2",
  3: "sm:grid-cols-3",
  4: "sm:grid-cols-4",
  5: "sm:grid-cols-5",
  6: "sm:grid-cols-3 lg:grid-cols-6",
};

/**
 * A row of headline numbers above a list.
 *
 * The questions somebody opening a page actually asks -- how many, how much,
 * how late -- answered before the rows, so they are not counted by eye. One
 * component so every page that has such a row draws it the same way: the same
 * label size, the same figure weight, the same dividers.
 *
 * The dividers are the border colour showing through a 1px gap between cells,
 * rather than a border on each cell, so a cell that wraps onto a second row on
 * a phone never draws a doubled line.
 */
export function StatStrip({ stats, className }: { stats: Stat[]; className?: string }) {
  return (
    <dl
      className={cn(
        "grid grid-cols-2 gap-px overflow-hidden rounded-xl bg-border ring-1 ring-foreground/10",
        COLUMNS[stats.length] ?? "sm:grid-cols-4",
        className,
      )}
    >
      {stats.map((stat) => (
        <div key={stat.label} className="bg-card px-[18px] py-3.5">
          <dt className="flex items-center gap-1.5 text-[11.5px] text-muted-foreground">
            {stat.icon && <stat.icon className="size-3 shrink-0" strokeWidth={1.5} aria-hidden />}
            {stat.label}
          </dt>
          <dd
            className={cn(
              "mt-1 text-[22px] leading-tight font-semibold tabular-nums",
              stat.alert ? "text-critical" : stat.tone ? TONE[stat.tone] : "text-foreground",
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
