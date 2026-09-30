import { Link } from "react-router-dom";

import { useT } from "@/i18n";
import { useCountUp } from "@/lib/motion";
import { cn } from "@/lib/format";

/**
 * What the score means today, as three figures rather than a sentence
 * (DECISIONS.md §178): how many risks are open, how many routes run from
 * something exposed to something sensitive, and how much of the estate the
 * reading was formed from.
 *
 * Coverage is up here, beside the score, because it qualifies it: a score over
 * half the checks is half a reading. A figure the page does not have yet is a
 * dash, never a zero.
 */
export function TodayStats({
  risks,
  routes,
  coverage,
}: {
  risks: number | null;
  routes: number | null;
  /** The share of checks that reached a verdict, 0 to 1. */
  coverage: number | null;
}) {
  const t = useT();
  return (
    <ul className="grid grid-cols-1 gap-2 sm:grid-cols-3">
      <Stat to="/risks" label={t.dashboard.openRisks} value={risks} />
      <Stat to="/attack-paths" label={t.dashboard.attackRoutes} value={routes} />
      <Stat
        to="/scans"
        label={t.dashboard.checksVerdicted}
        value={coverage === null ? null : Math.round(coverage * 100)}
        suffix="%"
      />
    </ul>
  );
}

function Stat({
  to,
  label,
  value,
  suffix = "",
}: {
  to: string;
  label: string;
  value: number | null;
  suffix?: string;
}) {
  const shown = Math.round(useCountUp(value ?? 0));
  return (
    <li>
      <Link
        to={to}
        className={cn(
          "flex h-full flex-col gap-1 rounded-lg border px-3.5 py-3 transition-colors hover:bg-muted/60",
          "focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring",
        )}
      >
        <span className="text-stat leading-none font-semibold tabular-nums">
          {value === null ? "—" : `${shown}${suffix}`}
        </span>
        <span className="text-caption text-muted-foreground">{label}</span>
      </Link>
    </li>
  );
}
