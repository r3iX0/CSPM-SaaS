import { useId, useState } from "react";
import { ChevronDownIcon } from "lucide-react";

import type { RouteEpisode, RouteHistory, RouteHistoryMeta } from "@/lib/types";
import { useT } from "@/i18n";
import { cn, formatDay } from "@/lib/format";
import { Sparkline } from "@/components/charts/Sparkline";
import { Button } from "@/components/ui/button";

/**
 * Whether it is getting better (DECISIONS.md §249): what the latest scan
 * moved, by name -- there is no organization-wide "last scan" (§244) -- a trend
 * of the routes open each day, and the routes closed recently with why each
 * closed, so a deleted asset never reads as a fix.
 */
export function RouteProgress({
  history,
  meta,
}: {
  history: RouteHistory;
  meta: RouteHistoryMeta;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const list = useId();

  if (!meta.recorded_since) {
    return <p className="text-meta text-muted-foreground">{t.attackPaths.historyNotYet}</p>;
  }

  const closed = history.routes.filter((episode) => episode.status === "CLOSED");
  const { latest } = history;
  const series = history.trend.map((point) => point.open);

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        {latest && (
          <p className="text-meta text-muted-foreground">
            {t.attackPaths.historyLatest(
              formatDay(latest.observed_at),
              latest.scope_name,
              latest.opened,
              latest.closed,
              latest.rerouted,
            )}
          </p>
        )}
        {series.length >= 2 && (
          <span className="flex items-center gap-2 text-meta text-muted-foreground">
            <Sparkline
              values={series}
              label={t.attackPaths.historyTrendLabel(meta.days)}
              className="h-5 w-24"
            />
            <span className="tabular-nums">{t.attackPaths.historyTrend(meta.days)}</span>
          </span>
        )}
        {closed.length > 0 && (
          <Button
            variant="ghost"
            size="xs"
            aria-expanded={open}
            aria-controls={list}
            onClick={() => setOpen((was) => !was)}
          >
            {t.attackPaths.historyClosed(closed.length, meta.days)}
            <ChevronDownIcon
              data-icon="inline-end"
              className={cn("transition-transform", open && "rotate-180")}
            />
          </Button>
        )}
      </div>
      <ul id={list} hidden={!open} className="flex flex-col gap-1">
        {open && closed.map((episode) => <ClosedRoute key={episode.id} episode={episode} />)}
      </ul>
    </div>
  );
}

function ClosedRoute({ episode }: { episode: RouteEpisode }) {
  const t = useT();
  return (
    <li className="flex flex-wrap items-baseline gap-x-2 text-meta">
      <span className="font-medium line-through decoration-muted-foreground">
        {episode.entry.name} <span className="text-muted-foreground">→</span> {episode.target.name}
      </span>
      <span className="text-muted-foreground">
        {t.attackPaths.historyClosedOn(formatDay(episode.closed_at))} ·{" "}
        {episode.close_reason === "ASSET_GONE"
          ? t.attackPaths.historyAssetGone
          : t.attackPaths.historyLinkRemoved}
      </span>
    </li>
  );
}
