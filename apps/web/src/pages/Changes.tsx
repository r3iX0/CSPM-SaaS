import { useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  ArrowDownIcon,
  ArrowRightIcon,
  ArrowUpIcon,
  GitCompareArrowsIcon,
  MinusIcon,
  PlusIcon,
} from "lucide-react";

import { api } from "@/lib/api";
import type { AssetChange, ChangeEvent } from "@/lib/types";
import { useUrlFilters } from "@/lib/useUrlFilters";
import { useT } from "@/i18n";
import { cn, formatDate, formatTime } from "@/lib/format";
import { changeDirection, type Direction } from "@/lib/changes";
import { CHANGE_KIND_ICONS } from "@/lib/icons";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { ResourceTypeLabel } from "@/components/security/IconLabel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { SelectField } from "@/components/common/SelectField";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import { StepPager } from "@/components/common/Pager";

const PAGE_SIZE = 50;
const WINDOWS = [1, 7, 30, 90] as const;

/**
 * What moved in the environment, rather than what is true in it now.
 *
 * Every other screen is a photograph: these are the findings, this is the
 * score, these are the assets. None of them answers the question a customer
 * actually asks after a week of somebody else's deployments -- *what changed
 * while I was away* -- and until this page existed the change events the
 * scanner has been writing all along were reachable only through the API.
 *
 * A feed of transitions, not a diff of two scans. The distinction shows up in
 * the empty state: a quiet week here is a genuinely quiet week, not a page
 * saying everything is still where it was.
 */
export function ChangesPage() {
  const t = useT();
  // In the URL, so "what moved in the last 30 days" is a link that can be sent.
  const [filters, update] = useUrlFilters({ days: "7", kind: "all", page: "0" });
  const days = Number.parseInt(filters.days, 10) || 7;
  const kind = filters.kind;
  const page = Math.max(0, Number.parseInt(filters.page, 10) || 0);
  const setPage = (next: number) => update({ page: String(next) });

  const params = new URLSearchParams();
  params.set("days", String(days));
  if (kind !== "all") params.set("change", kind);
  params.set("limit", String(PAGE_SIZE));
  params.set("offset", String(page * PAGE_SIZE));

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["changes", days, kind, page],
    queryFn: () =>
      api
        .get<ChangeEvent[]>(`/api/v1/changes?${params.toString()}`)
        .then((r) => r.data),
    placeholderData: keepPreviousData,
  });

  const events = data ?? [];
  // The endpoint returns a window rather than a count, so there is no total to
  // page against. A full page is the only honest signal that more exists.
  const hasMore = events.length === PAGE_SIZE;

  /** A new window or kind is a new set, so the page resets with it. */
  function rewindow(patch: { days?: string; kind?: string }) {
    update({ ...patch, page: null });
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t.changes.title}
        description={t.changes.intro}
      />

      <div className="flex flex-wrap items-center gap-2">
        <SelectField
          value={String(days)}
          onValueChange={(value) => rewindow({ days: String(value) })}
          ariaLabel={t.changes.windowLabel}
          className="w-[170px]"
          options={WINDOWS.map((window) => ({
            value: String(window),
            label: t.changes.windows[window],
          }))}
        />

        <SelectField
          value={kind}
          onValueChange={(value) => rewindow({ kind: value || "all" })}
          ariaLabel={t.changes.kindLabel}
          className="w-[230px]"
          idleValue="all"
          options={[
            { value: "all", label: t.changes.allKinds },
            ...(Object.keys(t.changes.kind) as AssetChange[]).map((value) => ({
              value,
              label: t.changes.kind[value],
              icon: CHANGE_KIND_ICONS[value],
            })),
          ]}
        />
      </div>

      {isLoading && <CardsSkeleton count={2} />}

      {error && (
        <ErrorState
          title="Could not load the change feed"
          detail="Cleave could not reach its own API."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      {data && events.length === 0 && (
        <EmptyState
          icon={GitCompareArrowsIcon}
          title={kind === "all" ? t.changes.empty : t.changes.emptyFiltered}
          detail={
            kind === "all" ? t.changes.emptyDetail : t.changes.emptyFilteredDetail
          }
          action={
            kind !== "all" ? (
              <Button
                variant="outline"
                onClick={() => rewindow({ kind: "all" })}
              >
                Show all changes
              </Button>
            ) : undefined
          }
        />
      )}

      {data && events.length > 0 && (
        <>
          {/* Grouped by the day it was observed, because that is the unit the
              question is asked in. An undifferentiated list of fifty rows makes
              "Tuesday's deployment" something the reader has to reconstruct
              from timestamps. */}
          {groupByDay(events).map(([day, rows]) => (
            <section key={day} className="flex flex-col gap-2">
              <h2 className="mt-1 text-xs font-medium text-muted-foreground">
                {formatDate(rows[0].observed_at)}
              </h2>
              <Card className="py-0">
                <CardContent className="p-0">
                  <ul>
                    {withBatches(rows).map((item) =>
                      "batch" in item ? (
                        <AppearedBatch key={`batch-${item.batch[0].id}`} events={item.batch} />
                      ) : (
                        <ChangeRow key={item.id} event={item} />
                      ),
                    )}
                  </ul>
                </CardContent>
              </Card>
            </section>
          ))}

          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-xs text-muted-foreground">
              {page * PAGE_SIZE + 1}–{page * PAGE_SIZE + events.length}{" "}
              {events.length === 1 ? t.changes.count : t.changes.countPlural}
            </p>
            <StepPager
              page={page}
              hasMore={hasMore}
              onPage={setPage}
              className="w-auto"
            />
          </div>
        </>
      )}
    </div>
  );
}

/**
 * Calendar days in the reader's own time zone, newest first, preserving the
 * order the API returned. Local rather than the UTC date in the timestamp,
 * because each row shows only its local time: a change at 01:30 must sit under
 * the day that time belongs to.
 */
function groupByDay(events: ChangeEvent[]): [string, ChangeEvent[]][] {
  const days = new Map<string, ChangeEvent[]>();
  for (const event of events) {
    const at = new Date(event.observed_at);
    const day = `${at.getFullYear()}-${at.getMonth()}-${at.getDate()}`;
    const existing = days.get(day);
    if (existing) existing.push(event);
    else days.set(day, [event]);
  }
  return [...days.entries()];
}

/** How many assets one scan may introduce before they are listed as one row. */
const BATCH_AT = 6;

/**
 * A day's rows, with each scan's arrivals folded into one row when there are
 * many of them.
 *
 * A first scan introduces every asset at once, and forty "first seen" rows
 * buried the two changes that day that meant something. Folded where the first
 * of them stood, so the API's order is otherwise kept (DECISIONS.md §188).
 */
function withBatches(rows: ChangeEvent[]): (ChangeEvent | { batch: ChangeEvent[] })[] {
  const arrivals = new Map<string, ChangeEvent[]>();
  for (const event of rows) {
    if (event.change !== "APPEARED" || !event.scan_id) continue;
    arrivals.set(event.scan_id, [...(arrivals.get(event.scan_id) ?? []), event]);
  }
  const out: (ChangeEvent | { batch: ChangeEvent[] })[] = [];
  const placed = new Set<string>();
  for (const event of rows) {
    const batch = event.change === "APPEARED" && event.scan_id ? arrivals.get(event.scan_id) : undefined;
    if (!batch || batch.length < BATCH_AT) {
      out.push(event);
    } else if (!placed.has(event.scan_id!)) {
      placed.add(event.scan_id!);
      out.push({ batch });
    }
  }
  return out;
}

function AppearedBatch({ events }: { events: ChangeEvent[] }) {
  const t = useT();
  const [open, setOpen] = useState(false);
  return (
    <li className="border-b last:border-0">
      <div className="flex items-start gap-3 px-5 py-3">
        <ChangeMark change="APPEARED" moved="neutral" />
        <div className="min-w-0 flex-1">
          <p className="text-body font-medium text-foreground">
            {t.changes.appearedBatch(events.length)}
          </p>
          <p className="mt-0.5 text-meta text-muted-foreground">{t.changes.appearedBatchDetail}</p>
        </div>
        <Button variant="outline" size="sm" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
          {open ? t.changes.hideAssets : t.changes.showAssets}
        </Button>
      </div>
      {open && (
        <ul className="border-t bg-muted/20">
          {events.map((event) => (
            <ChangeRow key={event.id} event={event} />
          ))}
        </ul>
      )}
    </li>
  );
}

function ChangeRow({ event }: { event: ChangeEvent }) {
  const t = useT();
  const attribute = event.change.endsWith("_CHANGED");
  const moved = attribute
    ? changeDirection(event.previous_value, event.current_value)
    : "neutral";

  return (
    <li className="flex items-start gap-3 border-b px-5 py-3 last:border-0">
      <ChangeMark change={event.change} moved={moved} />

      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <Link
            to={`/assets/${event.asset.id}`}
            className="truncate text-body font-medium text-foreground underline-offset-4 hover:underline"
          >
            {event.asset.name}
          </Link>
          <ResourceTypeLabel
            type={event.asset.resource_type}
            className="text-body text-muted-foreground"
          />
          {event.asset.environment && (
            <Badge variant="outline">{event.asset.environment}</Badge>
          )}
        </div>

        <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-caption text-muted-foreground">
          {/* An appearance or a disappearance says it in its own sentence; the
              kind would only repeat it. */}
          {attribute && <span>{t.changes.kind[event.change]}</span>}
          {event.change === "DISAPPEARED" && <span>{t.changes.disappeared}</span>}

          {attribute && (
            <span className="flex items-center gap-1.5">
              <SeverityBadge level={event.previous_value ?? "UNKNOWN"} size="sm" />
              <ArrowRightIcon className="size-3 shrink-0" aria-hidden />
              <SeverityBadge level={event.current_value ?? "UNKNOWN"} size="sm" />
              {moved !== "neutral" && (
                <span
                  className={cn(
                    "font-medium",
                    moved === "worse" ? "text-critical" : "text-ok",
                  )}
                >
                  {moved === "worse" ? t.changes.worse : t.changes.better}
                </span>
              )}
            </span>
          )}

          {event.change === "APPEARED" && <span>{t.changes.appeared}</span>}

          {/* The reading that decides whether this row is history or a job.
              The asset row is never deleted when a scan stops seeing it, so a
              DISAPPEARED event says nothing on its own about whether the thing
              is gone now. */}
          {event.change === "DISAPPEARED" && (
            <>
              <span aria-hidden>·</span>
              {event.asset.absent_since ? (
                <span className="font-medium text-high">
                  {t.changes.stillMissing}
                </span>
              ) : (
                <span className="font-medium text-ok">{t.changes.returned}</span>
              )}
            </>
          )}
        </div>
      </div>

      {/* The day is the heading above; the row only needs the hour. */}
      <time
        dateTime={event.observed_at}
        className="shrink-0 text-caption tabular-nums text-muted-foreground"
      >
        {formatTime(event.observed_at)}
      </time>
    </li>
  );
}

/**
 * The one glyph that carries the row's meaning at a glance.
 *
 * Shape as well as colour: an arrow that only turned red would tell a reader
 * who cannot separate the hues nothing at all, on a feed whose entire value is
 * spotting the handful of rows that got worse.
 */
function ChangeMark({
  change,
  moved,
}: {
  change: AssetChange;
  moved: Direction;
}) {
  const Icon =
    change === "APPEARED"
      ? PlusIcon
      : change === "DISAPPEARED"
        ? MinusIcon
        : moved === "worse"
          ? ArrowUpIcon
          : moved === "better"
            ? ArrowDownIcon
            : GitCompareArrowsIcon;

  const tone =
    change === "APPEARED" || change === "DISAPPEARED"
      ? "border-border bg-muted text-muted-foreground"
      : moved === "worse"
        ? "border-critical-border bg-critical-bg text-critical"
        : moved === "better"
          ? "border-ok-border bg-ok-bg text-ok"
          : "border-border bg-muted text-muted-foreground";

  return (
    <span
      className={cn(
        "mt-px flex size-[22px] shrink-0 items-center justify-center rounded-full border",
        tone,
      )}
    >
      <Icon className="size-3" aria-hidden />
    </span>
  );
}
