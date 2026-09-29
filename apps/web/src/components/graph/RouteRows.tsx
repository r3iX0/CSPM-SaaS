import { useState, type CSSProperties } from "react";
import { ChevronRightIcon, RadarIcon } from "lucide-react";

import type { MappedRoute, RoutePattern } from "@/lib/types";
import { useT } from "@/i18n";
import { LEVEL_RANK } from "@/lib/changes";
import { cn } from "@/lib/format";
import { SeverityBadge } from "@/components/security/SeverityBadge";

/*
 * A route and a group of repeated routes, as rows to pick one from in the
 * attack-path panel. Pointing at a row, or reaching it with the keyboard,
 * previews its route on the drawing; pressing it opens the navigator
 * (DECISIONS.md §142).
 */

/** What the page knows about a route beyond the route itself. */
export interface RouteMarks {
  tracked: ReadonlySet<string>;
  /** Closed by the simulated plan, once the server has said. */
  closed: ReadonlySet<string>;
  /**
   * How long each route closed by the latest answer waits before it is struck
   * through, in ms -- the cut played in list order (§146). Absent, or 0, lands
   * at once: routes that were already closed, and a reader who asked for less
   * motion.
   */
  closeDelay?: ReadonlyMap<string, number>;
}

/** The strike and the "closed" mark arrive together, after the route's delay. */
function closeTiming(marks: RouteMarks, key: string): CSSProperties | undefined {
  const delay = marks.closeDelay?.get(key) ?? 0;
  return delay > 0 ? { transitionDelay: `${delay}ms`, animationDelay: `${delay}ms` } : undefined;
}

export function PatternRow({
  pattern,
  members,
  onTrace,
  onPreview,
  byKey,
  marks,
}: {
  pattern: RoutePattern;
  /** The members the list is narrowed to, in its order. */
  members: RoutePattern["varies"];
  onTrace: (key: string) => void;
  onPreview: (key: string | null) => void;
  byKey: Map<string, MappedRoute>;
  marks: RouteMarks;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  // The group's shape is its exemplar's: the members differ at one end only.
  const exemplar = byKey.get(pattern.exemplar);
  const routes = members.flatMap((member) => byKey.get(member.route) ?? []);
  // The worst of what the group reaches, since a group can vary at the target.
  const reaches = routes
    .map((route) => route.target.data_sensitivity)
    .sort((a, b) => (LEVEL_RANK[b] ?? 0) - (LEVEL_RANK[a] ?? 0))[0];
  const tracked = members.filter((member) => marks.tracked.has(member.route)).length;
  const closed = members.filter((member) => marks.closed.has(member.route)).length;

  return (
    <div className="rounded-lg border border-border">
      <button
        type="button"
        onClick={() => setOpen((was) => !was)}
        onMouseEnter={() => onPreview(pattern.exemplar)}
        onMouseLeave={() => onPreview(null)}
        onFocus={() => onPreview(pattern.exemplar)}
        onBlur={() => onPreview(null)}
        aria-expanded={open}
        className="flex w-full items-start gap-2 px-2.5 py-2 text-left hover:bg-muted/60 focus-ring-inset"
      >
        <ChevronRightIcon
          className={cn(
            "mt-0.5 size-3.5 shrink-0 text-muted-foreground transition-transform",
            open && "rotate-90",
          )}
          aria-hidden
        />
        <span className="flex min-w-0 flex-1 flex-col gap-1">
          <span className="text-xs text-foreground">{pattern.description}</span>
          <span className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-[11px] text-muted-foreground">
            {exemplar && <HopStrip route={exemplar} />}
            <span className="tabular-nums">
              {pattern.hops} {pattern.hops === 1 ? t.attackPaths.oneHop : t.attackPaths.hops}
            </span>
            {reaches && <SeverityBadge level={reaches} size="sm" />}
            {members.length < pattern.size && (
              <span className="tabular-nums">
                {t.attackPaths.shownOf(members.length, pattern.size)}
              </span>
            )}
            {closed > 0 && (
              <span className="text-ok tabular-nums">{t.attackPaths.closedCount(closed)}</span>
            )}
            {tracked > 0 && (
              <span className="flex items-center gap-0.5 tabular-nums">
                <RadarIcon className="size-3" aria-hidden />
                {t.attackPaths.trackedCount(tracked)}
              </span>
            )}
          </span>
        </span>
      </button>
      {open && (
        <ul className="border-t">
          {members.map((member) => {
            const route = byKey.get(member.route);
            return (
              <li key={member.route}>
                <button
                  type="button"
                  onClick={() => onTrace(member.route)}
                  onMouseEnter={() => onPreview(member.route)}
                  onMouseLeave={() => onPreview(null)}
                  onFocus={() => onPreview(member.route)}
                  onBlur={() => onPreview(null)}
                  className="flex w-full items-center gap-2 py-1.5 pr-2.5 pl-8 text-left text-xs hover:bg-muted/60 focus-ring-inset"
                >
                  <span
                    style={closeTiming(marks, member.route)}
                    className={cn(
                      "min-w-0 flex-1 truncate line-through decoration-transparent",
                      "transition-[color,text-decoration-color] duration-[400ms] ease-out",
                      marks.closed.has(member.route) &&
                        "text-muted-foreground decoration-muted-foreground",
                    )}
                  >
                    {member.name}
                  </span>
                  <Marks routeKey={member.route} marks={marks} />
                  {route && <SeverityBadge level={route.target.data_sensitivity} size="sm" />}
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

export function RouteRow({
  route,
  onTrace,
  onPreview,
  marks,
}: {
  route: MappedRoute;
  onTrace: (key: string) => void;
  onPreview: (key: string | null) => void;
  marks: RouteMarks;
}) {
  const t = useT();
  const closed = marks.closed.has(route.key);
  return (
    <button
      type="button"
      onClick={() => onTrace(route.key)}
      onMouseEnter={() => onPreview(route.key)}
      onMouseLeave={() => onPreview(null)}
      onFocus={() => onPreview(route.key)}
      onBlur={() => onPreview(null)}
      className="rounded-lg border border-border px-3 py-2 text-left transition-colors hover:bg-muted/60 focus-ring"
    >
      <span className="flex items-baseline justify-between gap-3">
        {/* Always struck, in a transparent line, so closing is the line
            and the colour fading in -- a strike that appeared at once would
            be the whole cut in one frame. */}
        <span
          style={closeTiming(marks, route.key)}
          className={cn(
            "min-w-0 truncate text-xs font-medium text-foreground line-through decoration-transparent",
            "transition-[color,text-decoration-color] duration-[400ms] ease-out",
            closed && "text-muted-foreground decoration-muted-foreground",
          )}
        >
          {route.entry.name} <span className="text-muted-foreground">→</span>{" "}
          {route.target.name}
        </span>
        <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
          {route.hops} {route.hops === 1 ? t.attackPaths.oneHop : t.attackPaths.hops}
        </span>
      </span>
      <span className="mt-1 flex items-center gap-1.5 text-[11px] text-muted-foreground">
        <SeverityBadge level={route.entry.public_exposure} size="sm" />
        <HopStrip route={route} />
        <SeverityBadge level={route.target.data_sensitivity} size="sm" />
        <span className="ml-auto flex items-center gap-1.5">
          <Marks routeKey={route.key} marks={marks} />
        </span>
      </span>
    </button>
  );
}

/**
 * The route's shape at a glance: a dash a hop, the earliest place to cut in
 * the colour a cut is drawn in. The count beside the row says the same in
 * words, so this is not read out.
 */
function HopStrip({ route }: { route: MappedRoute }) {
  return (
    <span className="flex items-center gap-0.5" aria-hidden>
      {route.steps.map((step) => {
        const cut =
          route.cheapest_break?.source_id === step.source_id &&
          route.cheapest_break?.target_id === step.target_id &&
          route.cheapest_break?.relationship === step.relationship;
        return (
          <span
            key={`${step.source_id}|${step.relationship}|${step.target_id}`}
            className={cn("h-1 w-2.5 rounded-full", cut ? "bg-ok" : "bg-muted-foreground/40")}
          />
        );
      })}
    </span>
  );
}

function Marks({ routeKey, marks }: { routeKey: string; marks: RouteMarks }) {
  const t = useT();
  return (
    <>
      {marks.closed.has(routeKey) && (
        <span
          style={closeTiming(marks, routeKey)}
          className="animate-[cg-rise_300ms_ease-out_both] text-[11px] text-ok"
        >
          {t.attackPaths.closedByPlan}
        </span>
      )}
      {marks.tracked.has(routeKey) && (
        <span className="flex items-center gap-0.5 text-[11px] text-muted-foreground">
          <RadarIcon className="size-3" aria-hidden />
          {t.attackPaths.trackedBadge}
        </span>
      )}
    </>
  );
}
