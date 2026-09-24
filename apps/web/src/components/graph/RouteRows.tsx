import { useState } from "react";
import { RadarIcon } from "lucide-react";

import type { MappedRoute, RoutePattern } from "@/lib/types";
import { useT } from "@/i18n";
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
        className="flex w-full items-baseline justify-between gap-3 px-3 py-2 text-left hover:bg-muted/60"
      >
        <span className="min-w-0 text-xs text-foreground">{pattern.description}</span>
        <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
          {pattern.hops} {pattern.hops === 1 ? t.attackPaths.oneHop : t.attackPaths.hops}
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
                  className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-muted/60"
                >
                  <span
                    className={cn(
                      "min-w-0 flex-1 truncate",
                      marks.closed.has(member.route) && "text-muted-foreground line-through",
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
      className="rounded-lg border border-border px-3 py-2 text-left transition-colors hover:bg-muted/60"
    >
      <span className="flex items-baseline justify-between gap-3">
        <span
          className={cn(
            "min-w-0 truncate text-xs font-medium text-foreground",
            closed && "text-muted-foreground line-through",
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
        <span className="text-[11px] text-ok">{t.attackPaths.closedByPlan}</span>
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
