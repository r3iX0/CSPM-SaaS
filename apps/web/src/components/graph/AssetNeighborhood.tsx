import { lazy, Suspense, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { WorkflowIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { AttackPath, Neighborhood, NeighborhoodMeta } from "@/lib/types";
import { RISK_KIND_ICONS } from "@/lib/icons";
import { cn } from "@/lib/format";
import { Button, buttonVariants } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { AttackPathRoute } from "./AttackPathRoute";
import { hopKey, routeKey } from "./routeKeys";

// React Flow is loaded only when somebody asks for the graph.
const NeighborhoodCanvas = lazy(() => import("./NeighborhoodCanvas"));

const DEPTHS = [1, 2, 3] as const;

/** The query parameter holding the asset the graph is centred on. */
const AROUND = "around";

/** One drawn picture: a centre, a depth and the folds opened around it. */
const canvasKey = (focus: string, depth: number, folds: string[]) =>
  `${focus}|${depth}|${folds.join(",")}`;

/**
 * The assets around this one, drawn: what can reach it on the left, what it
 * can reach on the right.
 *
 * An addition to the route view, not a replacement for it. A route is drawn
 * as a straight line because that answers "which link do I cut" (see
 * AttackPathRoute); this answers "what is around here", which is a question
 * for exploring rather than acting (DECISIONS.md §101).
 *
 * Loaded on demand, for the same reason as the blast radius beside it: the
 * endpoint needs the organization's whole asset graph, and the canvas is the
 * heaviest chunk on the page.
 *
 * **Walked without leaving the page.** Pressing a box centres the graph on
 * it, and the centre lives in the URL as `?around=`, written as a new history
 * entry rather than a replacement: each re-centre is a step somebody took, so
 * Back retraces it, and a link to a re-centred view opens it drawn. Folds that
 * were opened belong to one centre and are forgotten when it moves.
 */
export function AssetNeighborhood({
  providerResourceId,
  name,
}: {
  providerResourceId: string;
  name: string;
}) {
  const [params, setParams] = useSearchParams();
  const around = params.get(AROUND) ?? providerResourceId;
  const elsewhere = around !== providerResourceId;

  const [asked, setAsked] = useState(elsewhere);
  const [depth, setDepth] = useState<number>(2);
  // By key rather than by object, so a refetch at another depth keeps the
  // same route traced.
  const [tracedKey, setTracedKey] = useState<string | null>(null);
  const [opened, setOpened] = useState<{ around: string; folds: string[] }>({
    around,
    folds: [],
  });
  const folds = opened.around === around ? opened.folds : [];
  // The canvas that should take the keyboard when it draws: the one a press
  // inside the canvas asked for. Named by its key, so a depth change or a Back
  // press -- which draw some other canvas -- never pulls focus off the page.
  const [focusFor, setFocusFor] = useState<string | null>(null);
  const frame = useRef<HTMLDivElement>(null);
  const keyboardInCanvas = () =>
    frame.current?.contains(document.activeElement) ?? false;

  const { data, isLoading, isFetching, error } = useQuery({
    queryKey: ["neighborhood", providerResourceId, around, depth, folds],
    queryFn: () => {
      const query = new URLSearchParams({ depth: String(depth) });
      for (const fold of folds) query.append("expand", fold);
      return api.get<Neighborhood>(
        `/api/v1/attack-paths/neighborhood/${encodeURIComponent(around)}?${query}`,
      );
    },
    enabled: asked,
    retry: false,
    // Keeps the old picture up until the new one arrives -- at another depth,
    // centred elsewhere, with a fold open -- rather than blanking the frame.
    // Only on this asset's page: following a link to another asset must not
    // show the last asset's graph under the new one's name.
    placeholderData: (previous, query) =>
      query?.queryKey[1] === providerResourceId ? previous : undefined,
  });

  const neighborhood = data?.data;
  const meta = data?.meta as NeighborhoodMeta | undefined;
  const centre = neighborhood?.nodes.find((node) => node.id === neighborhood.focus);
  const centreName = centre?.name ?? name;
  const alone =
    neighborhood !== undefined &&
    neighborhood.nodes.length <= 1 &&
    neighborhood.groups.length === 0;
  const routes = neighborhood?.routes ?? [];
  const traced = routes.find((route) => routeKey(route) === tracedKey) ?? null;

  function recenter(id: string) {
    if (id === around) return;
    setFocusFor(keyboardInCanvas() ? canvasKey(id, depth, []) : null);
    setParams((previous) => {
      const next = new URLSearchParams(previous);
      if (id === providerResourceId) next.delete(AROUND);
      else next.set(AROUND, id);
      return next;
    });
  }

  function openGroup(id: string) {
    const next = [...folds, id];
    setFocusFor(keyboardInCanvas() ? canvasKey(around, depth, next) : null);
    setOpened({ around, folds: next });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Around this asset</CardTitle>
        <CardDescription>
          What can reach {name}, and what it can reach, hop by hop
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {!asked && (
          <div>
            <Button variant="outline" size="sm" onClick={() => setAsked(true)}>
              <WorkflowIcon data-icon="inline-start" />
              Draw the graph
            </Button>
          </div>
        )}

        {asked && (
          <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
            <span id="neighborhood-depth">Hops each way</span>
            <div role="group" aria-labelledby="neighborhood-depth" className="flex gap-1">
              {DEPTHS.map((option) => (
                <Button
                  key={option}
                  variant={option === depth ? "secondary" : "ghost"}
                  size="sm"
                  aria-pressed={option === depth}
                  onClick={() => setDepth(option)}
                  className="tabular-nums"
                >
                  {option}
                </Button>
              ))}
            </div>
            {isFetching && !isLoading && <span className="text-xs">Updating…</span>}
          </div>
        )}

        {asked && elsewhere && (
          <div className="flex flex-wrap items-center gap-2 rounded-lg bg-muted/50 px-3 py-2 text-sm">
            <span className="min-w-0 flex-1">
              {centre ? (
                <>
                  Centred on <span className="font-medium">{centre.name}</span>
                </>
              ) : (
                "Centred on an asset that is not in the current graph"
              )}
            </span>
            {centre?.asset_id && (
              <Link
                to={`/assets/${centre.asset_id}`}
                className={buttonVariants({ variant: "outline", size: "sm" })}
              >
                Open its page
              </Link>
            )}
            <Button variant="ghost" size="sm" onClick={() => recenter(providerResourceId)}>
              Back to {name}
            </Button>
          </div>
        )}

        {asked && isLoading && <Skeleton className="h-[28rem] w-full" />}

        {asked && error && (
          <p className="text-sm text-muted-foreground">
            This asset is not a vertex in the current graph — it may not have been in the
            most recent scan.
          </p>
        )}

        {alone && (
          <p className="text-sm text-muted-foreground">
            Nothing reaches {centreName}, and it reaches nothing else CloudGuard has seen.
          </p>
        )}

        {neighborhood && !alone && (
          <>
            <div
              ref={frame}
              role="group"
              aria-label={`Graph of the assets around ${centreName}`}
              className="h-[28rem] w-full overflow-hidden rounded-lg border border-border"
            >
              <Suspense fallback={<Skeleton className="size-full" />}>
                <NeighborhoodCanvas
                  // A new centre, depth or fold is a new picture: remounting
                  // fits it to the frame, where an update would keep the old
                  // viewport pointed at wherever the last one was.
                  key={canvasKey(neighborhood.focus, depth, folds)}
                  neighborhood={neighborhood}
                  traced={traced}
                  pageAsset={providerResourceId}
                  onRecenter={recenter}
                  onOpenGroup={openGroup}
                  takeFocus={focusFor === canvasKey(neighborhood.focus, depth, folds)}
                />
              </Suspense>
            </div>
            <p className="text-xs text-muted-foreground">
              Left of {centreName} is what can reach it; right is what it can reach. Only
              reach is drawn — the network rules around an asset are configuration, and are
              not. A globe marks an asset reachable from the internet, a cylinder one holding
              sensitive data, and the number its open findings. Hops on an attack path are
              drawn darker. Press a box to centre the graph on it; in the graph, arrow keys
              move between boxes.
              {meta && neighborhood.groups.length > 0 && (
                <>
                  {" "}
                  Dashed boxes are counted, not drawn: past {meta.fan_out} neighbors of one
                  asset the rest are grouped, except those exposed to the internet or holding
                  sensitive data. Press one to draw its members.
                </>
              )}
            </p>
            {meta?.truncated && (
              <p className="text-xs text-muted-foreground">
                The graph stops at {meta.max_nodes} assets. What lies beyond the outermost
                boxes was not read — choose fewer hops, or centre on one of them to look
                further.
              </p>
            )}
            <RoutesThrough
              name={centreName}
              routes={routes}
              total={meta?.routes_total ?? routes.length}
              traced={traced}
              onTrace={(route) =>
                setTracedKey(route && routeKey(route) !== tracedKey ? routeKey(route) : null)
              }
              drawn={neighborhood}
              depth={depth}
            />
          </>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * The attack paths this asset sits on, as a list beside the canvas.
 *
 * Picking one traces it on the canvas and draws it again underneath as the
 * straight line `AttackPathRoute` draws everywhere else -- the canvas shows
 * where the route runs through the neighbourhood, the line shows which link
 * to cut. The line is the whole route; the canvas holds only the part within
 * the chosen hops, and when the two differ the card says so.
 */
function RoutesThrough({
  name,
  routes,
  total,
  traced,
  onTrace,
  drawn,
  depth,
}: {
  name: string;
  routes: AttackPath[];
  total: number;
  traced: AttackPath | null;
  onTrace: (route: AttackPath | null) => void;
  drawn: Neighborhood;
  depth: number;
}) {
  const RouteMark = RISK_KIND_ICONS.ATTACK_PATH;

  if (routes.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        No attack path passes through {name}.
      </p>
    );
  }

  const onCanvas = new Set(
    drawn.edges.map((edge) => hopKey(edge.source, edge.relationship, edge.target)),
  );
  const partlyOff =
    traced !== null &&
    traced.steps.some(
      (step) => !onCanvas.has(hopKey(step.source_id, step.relationship, step.target_id)),
    );

  return (
    <section aria-labelledby="routes-through" className="flex flex-col gap-2 border-t pt-3">
      <h3 id="routes-through" className="text-sm font-medium">
        Attack paths through {name}
        <span className="ml-2 font-normal text-muted-foreground tabular-nums">{total}</span>
      </h3>
      <ul className="-mx-2 flex flex-col">
        {routes.map((route) => {
          const active = traced !== null && routeKey(route) === routeKey(traced);
          return (
            <li key={routeKey(route)}>
              <button
                type="button"
                aria-pressed={active}
                onClick={() => onTrace(route)}
                className={cn(
                  "flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm transition-colors hover:bg-muted/60 focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
                  active && "bg-muted",
                )}
              >
                <RouteMark className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />
                <span className="min-w-0 flex-1 truncate">
                  {route.entry.name} → {route.target.name}
                </span>
                <span className="shrink-0 text-xs text-muted-foreground tabular-nums">
                  {route.hops} {route.hops === 1 ? "hop" : "hops"}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
      {total > routes.length && (
        <p className="text-xs text-muted-foreground">
          Showing the {routes.length} shortest of {total}. The attack paths page lists every
          one.
        </p>
      )}
      {traced && (
        <div className="flex flex-col gap-2 rounded-lg border border-border p-3">
          {partlyOff && (
            <p className="text-xs text-muted-foreground">
              Part of this route runs more than {depth} {depth === 1 ? "hop" : "hops"} from{" "}
              {name}, so the canvas shows only some of it. The line below is the whole route.
            </p>
          )}
          <AttackPathRoute
            steps={traced.steps}
            cutIndex={traced.steps.findIndex(
              (step) =>
                traced.cheapest_break?.source_id === step.source_id &&
                traced.cheapest_break?.relationship === step.relationship &&
                traced.cheapest_break?.target_id === step.target_id,
            )}
          />
        </div>
      )}
    </section>
  );
}
