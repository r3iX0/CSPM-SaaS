import {
  lazy,
  Suspense,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import {
  CircleHelpIcon,
  RouteIcon,
  ScissorsIcon,
  SearchIcon,
  UndoIcon,
  XIcon,
} from "lucide-react";

import { api } from "@/lib/api";
import type {
  AttackPathMeta,
  AttackPathStep,
  DeadEnd,
  MappedRoute,
  Risk,
  RouteMap,
  RouteMapEdge,
  RouteMapMeta,
  RouteMapNode,
  Simulation,
} from "@/lib/types";
import { useT } from "@/i18n";
import { StatStrip } from "@/components/common/StatStrip";
import { SelectField } from "@/components/common/SelectField";
import { ResourceTypeLabel } from "@/components/security/IconLabel";
import { GraphLegend, MARKS } from "@/components/graph/GraphLegend";
import { PatternRow, RouteRow, type RouteMarks } from "@/components/graph/RouteRows";
import { RouteNavigator } from "@/components/graph/RouteNavigator";
import { hopKey, routeKeyOf } from "@/components/graph/routeKeys";
import {
  listRoutes,
  placeName,
  ROUTE_SORTS,
  visits,
  type Place,
  type RouteListing,
  type RouteSort,
} from "@/components/graph/routeOrder";
import { routeMapQuery } from "@/components/graph/graphQueries";
import { usePrefersReducedMotion } from "@/lib/motion";
import { arrivedByMorph } from "@/lib/viewTransition";
import type { Hop } from "@/components/graph/RouteMapCanvas";
import { SimulationPanel } from "@/components/graph/SimulationPanel";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

// React Flow is the heaviest thing this page can load, and a tenant with no
// routes never needs it.
const RouteMapCanvas = lazy(() => import("@/components/graph/RouteMapCanvas"));

/**
 * Attack paths.
 *
 * Every other list in this product ranks by severity, which is the right order
 * for "what is wrong". This page answers a different question — what is wrong
 * *together* — and it answers it twice, because one answer was never enough.
 *
 * The rail ranks routes by hops, where the shortest is both the likeliest and
 * the cheapest to break, or by what they reach, what they start from, or
 * whether a risk tracks them. The map draws all of them at once, because forty
 * routes through one identity are forty rows that never say "one identity",
 * and the drawing says it in a look. Every line carries what cutting it would
 * close — for every link, not for a shortlist — so "which change is worth
 * making" is answered on the picture rather than beside it.
 *
 * **A route is read in the panel (§142).** Tracing one turns the panel into
 * the route navigator: its stops and the links between them, the link being
 * read opened with what cutting it would close, and the routes before and
 * after it in the list a key away. Pressing the traced route's own lines or
 * boxes on the drawing reads that hop. What is traced, the hop, the box
 * picked, the place narrowed to, the search and the sort are all in the URL
 * (`trace`, `hop`, `through`, `scope`, `group`, `q`, `sort`), so a link opens
 * on them.
 *
 * **Changes are tried in the panel's other tab (§141).** Pressing a line off
 * the traced route, or "Add to the plan" on a hop, puts it in a plan answered
 * whole by the server, because two changes can close what neither closes
 * alone. The plan is in the URL too (`cut`, one per link), so it can be sent to
 * whoever makes the change.
 */
export function AttackPathsPage() {
  const t = useT();
  const { data, isLoading, error, refetch } = useQuery(routeMapQuery);

  // Which of these routes the risks queue is tracking. This page rebuilds
  // routes live from the graph; the queue holds the ones with something
  // misconfigured on them, with a status somebody can set. Matched by their
  // ends, which is what names a route on both sides (DECISIONS.md §103).
  const tracked = useQuery({
    queryKey: ["risks", "tracked-routes"],
    enabled: Boolean(data && data.map.routes.length > 0),
    queryFn: () =>
      api.get<Risk[]>("/api/v1/risks?kind=ATTACK_PATH&limit=500").then((r) => {
        const byRoute = new Map<string, Risk>();
        for (const risk of r.data) {
          const first = risk.path[0];
          const last = risk.path[risk.path.length - 1];
          if (first && last) byRoute.set(routeKeyOf(first.source_id, last.target_id), risk);
        }
        return byRoute;
      }),
  });

  // The risks queue leads with the same links, under its own key and its own
  // small endpoint — it wants three rows and has no use for a route map. The
  // graph already carries them, so arriving here fills that cache rather than
  // leaving the next page to ask the server for what this one was just told.
  const queryClient = useQueryClient();
  const chokes = data?.map.choke_points;
  useEffect(() => {
    if (chokes) queryClient.setQueryData(["attack-paths", "choke-points"], chokes);
  }, [chokes, queryClient]);

  const [params, setParams] = useSearchParams();
  const location = useLocation();
  /** The route being read, by key. Null means every route is drawn. */
  const traced = params.get("trace");
  const hopParam = Math.max(
    0,
    Number.parseInt(params.get("hop") ?? "0", 10) || 0,
  );
  /** The box whose routes the list is narrowed to. */
  const picked = params.get("through");
  /** The subscription, and perhaps the group, the list is narrowed to. */
  const place = useMemo<Place | null>(() => {
    const scope = params.get("scope");
    if (!scope) return null;
    // An empty group is what sits directly in the subscription; no group at
    // all is anywhere in it.
    return {
      scope,
      group: params.has("group") ? params.get("group") || null : undefined,
    };
  }, [params]);
  const sortParam = params.get("sort");
  const sort: RouteSort = ROUTE_SORTS.includes(sortParam as RouteSort)
    ? (sortParam as RouteSort)
    : "hops";
  const query = params.get("q") ?? "";
  /** The links somebody is trying out together, in the order they were added. */
  const plan = useMemo(() => params.getAll("cut").flatMap(parseCut), [params]);
  const [tab, setTab] = useState<PanelTab>(() => (plan.length > 0 ? "simulate" : "routes"));
  /** The route under the pointer in the list, drawn faded-around until it leaves. */
  const [previewKey, setPreviewKey] = useState<string | null>(null);
  // Whether the traced route was chosen on this page rather than arriving with
  // a link: only then does the focus follow it into the panel.
  const [chosenHere, setChosenHere] = useState(false);

  // Every change replaces the entry: reading along the page is not a trail
  // somebody retraces with Back, as opening a box on the map is.
  function change(next: Record<string, string | null>) {
    setParams(
      (previous) => {
        const params = new URLSearchParams(previous);
        for (const [name, value] of Object.entries(next)) {
          if (value === null) params.delete(name);
          else params.set(name, value);
        }
        return params;
      },
      { replace: true },
    );
  }
  function setTraced(key: string | null) {
    setPreviewKey(null);
    change({ trace: key, hop: key ? "0" : null });
  }
  /** A route chosen here: read in the Routes tab, with the focus following it. */
  function trace(key: string | null) {
    setChosenHere(true);
    setTraced(key);
    if (key) setTab("routes");
  }

  function setPlan(next: Hop[]) {
    setParams(
      (previous) => {
        const params = new URLSearchParams(previous);
        params.delete("cut");
        for (const link of next) params.append("cut", cutKey(link));
        return params;
      },
      { replace: true },
    );
  }

  const map = data?.map;
  const routes = useMemo(() => map?.routes ?? [], [map]);
  const nodes = useMemo(
    () => new Map((map?.nodes ?? []).map((node) => [node.id, node])),
    [map],
  );
  const edges = useMemo(
    () =>
      new Map(
        (map?.edges ?? []).map((edge) => [
          hopKey(edge.source, edge.relationship, edge.target),
          edge,
        ]),
      ),
    [map],
  );
  const trackedKeys = useMemo(
    () => new Set(tracked.data?.keys() ?? []),
    [tracked.data],
  );
  const listing = useMemo(
    () =>
      map
        ? listRoutes(map, nodes, { picked, place, query, sort, tracked: trackedKeys })
        : null,
    [map, nodes, picked, place, query, sort, trackedKeys],
  );
  const tracedRoute = useMemo(
    () => routes.find((route) => route.key === traced) ?? null,
    [routes, traced],
  );
  const hop = tracedRoute
    ? Math.min(hopParam, tracedRoute.steps.length - 1)
    : 0;
  const previewRoute = useMemo(
    () =>
      previewKey && !tracedRoute
        ? (routes.find((route) => route.key === previewKey) ?? null)
        : null,
    [routes, previewKey, tracedRoute],
  );

  // A link that names a route came to read it, and the frame sits below the
  // counts: bring it up once, on arrival, and never again when somebody traces
  // from the rail they are already looking at (§139).
  const frame = useRef<HTMLDivElement>(null);
  const reduced = usePrefersReducedMotion();
  const [arrivingWith] = useState(traced);
  // After a morph the scroll is instant: the browser takes its picture of this
  // page once it has happened, and grows the link into the frame where it ends.
  const [morphed] = useState(() => arrivedByMorph(location.state));
  const arrived = useRef(false);
  useEffect(() => {
    if (arrived.current || !arrivingWith || tracedRoute?.key !== arrivingWith) return;
    arrived.current = true;
    frame.current?.scrollIntoView?.({
      block: "start",
      behavior: reduced || morphed ? "auto" : "smooth",
    });
  }, [arrivingWith, tracedRoute, reduced, morphed]);

  // Pressing a line, or a suggestion, puts it in the plan or takes it out.
  // From the drawing or a suggestion it opens the tab that answers for the
  // plan; from a hop being read it leaves the reader on the route.
  function togglePlanned(link: Hop, open = true) {
    const key = cutKey(asRemoved(link, map?.edges ?? []));
    const inPlan = plan.some((each) => cutKey(each) === key);
    if (inPlan) setPlan(plan.filter((each) => cutKey(each) !== key));
    else if (plan.length < MAX_CUTS) setPlan([...plan, asRemoved(link, map?.edges ?? [])]);
    if (open) setTab("simulate");
  }
  const isPlanned = (step: AttackPathStep) => {
    const key = cutKey(asRemoved(asHop(step), map?.edges ?? []));
    return plan.some((each) => cutKey(each) === key);
  };

  const simulation = useQuery({
    queryKey: ["attack-paths", "simulate", plan.map(cutKey)],
    enabled: plan.length > 0,
    // The last answer stays up, faded, while the next is checked: a panel that
    // emptied on every press would make adding a second change feel like
    // starting again.
    placeholderData: keepPreviousData,
    queryFn: () =>
      api
        .post<Simulation>("/api/v1/attack-paths/simulate", { cuts: plan })
        .then((r) => r.data),
  });
  const result = plan.length > 0 ? simulation.data : undefined;
  const simulated = useMemo(
    () =>
      plan.length > 0
        ? { links: plan, closes: new Set(result?.closed.map((route) => route.key)) }
        : null,
    [plan, result],
  );
  // What the list and the navigator say about the plan waits for the answer to
  // this plan, never the last one left up while it is checked.
  const settled =
    plan.length > 0 && simulation.isSuccess && !simulation.isFetching ? result : undefined;
  const marks = useMemo<RouteMarks>(
    () => ({
      tracked: trackedKeys,
      closed: new Set(settled?.closed.map((route) => route.key) ?? []),
    }),
    [trackedKeys, settled],
  );

  const at = tracedRoute && listing ? listing.order.indexOf(tracedRoute.key) : -1;
  function stepRoute(delta: -1 | 1) {
    const next = listing?.order[at + delta];
    if (at >= 0 && next) trace(next);
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        icon={RouteIcon}
        title={t.attackPaths.title}
        description={t.attackPaths.intro}
      />

      {isLoading && <CardsSkeleton />}

      {error && (
        <ErrorState
          title="Could not work out your attack paths"
          detail="CloudGuard could not reach its own API to rebuild the graph."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      {data && routes.length === 0 && <NothingFound meta={data.meta} />}

      {data && map && listing && routes.length > 0 && (
        <>
          <StatStrip
            stats={[
              {
                label: t.attackPaths.routesLabel,
                value: data.meta.total,
                alert: data.meta.total > 0,
              },
              { label: t.attackPaths.entryPointsLabel, value: data.meta.entry_points },
              {
                label: t.attackPaths.sensitiveTargetsLabel,
                value: data.meta.sensitive_targets,
              },
            ]}
          />

          {traced && !tracedRoute && (
            <Alert>
              <AlertDescription className="flex flex-wrap items-center justify-between gap-2">
                {t.attackPaths.traceMissing}
                <Button variant="outline" size="sm" onClick={() => setTraced(null)}>
                  {t.attackPaths.traceMissingClear}
                </Button>
              </AlertDescription>
            </Alert>
          )}

          <div ref={frame} className="scroll-mt-4">
            <RouteMapFrame
              map={map}
              meta={data.meta}
              traced={tracedRoute}
              hop={hop}
              preview={previewRoute}
              simulated={simulated}
              tab={tab}
              onTab={setTab}
              routesPanel={
                tracedRoute ? (
                  <RouteNavigator
                    route={tracedRoute}
                    nodes={nodes}
                    edges={edges}
                    hop={hop}
                    onHop={(next) => change({ hop: String(next) })}
                    position={at >= 0 ? { index: at, count: listing.order.length } : null}
                    onRoute={stepRoute}
                    pattern={
                      tracedRoute.pattern
                        ? map.patterns.find((each) => each.id === tracedRoute.pattern)
                        : undefined
                    }
                    risk={tracked.data?.get(tracedRoute.key)}
                    trackingKnown={tracked.isSuccess}
                    isPlanned={isPlanned}
                    onPlan={(step) => togglePlanned(asHop(step), false)}
                    planVerdict={
                      settled ? (marks.closed.has(tracedRoute.key) ? "closed" : "open") : null
                    }
                    focusOnOpen={chosenHere}
                    onBack={() => trace(null)}
                  />
                ) : (
                  <RouteList
                    map={map}
                    nodes={nodes}
                    listing={listing}
                    marks={marks}
                    onTrace={trace}
                    onPreview={setPreviewKey}
                    query={query}
                    onQuery={(next) => change({ q: next || null })}
                    sort={sort}
                    onSort={(next) => change({ sort: next === "hops" ? null : next })}
                    picked={picked}
                    onClearPick={() => change({ through: null })}
                    place={place}
                    onClearPlace={() => change({ scope: null, group: null })}
                  />
                )
              }
              simulationPanel={
                <SimulationPanel
                  map={map}
                  plan={plan}
                  result={result}
                  state={
                    simulation.isError
                      ? "error"
                      : simulation.isFetching
                        ? "checking"
                        : "ready"
                  }
                  maxCuts={MAX_CUTS}
                  onRetry={() => void simulation.refetch()}
                  onAdd={togglePlanned}
                  onRemove={togglePlanned}
                  onClear={() => setPlan([])}
                  onTrace={trace}
                />
              }
              picked={picked}
              onPickNode={(id) => {
                // A box on the route being read reads the hop arriving there.
                const stop = tracedRoute ? visits(tracedRoute).indexOf(id) : -1;
                if (stop >= 0) {
                  setTab("routes");
                  change({ hop: String(Math.max(0, stop - 1)) });
                  return;
                }
                // Any other box asks "what runs through here". The panel
                // answers, and any trace clears so every route through it is
                // visible.
                setTab("routes");
                setPreviewKey(null);
                change({
                  trace: null,
                  hop: null,
                  through: picked === id ? null : id,
                });
              }}
              onPickLink={(link) => {
                // A line on the route being read is read, as a click selects
                // on every canvas; a line anywhere else goes into the plan.
                const index = tracedRoute ? stepOf(tracedRoute, link) : -1;
                if (index >= 0) {
                  setTab("routes");
                  change({ hop: String(index) });
                  return;
                }
                togglePlanned(link);
              }}
              onClearPick={() => change({ through: null })}
            />
          </div>
        </>
      )}
    </div>
  );
}

/**
 * Links one plan may hold, as the API caps it (`MAX_SIMULATED_CUTS`): each is
 * weighed against the rest by rebuilding the estate without it, and a plan
 * longer than this is a project rather than a what-if.
 */
const MAX_CUTS = 10;

type PanelTab = "routes" | "simulate";

const cutKey = (link: Hop) => hopKey(link.source, link.relationship, link.target);

const asHop = (step: AttackPathStep): Hop => ({
  source: step.source_id,
  relationship: step.relationship,
  target: step.target_id,
});

/**
 * Which hop of a route a drawn line is, or -1. An escalation line is drawn
 * beside the role line it comes from, so a press on either reads the hop
 * between those two boxes.
 */
function stepOf(route: MappedRoute, link: Hop): number {
  const exact = route.steps.findIndex(
    (step) =>
      step.source_id === link.source &&
      step.relationship === link.relationship &&
      step.target_id === link.target,
  );
  if (exact >= 0) return exact;
  return route.steps.findIndex(
    (step) => step.source_id === link.source && step.target_id === link.target,
  );
}

/** A `cut` parameter back into a link; nothing for one that is not one. */
function parseCut(value: string): Hop[] {
  const first = value.indexOf("|");
  const last = value.lastIndexOf("|");
  if (first <= 0 || last <= first + 1 || last === value.length - 1) return [];
  return [
    {
      source: value.slice(0, first),
      relationship: value.slice(first + 1, last),
      target: value.slice(last + 1),
    },
  ];
}

/**
 * The link as the thing somebody removes. An escalation line beside a role
 * line is the same role assignment (DECISIONS.md §127), so pressing either
 * plans one change and the choke point that names the assignment shows it.
 */
function asRemoved(link: Hop, edges: RouteMapEdge[]): Hop {
  if (
    link.relationship === "can_grant_roles" &&
    edges.some(
      (edge) =>
        edge.source === link.source &&
        edge.target === link.target &&
        edge.relationship === "grants_role",
    )
  ) {
    return { source: link.source, relationship: "grants_role", target: link.target };
  }
  return { source: link.source, relationship: link.relationship, target: link.target };
}

/**
 * The drawing and the routes, as one frame.
 *
 * The rail used to be a column of cards beside a card holding the canvas, and
 * a traced route opened at the foot of that column, often below the fold. Now
 * it is the estate map's shape (DECISIONS.md §137): the canvas, and a panel on
 * its side that lists the routes and, once one is traced, reads it (§142).
 */
function RouteMapFrame({
  map,
  meta,
  traced,
  hop,
  preview,
  simulated,
  tab,
  onTab,
  routesPanel,
  simulationPanel,
  picked,
  onPickNode,
  onPickLink,
  onClearPick,
}: {
  map: RouteMap;
  meta: RouteMapMeta;
  traced: MappedRoute | null;
  hop: number;
  preview: MappedRoute | null;
  simulated: { links: Hop[]; closes: Set<string> } | null;
  tab: PanelTab;
  onTab: (tab: PanelTab) => void;
  routesPanel: ReactNode;
  simulationPanel: ReactNode;
  picked: string | null;
  onPickNode: (id: string) => void;
  onPickLink: (edge: Hop) => void;
  onClearPick: () => void;
}) {
  const t = useT();

  return (
    <section aria-labelledby="route-map-title" className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 id="route-map-title" className="text-sm font-medium">
          {t.attackPaths.mapTitle}
        </h2>
        <GraphLegend
          label={t.attackPaths.mapHelpLabel}
          items={[
            { mark: MARKS.exposure, label: t.attackPaths.legendEntry },
            { mark: MARKS.sensitive, label: t.attackPaths.legendSensitive },
            { mark: MARKS.findings, label: t.attackPaths.legendFindings },
            { mark: MARKS.weight, label: t.attackPaths.legendWeight },
            ...(simulated
              ? [
                  { mark: MARKS.cut, label: t.attackPaths.legendCut },
                  { mark: MARKS.closed, label: t.attackPaths.legendClosed },
                ]
              : []),
          ]}
        >
          <p>{t.attackPaths.mapHelp}</p>
        </GraphLegend>
      </div>

      {/* What a link from the dashboard grows into (DECISIONS.md §140). */}
      <div
        data-graph-frame=""
        className="flex w-full flex-col overflow-hidden rounded-xl border border-border bg-card lg:h-[36rem]"
      >
        {simulated && (
          <div className="flex items-center gap-2 border-b border-ok-border bg-ok-bg px-3 py-1.5 text-xs text-foreground">
            <ScissorsIcon className="size-3.5 shrink-0 text-ok" aria-hidden />
            <p className="min-w-0 flex-1">
              {t.attackPaths.simulating(simulated.links.length)}
            </p>
            {tab !== "simulate" && (
              <Button variant="ghost" size="sm" onClick={() => onTab("simulate")}>
                {t.attackPaths.simulationShow}
              </Button>
            )}
          </div>
        )}
        <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
          <div className="h-[28rem] min-w-0 lg:h-auto lg:flex-1">
            <Suspense fallback={<Skeleton className="size-full" />}>
              <RouteMapCanvas
                map={map}
                traced={traced}
                hop={traced ? hop : null}
                preview={preview}
                simulated={simulated}
                picked={picked}
                onPickNode={onPickNode}
                onPickLink={onPickLink}
                onClearPick={onClearPick}
              />
            </Suspense>
          </div>

          <aside
            aria-label={t.attackPaths.panelLabel}
            className="flex max-h-[30rem] min-h-0 flex-col border-t border-border lg:max-h-none lg:w-[22rem] lg:border-t-0 lg:border-l"
          >
            <Tabs
              value={tab}
              onValueChange={(value) => onTab(value as PanelTab)}
              className="min-h-0 flex-1 gap-0"
            >
              <div className="border-b border-border p-2">
                <TabsList className="w-full">
                  <TabsTrigger value="routes">
                    {t.attackPaths.tabRoutes}
                    <span className="text-muted-foreground tabular-nums">
                      {map.routes.length}
                    </span>
                  </TabsTrigger>
                  <TabsTrigger value="simulate">
                    {t.attackPaths.tabSimulate}
                    {simulated && (
                      <span className="text-muted-foreground tabular-nums">
                        {simulated.links.length}
                      </span>
                    )}
                  </TabsTrigger>
                </TabsList>
              </div>

              <TabsContent value="routes" className="flex min-h-0 flex-col">
                {routesPanel}
              </TabsContent>

              <TabsContent value="simulate" className="flex min-h-0 flex-col">
                {simulationPanel}
              </TabsContent>
            </Tabs>
          </aside>
        </div>
      </div>

      {meta.drawn < meta.total && (
        <p className="text-xs leading-relaxed text-muted-foreground">
          {t.attackPaths.mapDrawnOf(meta.drawn, meta.total)}
        </p>
      )}
    </section>
  );
}

/**
 * The routes themselves, in the panel beside the drawing.
 *
 * Patterns first, because a group of twelve identical routes is one thing to
 * decide about and twelve things to read. A route belongs to at most one
 * group, so the groups and the rest are every route exactly once. The order
 * and the narrowing are `listRoutes`', which the navigator counts by too.
 */
function RouteList({
  map,
  nodes,
  listing,
  marks,
  onTrace,
  onPreview,
  query,
  onQuery,
  sort,
  onSort,
  picked,
  onClearPick,
  place,
  onClearPlace,
}: {
  map: RouteMap;
  nodes: ReadonlyMap<string, RouteMapNode>;
  listing: RouteListing;
  marks: RouteMarks;
  onTrace: (key: string) => void;
  onPreview: (key: string | null) => void;
  query: string;
  onQuery: (query: string) => void;
  sort: RouteSort;
  onSort: (sort: RouteSort) => void;
  picked: string | null;
  onClearPick: () => void;
  place: Place | null;
  onClearPlace: () => void;
}) {
  const t = useT();
  const byKey = useMemo(
    () => new Map(map.routes.map((route) => [route.key, route])),
    [map.routes],
  );
  const labels: Record<RouteSort, string> = {
    hops: t.attackPaths.sortHops,
    sensitive: t.attackPaths.sortSensitive,
    exposed: t.attackPaths.sortExposed,
    tracked: t.attackPaths.sortTracked,
  };
  const pickedNode = picked ? nodes.get(picked) : undefined;
  // Named by any node in the subscription; the id alone when none drawn is.
  const placeNode = place
    ? map.nodes.find((node) => node.scope_id === place.scope)
    : undefined;
  const placeLabel = place
    ? placeName({
        scope_name: placeNode?.scope_name ?? place.scope,
        group:
          place.group === undefined
            ? null
            : (place.group ?? "what sits directly in it"),
      })
    : null;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {place && (
        <div className="flex items-center gap-2 border-b border-border p-2 pl-3">
          <p className="min-w-0 flex-1 text-xs text-muted-foreground">
            Through{" "}
            <span className="font-medium text-foreground">{placeLabel}</span>{" "}
            <span className="tabular-nums">({listing.count})</span>
          </p>
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label="Show routes everywhere"
            onClick={onClearPlace}
          >
            <XIcon />
          </Button>
        </div>
      )}
      {pickedNode && (
        <div className="flex items-center gap-2 border-b border-border p-2 pl-3">
          <p className="min-w-0 flex-1 text-xs text-muted-foreground">
            <span className="font-medium text-foreground">{pickedNode.name}</span>{" "}
            {t.attackPaths.routesThrough(pickedNode.routes)}
          </p>
          <Button variant="ghost" size="sm" onClick={onClearPick}>
            <UndoIcon data-icon="inline-start" />
            {t.attackPaths.clearTrace}
          </Button>
        </div>
      )}
      <div className="flex shrink-0 items-center gap-2 border-b border-border p-2">
        <div className="relative min-w-0 flex-1">
          <SearchIcon
            className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            type="search"
            value={query}
            onChange={(event) => onQuery(event.target.value)}
            placeholder={t.attackPaths.searchPlaceholder}
            aria-label={t.attackPaths.searchLabel}
            data-page-search
            className="h-7 pl-8 text-xs"
          />
        </div>
        <SelectField
          value={sort}
          onValueChange={(value) => onSort(value as RouteSort)}
          options={ROUTE_SORTS.map((value) => ({ value, label: labels[value] }))}
          ariaLabel={t.attackPaths.sortLabel}
          idleValue="hops"
          className="w-40"
        />
      </div>
      <div className="flex flex-col gap-4 overflow-y-auto p-3">
        {listing.count === 0 && (
          <p className="text-xs text-muted-foreground">
            {query.trim()
              ? t.attackPaths.noneNamed(query.trim())
              : `No route drawn here runs through ${placeLabel ?? "it"}.`}
          </p>
        )}
        {listing.patterns.length > 0 && (
          <div className="flex flex-col gap-2">
            {/* The help is a question mark away: it was three lines above
                the groups, read once and then only in the way (§143). */}
            <div className="flex items-center gap-1">
              <h3 className="text-xs font-medium">{t.attackPaths.patternsTitle}</h3>
              <span className="text-xs text-muted-foreground tabular-nums">
                · {t.attackPaths.patternsCount(listing.patterns.length)}
              </span>
              <Popover>
                <PopoverTrigger
                  render={
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      aria-label={t.attackPaths.patternsHelpLabel}
                      className="ml-auto text-muted-foreground"
                    >
                      <CircleHelpIcon />
                    </Button>
                  }
                />
                <PopoverContent align="end" className="w-72 text-xs leading-relaxed">
                  {t.attackPaths.patternsHelp}
                </PopoverContent>
              </Popover>
            </div>
            {listing.patterns.map(({ pattern, members }) => (
              <PatternRow
                key={pattern.id}
                pattern={pattern}
                members={members}
                onTrace={onTrace}
                onPreview={onPreview}
                byKey={byKey}
                marks={marks}
              />
            ))}
          </div>
        )}

        {listing.loose.length > 0 && (
          <div className="flex flex-col gap-2">
            <h3 className="text-xs font-medium">{t.attackPaths.listTitle}</h3>
            {listing.loose.map((route) => (
              <RouteRow
                key={route.key}
                route={route}
                onTrace={onTrace}
                onPreview={onPreview}
                marks={marks}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * Three different nothings, and they call for three different actions.
 *
 * A single "no attack paths" would read as reassurance in all three cases, and
 * in two of them it is the opposite: nothing classified as sensitive means
 * CloudGuard does not know what would cost the customer anything, which is a
 * gap in what it was told rather than a clean environment.
 */
function NothingFound({ meta }: { meta: AttackPathMeta }) {
  const t = useT();

  if (meta.entry_points === 0 && meta.sensitive_targets === 0) {
    return (
      <EmptyState
        icon={RouteIcon}
        title={t.attackPaths.emptyNoScan}
        detail={t.attackPaths.emptyNoScanDetail}
      />
    );
  }
  if (meta.sensitive_targets === 0) {
    return (
      <EmptyState
        icon={RouteIcon}
        title={t.attackPaths.emptyNoTargets}
        detail={t.attackPaths.emptyNoTargetsDetail}
      />
    );
  }
  if (meta.entry_points === 0) {
    return (
      <EmptyState
        icon={RouteIcon}
        title={t.attackPaths.emptyNoEntry}
        detail={t.attackPaths.emptyNoEntryDetail}
      />
    );
  }
  return (
    <div className="flex flex-col gap-4">
      <EmptyState
        icon={RouteIcon}
        title={t.attackPaths.emptyNoPaths}
        detail={t.attackPaths.emptyNoPathsDetail}
      />
      <DeadEnds meta={meta} />
    </div>
  );
}

const IDENTITY_TYPES = new Set(["user", "service_principal", "group"]);

/**
 * Why there is no route, one way in at a time.
 *
 * "Nothing exposed can reach anything sensitive" alone is a verdict nobody can
 * check, and it was often a statement about people: every directory account is
 * an entry point and every administrator a sensitive one, so a tenant with one
 * admin met the condition with no machine in it (DECISIONS.md §119). The counts
 * by type say which assets the verdict is about; each way in then says where it
 * stops, which is something a person can look at and disagree with.
 */
function DeadEnds({ meta }: { meta: AttackPathMeta }) {
  const t = useT();
  const ends = meta.dead_ends ?? [];
  const sensitive = Object.keys(meta.sensitive_target_types ?? {});
  const onlyAccounts =
    sensitive.length > 0 && sensitive.every((type) => IDENTITY_TYPES.has(type));
  const more = (meta.dead_ends_total ?? ends.length) - ends.length;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">{t.attackPaths.deadEndsTitle}</CardTitle>
        <div className="mt-1.5 flex flex-col gap-1.5 text-xs text-muted-foreground">
          <TypeCounts label={t.attackPaths.exposedCount} counts={meta.entry_point_types} />
          <TypeCounts
            label={t.attackPaths.sensitiveCount}
            counts={meta.sensitive_target_types}
          />
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {onlyAccounts && (
          <Alert>
            <AlertDescription>{t.attackPaths.onlyAccountsSensitive}</AlertDescription>
          </Alert>
        )}
        <ul className="divide-y">
          {ends.map((end) => (
            <li key={end.id} className="flex flex-col gap-0.5 py-2 first:pt-0 last:pb-0">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                {end.asset_id ? (
                  <Link
                    to={`/assets/${end.asset_id}`}
                    className="text-sm font-medium underline-offset-4 hover:underline"
                  >
                    {end.name}
                  </Link>
                ) : (
                  <span className="text-sm font-medium">{end.name}</span>
                )}
                <ResourceTypeLabel
                  type={end.resource_type}
                  className="text-xs text-muted-foreground"
                />
              </div>
              <p className="text-xs text-muted-foreground">{deadEndReason(t, end)}</p>
            </li>
          ))}
        </ul>
        {more > 0 && (
          <p className="text-xs text-muted-foreground">{t.attackPaths.deadEndsMore(more)}</p>
        )}
      </CardContent>
    </Card>
  );
}

function deadEndReason(t: ReturnType<typeof useT>, end: DeadEnd): string {
  switch (end.reason) {
    case "reaches_nothing":
      return t.attackPaths.deadEndReachesNothing(end.resource_type);
    case "identity_without_role":
      return t.attackPaths.deadEndIdentityWithoutRole;
    case "roles_without_control":
      return t.attackPaths.deadEndRolesWithoutControl;
    case "nothing_sensitive":
      return t.attackPaths.deadEndNothingSensitive(end.reached);
  }
}

function TypeCounts({
  label,
  counts,
}: {
  label: string;
  counts?: Record<string, number>;
}) {
  const entries = Object.entries(counts ?? {}).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return null;
  return (
    <p className="flex flex-wrap items-center gap-x-3 gap-y-1">
      <span className="font-medium text-foreground">{label}</span>
      {entries.map(([type, count]) => (
        <span key={type} className="flex items-center gap-1">
          <ResourceTypeLabel type={type} />
          <span className="tabular-nums">{count}</span>
        </span>
      ))}
    </p>
  );
}
