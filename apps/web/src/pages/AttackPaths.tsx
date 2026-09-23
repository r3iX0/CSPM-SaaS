import {
  lazy,
  Suspense,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import {
  ArrowLeftIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  MapIcon,
  RadarIcon,
  RouteIcon,
  ScissorsIcon,
  UndoIcon,
  XIcon,
} from "lucide-react";

import { api } from "@/lib/api";
import type {
  AttackPathMeta,
  ChokePoint,
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
import { cn } from "@/lib/format";
import { StatStrip } from "@/components/common/StatStrip";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { ResourceTypeLabel } from "@/components/security/IconLabel";
import { AttackPathRoute } from "@/components/graph/AttackPathRoute";
import { GraphLegend, MARKS } from "@/components/graph/GraphLegend";
import { OpenInGraph } from "@/components/graph/OpenInGraph";
import { PatternRow, RouteRow } from "@/components/graph/RouteRows";
import { hopKey, routeKeyOf } from "@/components/graph/routeKeys";
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
 * the cheapest to break. The map draws all of them at once, because forty
 * routes through one identity are forty rows that never say "one identity",
 * and the drawing says it in a look. Every line carries what cutting it would
 * close — for every link, not for a shortlist — so "which change is worth
 * making" is answered on the picture rather than beside it.
 *
 * **Routes are read here, not on the estate map (§138).** A traced route is
 * walked one hop at a time in a bar across the top of the drawing, each hop
 * saying which subscription and group it lands in, with a link to that place
 * on the map. The map links back here narrowed to one of its boxes. What is
 * traced, the hop, the box picked and the place narrowed to are all in the URL
 * (`trace`, `hop`, `through`, `scope`, `group`), so a link opens on them.
 *
 * **Changes are tried in the panel's other tab (§141).** Pressing a line adds
 * it to a plan rather than trying it alone, and the plan is answered whole by
 * the server, because two changes can close what neither closes alone. The
 * plan is in the URL too (`cut`, one per link), so it can be sent to whoever
 * makes the change.
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
  /** The links somebody is trying out together, in the order they were added. */
  const plan = useMemo(() => params.getAll("cut").flatMap(parseCut), [params]);
  const [tab, setTab] = useState<PanelTab>(() => (plan.length > 0 ? "simulate" : "routes"));

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
  const setTraced = (key: string | null) =>
    change({ trace: key, hop: key ? "0" : null });

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
  const tracedRoute = useMemo(
    () => routes.find((route) => route.key === traced) ?? null,
    [routes, traced],
  );
  const hop = tracedRoute
    ? Math.min(hopParam, tracedRoute.steps.length - 1)
    : 0;

  // A link that names a route came to read it, and the frame sits below the
  // counts and the choke points: bring it up once, on arrival, and never again
  // when somebody traces from the rail they are already looking at (§139).
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
  // Pressing a line, or a suggestion, puts it in the plan or takes it out,
  // and opens the tab that answers for the plan.
  function togglePlanned(link: Hop) {
    const key = cutKey(asRemoved(link, map?.edges ?? []));
    const inPlan = plan.some((each) => cutKey(each) === key);
    if (inPlan) setPlan(plan.filter((each) => cutKey(each) !== key));
    else if (plan.length < MAX_CUTS) setPlan([...plan, asRemoved(link, map?.edges ?? [])]);
    setTab("simulate");
  }

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

      {data && map && routes.length > 0 && (
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

          {/* Before everything else, because it is what to do about everything
              else. */}
          <ChokePoints
            chokes={map.choke_points}
            planned={plan}
            full={plan.length >= MAX_CUTS}
            onToggle={(link) => {
              togglePlanned(link);
              frame.current?.scrollIntoView?.({
                block: "start",
                behavior: reduced ? "auto" : "smooth",
              });
            }}
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
              onTrace={(key) => {
                setTraced(key);
                if (key) setTab("routes");
              }}
              onHop={(next) => change({ hop: String(next) })}
              tracked={tracked.data}
              trackingKnown={tracked.isSuccess}
              simulated={simulated}
              tab={tab}
              onTab={setTab}
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
                  onTrace={(key) => {
                    setTraced(key);
                    setTab("routes");
                  }}
                />
              }
              picked={picked}
              place={place}
              onPickNode={(id) => {
                // A box asks "what runs through here". The panel answers, and
                // any trace clears so every route through it is visible.
                setTab("routes");
                change({
                  trace: null,
                  hop: null,
                  through: picked === id ? null : id,
                });
              }}
              onPickLink={togglePlanned}
              onClearPick={() => change({ through: null })}
              onClearPlace={() => change({ scope: null, group: null })}
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
 * A subscription, or a group in one, as the estate map opens it. `group`
 * undefined is anywhere in the subscription; null is what sits directly in it.
 */
interface Place {
  scope: string;
  group: string | null | undefined;
}

/** ARM is case-insensitive about group names: `Prod` and `prod` are one group. */
const sameGroup = (a: string | null, b: string | null) =>
  (a ?? "").toLowerCase() === (b ?? "").toLowerCase();

function inPlace(node: RouteMapNode | undefined, place: Place): boolean {
  if (!node || node.scope_id !== place.scope) return false;
  return place.group === undefined || sameGroup(node.group, place.group);
}

/** Every node a route visits, in order: its entry, then each step's target. */
const visits = (route: MappedRoute) => [
  route.entry.id,
  ...route.steps.map((step) => step.target_id),
];

/** Where a node sits, as a name: "Production › web", or the subscription alone. */
const placeName = (node: Pick<RouteMapNode, "scope_name" | "group">) =>
  node.group ? `${node.scope_name} › ${node.group}` : node.scope_name;

/** The estate map, opened on the place a node sits. */
function mapHref(node: Pick<RouteMapNode, "scope_id" | "group">): string {
  const query = new URLSearchParams({
    view: "graph",
    subscription_id: node.scope_id,
  });
  if (node.group) query.set("resource_group", node.group);
  return `/assets?${query}`;
}

/**
 * The links holding up several routes at once, and what happens if one goes.
 *
 * The number is what actually closes, read off an analysis that answers for
 * every link rather than for a shortlist (`graph/severance.py`). Where a link
 * sits on more routes than it closes, the panel says so: a customer told four
 * routes close who then sees two remain stops believing the next number too.
 *
 * Each can be added to the simulation beside the drawing, which answers for
 * it together with whatever else is planned. Adding one changes nothing.
 */
function ChokePoints({
  chokes,
  planned,
  full,
  onToggle,
}: {
  chokes: ChokePoint[];
  planned: Hop[];
  full: boolean;
  onToggle: (link: Hop) => void;
}) {
  const t = useT();
  if (!chokes.length) return null;
  const inPlan = new Set(planned.map(cutKey));

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ScissorsIcon className="size-4 text-muted-foreground" aria-hidden />
          {t.attackPaths.chokeTitle}
        </CardTitle>
        <p className="text-xs leading-relaxed text-muted-foreground">
          {t.attackPaths.chokeHelp}
        </p>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {chokes.map((choke) => {
          const link = {
            source: choke.source.id,
            relationship: choke.relationship,
            target: choke.target.id,
          };
          const simulating = inPlan.has(cutKey(link));

          return (
            <div
              key={cutKey(link)}
              className={cn(
                "rounded-lg border px-4 py-3 transition-colors",
                simulating ? "border-ok-border bg-ok-bg" : "border-border",
              )}
            >
              <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
                <p className="font-mono text-xs text-foreground">{choke.detail}</p>
                <p className="text-xs text-muted-foreground">
                  <span className="text-sm font-semibold tabular-nums text-foreground">
                    {choke.severs}
                  </span>{" "}
                  {t.attackPaths.chokeOf} {choke.total_routes}{" "}
                  {t.attackPaths.chokeSevers}
                </p>
              </div>
              {choke.on_routes > choke.severs && (
                <p className="mt-1 text-xs text-muted-foreground">
                  {t.attackPaths.chokeSitsOn.replace("{on}", String(choke.on_routes))}
                </p>
              )}
              <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
                {choke.closes.map((route) => (
                  <li
                    key={`${route.entry}->${route.target}`}
                    className="flex items-center gap-1.5 text-xs text-muted-foreground"
                  >
                    <SeverityBadge level={route.data_sensitivity} size="sm" />
                    <span>
                      {route.entry} → {route.target}
                    </span>
                  </li>
                ))}
              </ul>
              <Button
                type="button"
                size="sm"
                variant={simulating ? "secondary" : "outline"}
                className="mt-3"
                disabled={!simulating && full}
                onClick={() => onToggle(link)}
              >
                {simulating ? (
                  <>
                    <UndoIcon aria-hidden />
                    {t.attackPaths.simulateStop}
                  </>
                ) : (
                  <>
                    <ScissorsIcon aria-hidden />
                    {t.attackPaths.simulate}
                  </>
                )}
              </Button>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

/**
 * The drawing and the routes, as one frame.
 *
 * The rail used to be a column of cards beside a card holding the canvas, and
 * a traced route opened at the foot of that column, often below the fold. Now
 * it is the estate map's shape (DECISIONS.md §137): the canvas, and a panel on
 * its side that lists the routes and, once one is traced, reads it hop by hop
 * with a way back to the list.
 */
function RouteMapFrame({
  map,
  meta,
  traced,
  hop,
  onTrace,
  onHop,
  tracked,
  trackingKnown,
  simulated,
  tab,
  onTab,
  simulationPanel,
  picked,
  place,
  onPickNode,
  onPickLink,
  onClearPick,
  onClearPlace,
}: {
  map: RouteMap;
  meta: RouteMapMeta;
  traced: MappedRoute | null;
  hop: number;
  onTrace: (key: string | null) => void;
  onHop: (hop: number) => void;
  tracked?: Map<string, Risk>;
  trackingKnown: boolean;
  simulated: { links: Hop[]; closes: Set<string> } | null;
  tab: PanelTab;
  onTab: (tab: PanelTab) => void;
  simulationPanel: ReactNode;
  picked: string | null;
  place: Place | null;
  onPickNode: (id: string) => void;
  onPickLink: (edge: Hop) => void;
  onClearPick: () => void;
  onClearPlace: () => void;
}) {
  const t = useT();
  const nodes = useMemo(
    () => new Map(map.nodes.map((node) => [node.id, node])),
    [map.nodes],
  );

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
        {traced && (
          <RouteStepper
            route={traced}
            hop={hop}
            nodes={nodes}
            onHop={onHop}
            onClose={() => onTrace(null)}
          />
        )}
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
                {traced ? (
                  <TracedRoute
                    route={traced}
                    nodes={nodes}
                    risk={tracked?.get(traced.key)}
                    trackingKnown={trackingKnown}
                    onBack={() => onTrace(null)}
                  />
                ) : (
                  <RouteList
                    map={map}
                    nodes={nodes}
                    onTrace={onTrace}
                    picked={picked}
                    onClearPick={onClearPick}
                    place={place}
                    onClearPlace={onClearPlace}
                  />
                )}
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
 * group, so the groups and the rest are every route exactly once.
 */
function RouteList({
  map,
  nodes,
  onTrace,
  picked,
  onClearPick,
  place,
  onClearPlace,
}: {
  map: RouteMap;
  nodes: ReadonlyMap<string, RouteMapNode>;
  onTrace: (key: string | null) => void;
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
  // With a box picked, the list narrows to the routes running through it —
  // which is the question pressing a box asks. With a place, to the routes
  // through anything in it, which is what the estate map links here for.
  const shown = useMemo(
    () =>
      map.routes.filter(
        (route) =>
          (!picked || visits(route).includes(picked)) &&
          (!place || visits(route).some((id) => inPlace(nodes.get(id), place))),
      ),
    [map.routes, picked, place, nodes],
  );
  const shownKeys = useMemo(
    () => new Set(shown.map((route) => route.key)),
    [shown],
  );
  const patterns = picked
    ? map.patterns.filter((pattern) => pattern.routes.some((key) => shownKeys.has(key)))
    : map.patterns;
  const loose = shown.filter((route) => route.pattern === null);
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
            <span className="tabular-nums">({shown.length})</span>
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
      <div className="flex flex-col gap-4 overflow-y-auto p-3">
        {shown.length === 0 && (
          <p className="text-xs text-muted-foreground">
            No route drawn here runs through {placeLabel ?? "it"}.
          </p>
        )}
        {patterns.length > 0 && (
          <div className="flex flex-col gap-2">
            <div>
              <h3 className="text-xs font-medium">{t.attackPaths.patternsTitle}</h3>
              <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
                {t.attackPaths.patternsHelp}
              </p>
            </div>
            {patterns.map((pattern) => (
              <PatternRow
                key={pattern.id}
                pattern={pattern}
                traced={null}
                onTrace={onTrace}
                byKey={byKey}
              />
            ))}
          </div>
        )}

        {loose.length > 0 && (
          <div className="flex flex-col gap-2">
            <h3 className="text-xs font-medium">{t.attackPaths.listTitle}</h3>
            {loose.map((route) => (
              <RouteRow key={route.key} route={route} traced={null} onTrace={onTrace} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/** One route, read hop by hop, with the link worth cutting marked. */
function TracedRoute({
  route,
  nodes,
  risk,
  trackingKnown,
  onBack,
}: {
  route: MappedRoute;
  nodes: ReadonlyMap<string, RouteMapNode>;
  risk?: Risk;
  trackingKnown: boolean;
  onBack: () => void;
}) {
  const t = useT();
  // The places the route runs through, in the order it reaches them, each a
  // link to the estate map opened there: the map shows a place's wiring, and
  // this is how a route is followed down into it.
  const places = new Map<string, RouteMapNode>();
  for (const id of visits(route)) {
    const node = nodes.get(id);
    if (node)
      places.set(`${node.scope_id}|${(node.group ?? "").toLowerCase()}`, node);
  }
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-center gap-2 border-b border-border p-2">
        <Button variant="ghost" size="sm" onClick={onBack}>
          <ArrowLeftIcon data-icon="inline-start" />
          {t.attackPaths.clearTrace}
        </Button>
      </div>
      <div className="flex flex-col gap-3 overflow-y-auto p-3">
        <div>
          <p className="text-[11px] font-medium text-muted-foreground">{t.attackPaths.route}</p>
          <h3 className="text-sm font-medium">
            {route.entry.name} <span className="text-muted-foreground">→</span>{" "}
            {route.target.name}
          </h3>
        </div>
        <AttackPathRoute
          steps={route.steps}
          cutIndex={route.steps.findIndex(
            (step) =>
              route.cheapest_break?.source_id === step.source_id &&
              route.cheapest_break?.target_id === step.target_id,
          )}
        />
        {places.size > 0 && (
          <div className="flex flex-col gap-1">
            <h4 className="text-xs font-medium text-muted-foreground">
              Where it runs
            </h4>
            <ul className="flex flex-col gap-0.5">
              {[...places.values()].map((node) => (
                <li key={`${node.scope_id}|${node.group ?? ""}`}>
                  <Link
                    to={mapHref(node)}
                    className="flex items-center gap-1.5 text-xs underline-offset-4 hover:underline"
                  >
                    <MapIcon
                      className="size-3.5 text-muted-foreground"
                      aria-hidden
                    />
                    {placeName(node)}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        )}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <OpenInGraph entryId={route.entry.id} traceKey={route.key} />
          {risk ? (
            <Link
              to={`/risks/${risk.id}`}
              className="flex items-center gap-1.5 text-xs text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
            >
              <RadarIcon className="size-3.5" aria-hidden />
              Tracked as a risk
            </Link>
          ) : (
            trackingKnown && (
              <span className="text-xs text-muted-foreground">
                Not a risk: nothing on this route fails a check
              </span>
            )
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * The route being read, one hop at a time, across the top of the drawing.
 *
 * Moved here from the estate map (DECISIONS.md §138). The drawing marks the
 * hop being read; this says what that hop is, in the route's own sentence with
 * the role named (§121), where it lands -- the subscription and group, a link
 * to that place on the map -- and whether cutting it severs the route. Arrow
 * keys step along it and Escape puts it down.
 */
function RouteStepper({
  route,
  hop,
  nodes,
  onHop,
  onClose,
}: {
  route: MappedRoute;
  hop: number;
  nodes: ReadonlyMap<string, RouteMapNode>;
  onHop: (hop: number) => void;
  onClose: () => void;
}) {
  const step = route.steps[hop];
  const count = route.steps.length;
  const landing = nodes.get(step.target_id);
  const isCut = (each: MappedRoute["steps"][number]) =>
    route.cheapest_break?.source_id === each.source_id &&
    route.cheapest_break?.target_id === each.target_id &&
    route.cheapest_break?.relationship === each.relationship;

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === "ArrowLeft" && hop > 0) onHop(hop - 1);
    else if (event.key === "ArrowRight" && hop < count - 1) onHop(hop + 1);
    else if (event.key === "Escape") onClose();
    else return;
    event.preventDefault();
  }

  return (
    <div
      role="group"
      aria-label={`Attack path from ${route.entry.name} to ${route.target.name}`}
      onKeyDown={onKeyDown}
      className="flex shrink-0 flex-col gap-2 border-b border-border bg-muted/30 p-2.5"
    >
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="icon-sm"
          aria-label="Previous hop"
          disabled={hop === 0}
          onClick={() => onHop(hop - 1)}
        >
          <ChevronLeftIcon />
        </Button>
        <span className="w-20 text-center text-xs font-medium tabular-nums">
          Hop {hop + 1} of {count}
        </span>
        <Button
          variant="outline"
          size="icon-sm"
          aria-label="Next hop"
          disabled={hop === count - 1}
          onClick={() => onHop(hop + 1)}
        >
          <ChevronRightIcon />
        </Button>
        <p className="min-w-0 flex-1 truncate text-xs text-muted-foreground">
          {route.entry.name} <span aria-hidden>→</span>
          <span className="sr-only">to</span> {route.target.name}
        </p>
        <Button
          variant="ghost"
          size="icon-sm"
          aria-label="Stop reading the route"
          onClick={onClose}
        >
          <XIcon />
        </Button>
      </div>

      <div aria-live="polite" className="flex flex-col gap-0.5 px-1">
        <p className="text-sm">{step.detail || step.description}</p>
        {landing && (
          <p className="text-xs text-muted-foreground">
            Lands in{" "}
            <Link
              to={mapHref(landing)}
              className="underline underline-offset-4 hover:text-foreground"
            >
              {placeName(landing)}
            </Link>
          </p>
        )}
        {isCut(step) && (
          <p className="flex items-center gap-1 text-xs text-ok">
            <ScissorsIcon className="size-3.5" aria-hidden />
            Cutting this link severs the route
          </p>
        )}
      </div>

      {/* Every hop, pressable: how far along the route is, and where it breaks. */}
      <ol className="flex gap-1 px-1" aria-label="Hops">
        {route.steps.map((each, index) => (
          <li
            key={`${each.source_id}|${each.relationship}|${each.target_id}`}
            className="flex-1"
          >
            <button
              type="button"
              aria-label={`Hop ${index + 1}: ${each.description}`}
              aria-current={index === hop ? "step" : undefined}
              onClick={() => onHop(index)}
              className={cn(
                "block h-1.5 w-full rounded-full transition-colors focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
                index === hop
                  ? "bg-primary"
                  : isCut(each)
                    ? "bg-ok/60"
                    : index < hop
                      ? "bg-foreground/40"
                      : "bg-muted",
              )}
            />
          </li>
        ))}
      </ol>
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
