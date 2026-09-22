import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { RadarIcon, RouteIcon, ScissorsIcon, UndoIcon } from "lucide-react";

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
  RoutePattern,
} from "@/lib/types";
import { useT } from "@/i18n";
import { cn } from "@/lib/format";
import { StatStrip } from "@/components/common/StatStrip";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { ResourceTypeLabel } from "@/components/security/IconLabel";
import { AttackPathRoute } from "@/components/graph/AttackPathRoute";
import { OpenInGraph } from "@/components/graph/OpenInGraph";
import { routeKeyOf } from "@/components/graph/routeKeys";
import type { Hop } from "@/components/graph/RouteMapCanvas";
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
 */
export function AttackPathsPage() {
  const t = useT();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["attack-paths", "graph"],
    queryFn: () =>
      api.get<RouteMap>("/api/v1/attack-paths/graph").then((r) => ({
        map: r.data,
        meta: r.meta as unknown as RouteMapMeta,
      })),
  });

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

  /** The route being read, by key. Null means every route is drawn. */
  const [traced, setTraced] = useState<string | null>(null);
  /** The link somebody is weighing up, and what the graph said closes with it. */
  const [considered, setConsidered] = useState<RouteMapEdge | null>(null);
  /** The box whose routes the rail is narrowed to. */
  const [picked, setPicked] = useState<string | null>(null);

  const map = data?.map;
  const routes = useMemo(() => map?.routes ?? [], [map]);
  const tracedRoute = useMemo(
    () => routes.find((route) => route.key === traced) ?? null,
    [routes, traced],
  );
  const simulated = useMemo(
    () =>
      considered
        ? {
            link: {
              source: considered.source,
              relationship: considered.relationship,
              target: considered.target,
            } satisfies Hop,
            closes: new Set(considered.closes),
          }
        : null,
    [considered],
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
            edges={map.edges}
            considered={considered}
            onConsider={setConsidered}
          />

          <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
            <RouteMapCard
              map={map}
              meta={data.meta}
              traced={tracedRoute}
              simulated={simulated}
              picked={picked}
              onPickNode={(id) => {
                // A box asks "what runs through here". The rail answers, and
                // any trace clears so every route through it is visible.
                setTraced(null);
                setConsidered(null);
                setPicked((current) => (current === id ? null : id));
              }}
              onPickLink={(edge) =>
                setConsidered((current) =>
                  current && sameLink(current, edge) ? null : edge,
                )
              }
              onClearPick={() => setPicked(null)}
            />

            <RouteRail
              map={map}
              traced={traced}
              onTrace={setTraced}
              tracked={tracked.data}
              trackingKnown={tracked.isSuccess}
              picked={picked}
            />
          </div>
        </>
      )}
    </div>
  );
}

const sameLink = (a: RouteMapEdge, b: RouteMapEdge) =>
  a.source === b.source && a.relationship === b.relationship && a.target === b.target;

/**
 * The links holding up several routes at once, and what happens if one goes.
 *
 * The number is what actually closes, read off an analysis that answers for
 * every link rather than for a shortlist (`graph/severance.py`). Where a link
 * sits on more routes than it closes, the panel says so: a customer told four
 * routes close who then sees two remain stops believing the next number too.
 *
 * "Simulate the cut" changes nothing. It greys out what would go out of reach,
 * on the drawing, from the same answer the number came from — so the claim and
 * the picture cannot disagree.
 */
function ChokePoints({
  chokes,
  edges,
  considered,
  onConsider,
}: {
  chokes: ChokePoint[];
  edges: RouteMapEdge[];
  considered: RouteMapEdge | null;
  onConsider: (edge: RouteMapEdge | null) => void;
}) {
  const t = useT();
  if (!chokes.length) return null;

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
          const edge = edges.find(
            (candidate) =>
              candidate.source === choke.source.id &&
              candidate.relationship === choke.relationship &&
              candidate.target === choke.target.id,
          );
          const simulating = Boolean(edge && considered && sameLink(edge, considered));

          return (
            <div
              key={`${choke.source.id}-${choke.relationship}-${choke.target.id}`}
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
              {edge && (
                <Button
                  type="button"
                  size="sm"
                  variant={simulating ? "secondary" : "outline"}
                  className="mt-3"
                  onClick={() => onConsider(simulating ? null : edge)}
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
              )}
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

function RouteMapCard({
  map,
  meta,
  traced,
  simulated,
  picked,
  onPickNode,
  onPickLink,
  onClearPick,
}: {
  map: RouteMap;
  meta: RouteMapMeta;
  traced: MappedRoute | null;
  simulated: { link: Hop; closes: Set<string> } | null;
  picked: string | null;
  onPickNode: (id: string) => void;
  onPickLink: (edge: RouteMapEdge) => void;
  onClearPick: () => void;
}) {
  const t = useT();
  const pickedNode = map.nodes.find((node) => node.id === picked);

  return (
    <Card className="min-w-0">
      <CardHeader>
        <CardTitle className="text-sm">{t.attackPaths.mapTitle}</CardTitle>
        {simulated && (
          <Alert className="mt-2 border-ok-border bg-ok-bg text-ok">
            <ScissorsIcon />
            <AlertDescription className="text-foreground">
              {t.attackPaths.simulating}
            </AlertDescription>
          </Alert>
        )}
        {pickedNode && (
          <p className="mt-1 flex flex-wrap items-center gap-x-2 text-xs text-muted-foreground">
            <span className="font-medium text-foreground">{pickedNode.name}</span>
            {t.attackPaths.routesThrough(pickedNode.routes)}
            <button
              type="button"
              onClick={onClearPick}
              className="underline underline-offset-4 hover:text-foreground"
            >
              {t.attackPaths.clearTrace}
            </button>
          </p>
        )}
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        <div className="h-[32rem] w-full overflow-hidden rounded-lg border border-border">
          <Suspense fallback={<Skeleton className="size-full" />}>
            <RouteMapCanvas
              map={map}
              traced={traced}
              simulated={simulated}
              onPickNode={onPickNode}
              onPickLink={onPickLink}
            />
          </Suspense>
        </div>
        <p className="text-xs leading-relaxed text-muted-foreground">
          {t.attackPaths.mapHelp}
          {meta.drawn < meta.total && (
            <> {t.attackPaths.mapDrawnOf(meta.drawn, meta.total)}</>
          )}
        </p>
      </CardContent>
    </Card>
  );
}

/**
 * The routes themselves, beside the drawing.
 *
 * Patterns first, because a group of twelve identical routes is one thing to
 * decide about and twelve things to read. A route belongs to at most one
 * group, so the groups and the rest are every route exactly once.
 */
function RouteRail({
  map,
  traced,
  onTrace,
  tracked,
  trackingKnown,
  picked,
}: {
  map: RouteMap;
  traced: string | null;
  onTrace: (key: string | null) => void;
  tracked?: Map<string, Risk>;
  trackingKnown: boolean;
  picked: string | null;
}) {
  const t = useT();
  const byKey = useMemo(
    () => new Map(map.routes.map((route) => [route.key, route])),
    [map.routes],
  );
  // With a box picked, the rail narrows to the routes running through it —
  // which is the question pressing a box asks.
  const shown = useMemo(() => {
    if (!picked) return map.routes;
    return map.routes.filter(
      (route) =>
        route.entry.id === picked ||
        route.steps.some((step) => step.target_id === picked),
    );
  }, [map.routes, picked]);
  const shownKeys = useMemo(() => new Set(shown.map((route) => route.key)), [shown]);
  const patterns = picked
    ? map.patterns.filter((pattern) => pattern.routes.some((key) => shownKeys.has(key)))
    : map.patterns;
  const loose = shown.filter((route) => route.pattern === null);
  const tracedRoute = traced ? byKey.get(traced) : undefined;

  return (
    <aside className="flex min-w-0 flex-col gap-4">
      {traced && (
        <Button type="button" variant="outline" size="sm" onClick={() => onTrace(null)}>
          <UndoIcon aria-hidden />
          {t.attackPaths.clearTrace}
        </Button>
      )}

      {patterns.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">{t.attackPaths.patternsTitle}</CardTitle>
            <p className="text-xs leading-relaxed text-muted-foreground">
              {t.attackPaths.patternsHelp}
            </p>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {patterns.map((pattern) => (
              <PatternRow
                key={pattern.id}
                pattern={pattern}
                traced={traced}
                onTrace={onTrace}
                byKey={byKey}
              />
            ))}
          </CardContent>
        </Card>
      )}

      {loose.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">{t.attackPaths.listTitle}</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {loose.map((route) => (
              <RouteRow key={route.key} route={route} traced={traced} onTrace={onTrace} />
            ))}
          </CardContent>
        </Card>
      )}

      {tracedRoute && (
        <TracedRoute
          route={tracedRoute}
          risk={tracked?.get(tracedRoute.key)}
          trackingKnown={trackingKnown}
        />
      )}
    </aside>
  );
}

function PatternRow({
  pattern,
  traced,
  onTrace,
  byKey,
}: {
  pattern: RoutePattern;
  traced: string | null;
  onTrace: (key: string | null) => void;
  byKey: Map<string, MappedRoute>;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);

  return (
    <div className="rounded-lg border border-border">
      <button
        type="button"
        onClick={() => setOpen((was) => !was)}
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
          {pattern.varies.map((member) => (
            <li key={member.route}>
              <button
                type="button"
                onClick={() => onTrace(traced === member.route ? null : member.route)}
                className={cn(
                  "flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-muted/60",
                  traced === member.route && "bg-muted font-medium",
                )}
              >
                <span className="min-w-0 flex-1 truncate">{member.name}</span>
                {byKey.get(member.route) && (
                  <SeverityBadge
                    level={byKey.get(member.route)!.target.data_sensitivity}
                    size="sm"
                  />
                )}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function RouteRow({
  route,
  traced,
  onTrace,
}: {
  route: MappedRoute;
  traced: string | null;
  onTrace: (key: string | null) => void;
}) {
  const t = useT();
  return (
    <button
      type="button"
      onClick={() => onTrace(traced === route.key ? null : route.key)}
      className={cn(
        "rounded-lg border px-3 py-2 text-left transition-colors hover:bg-muted/60",
        traced === route.key ? "border-foreground bg-muted" : "border-border",
      )}
    >
      <span className="flex items-baseline justify-between gap-3">
        <span className="min-w-0 truncate text-xs font-medium text-foreground">
          {route.entry.name} <span className="text-muted-foreground">→</span>{" "}
          {route.target.name}
        </span>
        <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
          {route.hops} {route.hops === 1 ? t.attackPaths.oneHop : t.attackPaths.hops}
        </span>
      </span>
      <span className="mt-1 flex items-center gap-1.5 text-[11px] text-muted-foreground">
        <SeverityBadge level={route.entry.public_exposure} size="sm" />
        <span aria-hidden>→</span>
        <SeverityBadge level={route.target.data_sensitivity} size="sm" />
      </span>
    </button>
  );
}

/** One route, read hop by hop, with the link worth cutting marked. */
function TracedRoute({
  route,
  risk,
  trackingKnown,
}: {
  route: MappedRoute;
  risk?: Risk;
  trackingKnown: boolean;
}) {
  const t = useT();
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">
          {route.entry.name} <span className="text-muted-foreground">→</span>{" "}
          {route.target.name}
        </CardTitle>
        <p className="text-[11px] font-medium text-muted-foreground">
          {t.attackPaths.route}
        </p>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <AttackPathRoute
          steps={route.steps}
          cutIndex={route.steps.findIndex(
            (step) =>
              route.cheapest_break?.source_id === step.source_id &&
              route.cheapest_break?.target_id === step.target_id,
          )}
        />
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
      </CardContent>
    </Card>
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
