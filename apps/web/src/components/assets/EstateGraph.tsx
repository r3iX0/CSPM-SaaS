import {
  createElement,
  lazy,
  Suspense,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import {
  ArrowLeftIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  CircleHelpIcon,
  MoveRightIcon,
  ScissorsIcon,
  XIcon,
} from "lucide-react";

import { api, ApiError } from "@/lib/api";
import type { EstateBox, EstateEdge, EstateMap, EstateMeta, EstateRoute } from "@/lib/types";
import { FACTOR_ICONS, GRAPH_ICON, RISK_KIND_ICONS } from "@/lib/icons";
import { words } from "@/lib/vocabulary";
import { cn } from "@/lib/format";
import { usePrefersReducedMotion } from "@/lib/motion";
import { EmptyState, ErrorState } from "@/components/common/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { boxHref, boxIcon, boxLabel, edgeLabel } from "@/components/graph/estateNames";
import { Markers } from "@/components/graph/estateMarkers";
import { OpenInGraph } from "@/components/graph/OpenInGraph";
import { PatternRow, RouteRow } from "@/components/graph/RouteRows";
import type { MapSelection } from "@/components/graph/EstateCanvas";

// React Flow is loaded only when somebody opens the map.
const EstateCanvas = lazy(() => import("@/components/graph/EstateCanvas"));

/** One drawn picture per lens. */
const lensKey = (scope: string | null, group: string | null) => `${scope ?? ""}|${group ?? ""}`;

type PanelTab = "paths" | "contents" | "links";

/**
 * The estate as a map: subscriptions, then the groups in one, then the assets
 * in one of those, with the reach that crosses between them (DECISIONS.md
 * §111), and the same boxes again as a ranked list -- which is what the
 * hierarchy view was, and why it is gone (§112).
 *
 * The neighbourhood on an asset's page answers "what is around this asset"
 * and never draws the whole tenant. This answers the question before it --
 * "how is my estate wired together, and where do I start looking" -- by
 * drawing containers instead of assets, and opening one at a time.
 *
 * **One frame, not a page of cards (§133).** The canvas and a panel beside it
 * are the whole view. A click on the canvas selects and the panel answers for
 * what is selected -- what it is, what runs through it -- and opening is a
 * second act. With nothing selected the panel lists the attack paths, the
 * contents and the links, which are the map's text forms. Walking a route
 * puts its step bar across the top of the frame. "Attack paths only" draws
 * just the boxes and arrows a route runs along.
 *
 * **The lens is the list's scope filter.** `subscription_id` and
 * `resource_group` in the URL are what the map has opened, so switching to
 * the list shows the assets the map was drawing, and a link to an opened map
 * is a link like any other. Opening a box is a new history entry, as
 * re-centring the neighbourhood is (§101): each is a step somebody took, so
 * Back retraces it -- unlike narrowing a list, which replaces.
 *
 * **So is the walk.** `walk` (a route's key) and `hop` are in the URL too, and
 * opening a box keeps them: a route that runs into the box opened is still
 * being walked there, which is how a route is followed down into a group. A
 * step along the route replaces the entry rather than adding one.
 */
export function EstateGraph({ scopeId, group }: { scopeId: string; group: string }) {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const location = useLocation();
  const scope = scopeId || null;
  const opened = scope ? group || null : null;
  const walkKey = params.get("walk");
  const hopParam = Math.max(0, Number.parseInt(params.get("hop") ?? "0", 10) || 0);
  const frame = useRef<HTMLDivElement>(null);
  // The picture whose canvas should take the keyboard when it draws: the one
  // a press inside the canvas asked for, never one reached by Back.
  const [focusFor, setFocusFor] = useState<string | null>(null);
  // What is selected, remembered with the picture it belongs to so that
  // opening another box forgets it.
  const [selection, setSelection] = useState<{ lens: string; on: MapSelection } | null>(null);
  const [tab, setTab] = useState<PanelTab | null>(null);
  const [pathsOnly, setPathsOnly] = useState(true);
  const reduced = usePrefersReducedMotion();

  const { data, isLoading, isFetching, error, refetch } = useQuery({
    // The route being walked is not part of the key: it only asks the server
    // to keep that one route past its cap, which a list-picked route never
    // needs and a linked one needs on its first read.
    queryKey: ["estate", scope, opened],
    queryFn: () => {
      const query = new URLSearchParams();
      if (scope) query.set("subscription_id", scope);
      if (opened) query.set("resource_group", opened);
      if (walkKey) query.set("route", walkKey);
      return api.get<EstateMap>(`/api/v1/attack-paths/estate?${query}`);
    },
    retry: false,
    // The old picture stays up until the new one arrives, rather than blanking.
    placeholderData: keepPreviousData,
  });

  const map = data?.data;
  const meta = data?.meta as EstateMeta | undefined;

  function open(next: { scope: string | null; group: string | null }) {
    const inCanvas = frame.current?.contains(document.activeElement) ?? false;
    setFocusFor(inCanvas ? lensKey(next.scope, next.group) : null);
    setParams((previous) => {
      const params = new URLSearchParams(previous);
      if (next.scope) params.set("subscription_id", next.scope);
      else params.delete("subscription_id");
      if (next.group) params.set("resource_group", next.group);
      else params.delete("resource_group");
      params.delete("page");
      return params;
    });
  }

  function openBox(box: EstateBox) {
    // What sits directly in a subscription is drawn when the subscription is
    // opened, so that box -- a group box with no group -- opens the subscription.
    if (box.kind === "scope" || box.kind === "group") {
      open({ scope: box.scope_id, group: box.kind === "group" ? box.group : null });
      return;
    }
    // An asset opens its page with its own graph drawn; the fold, the list.
    const href = boxHref(box);
    if (href) navigate(href, { state: { from: `${location.pathname}${location.search}` } });
  }

  function walkTo(route: string | null, hop = 0) {
    setParams(
      (previous) => {
        const params = new URLSearchParams(previous);
        if (route) {
          params.set("walk", route);
          params.set("hop", String(hop));
        } else {
          params.delete("walk");
          params.delete("hop");
        }
        return params;
      },
      { replace: true },
    );
  }

  if (isLoading) return <Skeleton className="h-[34rem] w-full rounded-xl" />;

  if (error) {
    // Only a 404 means the scope is not there. Anything else -- a timeout, a
    // 500 -- is CloudGuard failing to answer, and saying "nothing is there"
    // would present an outage as an empty estate (§66).
    if (!(error instanceof ApiError) || error.status !== 404) {
      return (
        <ErrorState
          title="Could not draw your estate"
          detail="CloudGuard could not reach its own API to read the map."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      );
    }
    return (
      <Card>
        <CardContent className="flex flex-col items-start gap-3">
          <p className="text-sm">
            CloudGuard holds nothing in that {opened ? "resource group" : "scope"}. It may
            have been removed since the link was made, or not have been in the most recent scan.
          </p>
          <Button variant="outline" size="sm" onClick={() => open({ scope: null, group: null })}>
            Draw the whole estate
          </Button>
        </CardContent>
      </Card>
    );
  }

  if (!map || map.boxes.length === 0) {
    return (
      <EmptyState
        icon={GRAPH_ICON}
        title="Nothing discovered yet"
        detail="Once a scan completes, the subscriptions it read, and the reach between them, are drawn here."
      />
    );
  }

  // The lens's own names, read off the boxes it drew.
  const scopeName =
    map.boxes.find((box) => box.inside && box.scope_id === scope)?.scope_name ?? scope;
  const groupName = map.boxes.find((box) => box.inside && box.group !== null)?.group ?? opened;

  // Keyed on the lens the answer is for, not the one asked: the old picture
  // stays up while the next loads, and the canvas must remount -- and refit --
  // when the new one arrives, not when it was asked for.
  const key = lensKey(map.lens.scope_id, map.lens.group);
  const selected = selection?.lens === key ? selection.on : null;
  const select = (on: MapSelection | null) => setSelection(on ? { lens: key, on } : null);
  // An API from before the routes were sent (§132) answers without them: the
  // web and the API deploy separately, and the map must still draw meanwhile.
  const routes = map.routes ?? [];
  const patterns = map.patterns ?? [];
  const walked = walkKey ? routes.find((route) => route.key === walkKey) : undefined;
  const hop = walked ? Math.min(hopParam, walked.steps.length - 1) : 0;
  const byKey = new Map(routes.map((route) => [route.key, route]));
  const loose = (map.loose ?? []).map((id) => byKey.get(id)).filter((r) => r !== undefined);
  // The estate's own nouns: a subscription on Azure, an account on AWS (§78).
  const w = words(map.boxes.find((box) => box.provider)?.provider);
  const titled = new Map(map.boxes.map((box) => [box.id, boxLabel(box).title]));
  // The text form of the arrows, reach on a route first.
  const reach = map.edges
    .filter((edge) => edgeLabel(edge.links) !== undefined)
    .sort((a, b) => Number(b.on_route) - Number(a.on_route));

  // Attack paths only: the boxes a route passes through and the arrows it
  // runs along, and whatever is selected so a pick from the list is drawn.
  // Off, or with no route here to draw, the whole lens is.
  const filtering = pathsOnly && routes.length > 0;
  const drawn = filtering ? pathsOf(map, selected?.kind === "box" ? selected.id : null) : map;
  const hidden = map.boxes.length - drawn.boxes.length;
  const shownTab: PanelTab = tab ?? (routes.length > 0 ? "paths" : "contents");

  function walk(route: string | null) {
    walkTo(route);
    // Below lg the panel is under the canvas: bring the map back into view.
    if (route) frame.current?.scrollIntoView({ block: "nearest", behavior: reduced ? "auto" : "smooth" });
  }

  const pick = (on: MapSelection) => {
    select(on);
    frame.current?.scrollIntoView({ block: "nearest", behavior: reduced ? "auto" : "smooth" });
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <nav aria-label="Where the map is opened" className="flex flex-wrap items-center gap-1 text-sm">
          <Crumb current={!scope} onClick={() => open({ scope: null, group: null })}>
            Estate
          </Crumb>
          {scope && (
            <>
              <ChevronRightIcon className="size-3.5 text-muted-foreground" aria-hidden />
              <Crumb current={!opened} onClick={() => open({ scope, group: null })}>
                {scopeName}
              </Crumb>
            </>
          )}
          {opened && (
            <>
              <ChevronRightIcon className="size-3.5 text-muted-foreground" aria-hidden />
              <Crumb current>{groupName}</Crumb>
            </>
          )}
          {isFetching && <span className="ml-2 text-xs text-muted-foreground">Updating…</span>}
        </nav>
        <Legend accounts={w.accounts} />
      </div>

      <div
        ref={frame}
        role="group"
        aria-label={`Map of ${opened ? groupName : scope ? scopeName : "the estate"}`}
        className="flex w-full flex-col overflow-hidden rounded-xl border border-border bg-card lg:h-[max(34rem,calc(100dvh-15rem))]"
      >
        {walked && (
          <RouteStepper
            route={walked}
            hop={hop}
            boxes={map.boxes}
            titled={titled}
            onHop={(next) => walkTo(walked.key, next)}
            onFollow={openBox}
            onClose={() => walkTo(null)}
          />
        )}
        <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
          <div className="relative h-[28rem] min-w-0 lg:h-auto lg:flex-1">
            <div className="absolute top-3 left-3 z-10 flex items-center gap-2 rounded-md border border-border bg-card/90 px-2.5 py-1.5 text-xs backdrop-blur-sm">
              <Switch
                id="estate-paths-only"
                size="sm"
                checked={filtering}
                disabled={routes.length === 0}
                onCheckedChange={setPathsOnly}
              />
              <Label htmlFor="estate-paths-only" className="text-xs font-normal">
                Attack paths only
              </Label>
              {filtering && hidden > 0 && (
                <span className="text-muted-foreground tabular-nums">· {hidden} hidden</span>
              )}
            </div>
            <Suspense fallback={<Skeleton className="size-full" />}>
              <EstateCanvas
                // A new lens, or a new filter, is a new picture: remounting
                // lays it out and fits it, where an update would keep the old
                // viewport.
                key={`${key}|${filtering}`}
                map={drawn}
                onOpen={openBox}
                takeFocus={focusFor === key}
                selected={selected}
                onSelect={select}
                trace={walked ? { key: walked.key, boxes: walked.boxes, hop } : null}
              />
            </Suspense>
          </div>

          <aside
            aria-label="About the map"
            className="flex max-h-[30rem] min-h-0 flex-col border-t border-border lg:max-h-none lg:w-[22rem] lg:border-t-0 lg:border-l"
          >
            {selected ? (
              <Selected
                map={map}
                on={selected}
                routes={routes}
                walking={walked?.key ?? null}
                titled={titled}
                onWalk={walk}
                onOpen={openBox}
                onBack={() => select(null)}
              />
            ) : (
              <Tabs
                value={shownTab}
                onValueChange={(value) => setTab(value as PanelTab)}
                className="min-h-0 flex-1 gap-0"
              >
                <div className="border-b border-border p-2">
                  <TabsList className="w-full">
                    <TabsTrigger value="paths" disabled={routes.length === 0}>
                      Paths
                      <span className="text-muted-foreground tabular-nums">
                        {meta?.routes_total ?? routes.length}
                      </span>
                    </TabsTrigger>
                    <TabsTrigger value="contents">
                      Contents
                      <span className="text-muted-foreground tabular-nums">
                        {map.boxes.filter((box) => box.inside).length}
                      </span>
                    </TabsTrigger>
                    <TabsTrigger value="links" disabled={reach.length === 0}>
                      Links
                      <span className="text-muted-foreground tabular-nums">{reach.length}</span>
                    </TabsTrigger>
                  </TabsList>
                </div>

                <TabsContent value="paths" className="flex flex-col gap-2 overflow-y-auto p-3">
                  <p className="text-xs text-muted-foreground">
                    Pick one to walk it on the map, hop by hop.
                    {meta && meta.routes_total > routes.length && (
                      <> The {routes.length} shortest of {meta.routes_total} are listed.</>
                    )}
                  </p>
                  {patterns.map((pattern) => (
                    <PatternRow
                      key={pattern.id}
                      pattern={pattern}
                      traced={walked?.key ?? null}
                      onTrace={walk}
                      byKey={byKey}
                    />
                  ))}
                  {loose.map((route) => (
                    <RouteRow
                      key={route.key}
                      route={route}
                      traced={walked?.key ?? null}
                      onTrace={walk}
                    />
                  ))}
                </TabsContent>

                <TabsContent value="contents" className="overflow-y-auto">
                  <Contents
                    map={map}
                    accounts={w.accounts}
                    drawn={new Set(drawn.boxes.map((box) => box.id))}
                    onPick={(box) => pick({ kind: "box", id: box.id })}
                  />
                </TabsContent>

                <TabsContent value="links" className="overflow-y-auto p-3">
                  <p className="text-xs text-muted-foreground">
                    Reach that crosses between boxes. Pick one to find it on the map.
                  </p>
                  <ul className="-mx-2 mt-2 flex flex-col">
                    {reach.map((edge) => {
                      const id = `${edge.source}|${edge.target}`;
                      return (
                        <li key={id}>
                          <button
                            type="button"
                            onClick={() => pick({ kind: "edge", id })}
                            className={cn(
                              "flex w-full flex-wrap gap-x-1.5 rounded-md px-2 py-1 text-left text-sm transition-colors hover:bg-muted/60",
                              "focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
                            )}
                          >
                            <span className="font-medium">{titled.get(edge.source)}</span>
                            <span className="text-muted-foreground">{edgeLabel(edge.links)}</span>
                            <span className="font-medium">{titled.get(edge.target)}</span>
                            {edge.on_route && (
                              <span className="text-xs text-muted-foreground">
                                · on an attack path
                              </span>
                            )}
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                </TabsContent>
              </Tabs>
            )}
          </aside>
        </div>
      </div>

      {meta && meta.folded_with_reach > 0 && (
        <p className="text-xs text-muted-foreground">
          Past {meta.max_assets} assets the rest are counted in the dashed box;{" "}
          {meta.folded_with_reach} of them hold reach, drawn from that box.
        </p>
      )}
    </div>
  );
}

/**
 * The lens cut down to what attack paths run through: the boxes any route
 * here passes, the arrows a route runs along between two of them, and the
 * one box `keep` names even when no route does, so a box picked from the
 * contents list is drawn to be found.
 */
function pathsOf(map: EstateMap, keep: string | null): EstateMap {
  const onRoute = new Set<string>();
  for (const route of map.routes ?? []) {
    for (const box of route.boxes) if (box) onRoute.add(box);
  }
  const boxes = map.boxes.filter((box) => box.routes > 0 || onRoute.has(box.id) || box.id === keep);
  const kept = new Set(boxes.map((box) => box.id));
  const edges = map.edges.filter(
    (edge) => edge.on_route && kept.has(edge.source) && kept.has(edge.target),
  );
  return { ...map, boxes, edges };
}

/** Routes running through a box, or along an arrow between two. */
function routesThrough(routes: EstateRoute[], on: MapSelection, edge?: EstateEdge): EstateRoute[] {
  if (on.kind === "box") return routes.filter((route) => route.boxes.includes(on.id));
  if (!edge) return [];
  return routes.filter((route) =>
    route.boxes.some(
      (box, i) => box === edge.source && route.boxes[i + 1] === edge.target,
    ),
  );
}

/**
 * What is selected, and the attack paths through it.
 *
 * A box says what it is, with the same marks it carries on the canvas, and
 * offers to open it -- the second act a click does not do. An arrow says
 * everything it carries. Both list the routes that run through, each of which
 * can be walked from here: "what runs through this" is the question a click
 * on the map asks.
 */
function Selected({
  map,
  on,
  routes,
  walking,
  titled,
  onWalk,
  onOpen,
  onBack,
}: {
  map: EstateMap;
  on: MapSelection;
  routes: EstateRoute[];
  walking: string | null;
  titled: ReadonlyMap<string, string>;
  onWalk: (route: string | null) => void;
  onOpen: (box: EstateBox) => void;
  onBack: () => void;
}) {
  const box = on.kind === "box" ? map.boxes.find((each) => each.id === on.id) : undefined;
  const edge =
    on.kind === "edge"
      ? map.edges.find((each) => `${each.source}|${each.target}` === on.id)
      : undefined;
  const through = routesThrough(routes, on, edge);

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-center gap-2 border-b border-border p-2">
        <Button variant="ghost" size="sm" onClick={onBack}>
          <ArrowLeftIcon data-icon="inline-start" />
          All
        </Button>
      </div>
      <div className="flex flex-col gap-3 overflow-y-auto p-3">
        {box && (
          <>
            <div className="flex items-start gap-2">
              {box.kind !== "fold" &&
                createElement(boxIcon(box), {
                  className: "mt-0.5 size-4 shrink-0 text-muted-foreground",
                  "aria-hidden": true,
                })}
              <div className="min-w-0 flex-1">
                <h3 className="truncate text-sm font-medium">{boxLabel(box).title}</h3>
                <p className="truncate text-xs text-muted-foreground">{boxLabel(box).detail}</p>
              </div>
              <Markers box={box} className="text-xs" />
            </div>
            <Button variant="outline" size="sm" className="self-start" onClick={() => onOpen(box)}>
              {box.kind === "scope" || box.kind === "group"
                ? "Open on the map"
                : box.kind === "fold"
                  ? "List them"
                  : "Open its page"}
              <ChevronRightIcon data-icon="inline-end" />
            </Button>
          </>
        )}
        {edge && (
          <div className="flex flex-col gap-1">
            <h3 className="text-sm">
              <span className="font-medium">{titled.get(edge.source)}</span>{" "}
              <span className="text-muted-foreground">→</span>{" "}
              <span className="font-medium">{titled.get(edge.target)}</span>
            </h3>
            <ul className="text-xs text-muted-foreground">
              {edge.links.map((link) => (
                <li key={link.relationship}>
                  {link.label}
                  {link.count > 1 && <span className="tabular-nums"> ×{link.count}</span>}
                </li>
              ))}
            </ul>
          </div>
        )}
        {!box && !edge && (
          <p className="text-xs text-muted-foreground">That is no longer on this map.</p>
        )}

        {(box || edge) && (
          <div className="flex flex-col gap-2">
            <h4 className="text-xs font-medium text-muted-foreground">
              {through.length === 0
                ? "No attack path runs through it."
                : `${through.length} attack path${through.length === 1 ? "" : "s"} through it`}
            </h4>
            {through.map((route) => (
              <RouteRow key={route.key} route={route} traced={walking} onTrace={onWalk} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * The route being walked, one hop at a time, across the top of the map. Where
 * the hop lands in a subscription or group, "Follow into" opens it with the
 * walk kept, so the route is read down to the assets it runs through.
 *
 * The map numbers the boxes the route visits and marks the hop being read;
 * this says what that hop is, in the route's own sentence with the role named
 * (DECISIONS.md section 121), and moves along it. A hop inside one box, or out
 * to somewhere this lens does not draw, is still a hop: it is counted here and
 * said plainly, rather than skipped because the map has no arrow for it.
 */
function RouteStepper({
  route,
  hop,
  boxes,
  titled,
  onHop,
  onFollow,
  onClose,
}: {
  route: EstateRoute;
  hop: number;
  boxes: EstateBox[];
  titled: ReadonlyMap<string, string>;
  onHop: (hop: number) => void;
  onFollow: (box: EstateBox) => void;
  onClose: () => void;
}) {
  const step = route.steps[hop];
  const count = route.steps.length;
  const from = route.boxes[hop];
  const to = route.boxes[hop + 1];
  const cut =
    route.cheapest_break?.source_id === step.source_id &&
    route.cheapest_break?.target_id === step.target_id &&
    route.cheapest_break?.relationship === step.relationship;
  const where =
    from === null || to === null
      ? "Part of this hop is outside what the map has opened."
      : from === to
        ? `Inside ${titled.get(from) ?? "one box"} on this map.`
        : null;
  // The box this hop lands in, when it is one the map can open: following the
  // route into it opens it with the walk kept, at this hop. Only where it
  // lands -- following it back into where it came from reads as a step back.
  const landing = to ? boxes.find((box) => box.id === to) : undefined;
  const into =
    landing && (landing.kind === "scope" || landing.kind === "group") && landing.assets > 0
      ? landing
      : undefined;

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
        {into && (
          <Button variant="outline" size="sm" onClick={() => onFollow(into)}>
            Follow into {titled.get(into.id) ?? "it"}
            <ChevronRightIcon data-icon="inline-end" />
          </Button>
        )}
        <span className="hidden sm:block">
          <OpenInGraph entryId={route.entry.id} traceKey={route.key} />
        </span>
        <Button variant="ghost" size="icon-sm" aria-label="Stop walking the route" onClick={onClose}>
          <XIcon />
        </Button>
      </div>

      <div aria-live="polite" className="flex flex-col gap-0.5 px-1">
        <p className="text-sm">{step.detail || step.description}</p>
        {where && <p className="text-xs text-muted-foreground">{where}</p>}
        {cut && (
          <p className="flex items-center gap-1 text-xs text-ok">
            <ScissorsIcon className="size-3.5" aria-hidden />
            Cutting this link severs the route
          </p>
        )}
      </div>

      {/* Every hop, pressable: how far along the route is, and where it breaks. */}
      <ol className="flex gap-1 px-1" aria-label="Hops">
        {route.steps.map((each, index) => (
          <li key={`${each.source_id}|${each.relationship}|${each.target_id}`} className="flex-1">
            <button
              type="button"
              aria-label={`Hop ${index + 1}: ${each.description}`}
              aria-current={index === hop ? "step" : undefined}
              onClick={() => onHop(index)}
              className={cn(
                "block h-1.5 w-full rounded-full transition-colors focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
                index === hop ? "bg-primary" : index < hop ? "bg-foreground/40" : "bg-muted",
                route.cheapest_break?.source_id === each.source_id &&
                  route.cheapest_break?.target_id === each.target_id &&
                  index !== hop &&
                  "bg-ok/60",
              )}
            />
          </li>
        ))}
      </ol>
    </div>
  );
}

/**
 * What is inside the opened box, worst first, as rows.
 *
 * This is the hierarchy view, folded into the map (§112): at the top the
 * subscriptions, opened the groups, opened again the assets -- each with the
 * same counts the boxes carry, ranked by what is wrong rather than laid out by
 * reach. It is also the map's text form, which a canvas alone does not have.
 * A row selects its box, as a click on the canvas does (§133); a box that
 * "Attack paths only" is not drawing says so.
 */
function Contents({
  map,
  accounts,
  drawn,
  onPick,
}: {
  map: EstateMap;
  accounts: string;
  drawn: ReadonlySet<string>;
  onPick: (box: EstateBox) => void;
}) {
  const rows = map.boxes
    .filter((box) => box.inside)
    .sort(
      (a, b) =>
        // The fold is a remainder, so it always goes last.
        Number(a.kind === "fold") - Number(b.kind === "fold") ||
        b.findings.open - a.findings.open ||
        b.routes - a.routes ||
        b.assets - a.assets ||
        boxLabel(a).title.localeCompare(boxLabel(b).title),
    );
  const heading = map.lens.group
    ? "In this resource group"
    : map.lens.scope_id
      ? "In this scope"
      : `Your ${accounts}`;

  return (
    <div className="flex flex-col py-2">
      <h3 className="px-4 pt-1 text-sm font-medium">
        {heading}
        <span className="ml-2 font-normal text-muted-foreground">worst first</span>
      </h3>
      <ul className="mt-1 flex flex-col">
        {rows.map((box) => {
          const { title, detail } = boxLabel(box);
          return (
            <li key={box.id}>
              <button
                type="button"
                onClick={() => onPick(box)}
                className="flex w-full items-center gap-3 px-4 py-2 text-left transition-colors hover:bg-muted/50 focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
              >
                {box.kind !== "fold" ? (
                  createElement(boxIcon(box), {
                    className: "size-4 shrink-0 text-muted-foreground",
                    "aria-hidden": true,
                  })
                ) : (
                  <span className="size-4 shrink-0" aria-hidden />
                )}
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium">{title}</span>
                  <span className="block truncate text-xs text-muted-foreground">
                    {detail}
                    {!drawn.has(box.id) && " · not on an attack path"}
                  </span>
                </span>
                <Markers box={box} className="text-xs" />
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/**
 * The marks, each once, with its word -- and the rest of how to read the map
 * behind a question mark. It was a paragraph under the canvas, which is the
 * one place a legend is not read.
 */
function Legend({ accounts }: { accounts: string }) {
  const Exposure = FACTOR_ICONS.exposure;
  const Sensitive = FACTOR_ICONS.dataSensitivity;
  const Route = RISK_KIND_ICONS.ATTACK_PATH;
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
      <span className="flex items-center gap-1">
        <Exposure className="size-3.5 text-high" aria-hidden />
        Reachable from the internet
      </span>
      <span className="flex items-center gap-1">
        <Sensitive className="size-3.5 text-high" aria-hidden />
        Sensitive data
      </span>
      <span className="flex items-center gap-1">
        <Route className="size-3.5 text-foreground" aria-hidden />
        Attack paths
      </span>
      <span className="flex items-center gap-1">
        <span className="rounded border px-1 leading-4 font-medium">3</span>
        Open findings
      </span>
      <span className="flex items-center gap-1">
        <MoveRightIcon className="size-3.5 text-foreground" aria-hidden />
        On an attack path
      </span>
      <Popover>
        <PopoverTrigger
          render={
            <Button variant="ghost" size="icon-sm" aria-label="How to read the map">
              <CircleHelpIcon />
            </Button>
          }
        />
        <PopoverContent align="end" className="w-80 text-xs leading-relaxed">
          <p>
            Boxes are {accounts}, the directory, resource groups and assets. Arrows are reach
            that crosses between them: the identity a resource runs as, or a role held over
            another scope. A role over a box reaches everything inside it.
          </p>
          <p>
            Reach runs left to right, starting from the boxes that hold something reachable
            from the internet. Darker arrows are on an attack path.
          </p>
          <p>
            Pressing a box or an arrow selects it, and the panel shows what runs through
            it. Double-click, or press Enter, to open one of the {accounts} or groups here,
            or an asset's own graph. In the map, arrow keys move between boxes.
          </p>
        </PopoverContent>
      </Popover>
    </div>
  );
}

function Crumb({
  current,
  onClick,
  children,
}: {
  current: boolean;
  onClick?: () => void;
  children: ReactNode;
}) {
  if (current) {
    return (
      <span aria-current="location" className="px-2 font-medium">
        {children}
      </span>
    );
  }
  return (
    <Button variant="ghost" size="sm" onClick={onClick}>
      {children}
    </Button>
  );
}
