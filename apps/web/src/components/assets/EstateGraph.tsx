import {
  createElement,
  lazy,
  Suspense,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  Link,
  Navigate,
  useLocation,
  useNavigate,
  useSearchParams,
} from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ArrowLeftIcon, ChevronRightIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import type { EstateBox, EstateEdge, EstateMap, EstateMeta } from "@/lib/types";
import { GRAPH_ICON, RISK_KIND_ICONS } from "@/lib/icons";
import { words } from "@/lib/vocabulary";
import { cn } from "@/lib/format";
import { usePrefersReducedMotion } from "@/lib/motion";
import { EmptyState, ErrorState } from "@/components/common/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { boxHref, boxIcon, boxLabel, edgeLabel } from "@/components/graph/estateNames";
import { Markers } from "@/components/graph/estateMarkers";
import { GraphLegend, MARKS } from "@/components/graph/GraphLegend";
import type { MapSelection } from "@/components/graph/EstateCanvas";

// React Flow is loaded only when somebody opens the map.
const EstateCanvas = lazy(() => import("@/components/graph/EstateCanvas"));

/** One drawn picture per lens. */
const lensKey = (scope: string | null, group: string | null) => `${scope ?? ""}|${group ?? ""}`;

type PanelTab = "contents" | "links";

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
 * what is selected -- what it is, what reaches it, what it reaches -- and
 * opening is a second act. With nothing selected the panel lists the contents
 * and the links, which are the map's text forms.
 *
 * **Connections, not routes (§138).** The map is for exploring how the estate
 * is wired. Attack paths are the attack-path page's: a selected box says how
 * many run through it and links there, narrowed to it, and an old link to
 * walk a route here is sent there.
 *
 * **The lens is the list's scope filter.** `subscription_id` and
 * `resource_group` in the URL are what the map has opened, so switching to
 * the list shows the assets the map was drawing, and a link to an opened map
 * is a link like any other. Opening a box is a new history entry, as
 * re-centring the neighbourhood is (§101): each is a step somebody took, so
 * Back retraces it -- unlike narrowing a list, which replaces.
 */
export function EstateGraph({ scopeId, group }: { scopeId: string; group: string }) {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const location = useLocation();
  const scope = scopeId || null;
  const opened = scope ? group || null : null;
  // A route to walk, from a link made before walking moved (§138).
  const walkKey = params.get("walk");
  const frame = useRef<HTMLDivElement>(null);
  // The picture whose canvas should take the keyboard when it draws: the one
  // a press inside the canvas asked for, never one reached by Back.
  const [focusFor, setFocusFor] = useState<string | null>(null);
  // What is selected, remembered with the picture it belongs to so that
  // opening another box forgets it.
  const [selection, setSelection] = useState<{
    lens: string;
    on: MapSelection;
  } | null>(null);
  const [tab, setTab] = useState<PanelTab>("contents");
  const reduced = usePrefersReducedMotion();

  const { data, isLoading, isFetching, error, refetch } = useQuery({
    queryKey: ["estate", scope, opened],
    queryFn: () => {
      const query = new URLSearchParams();
      if (scope) query.set("subscription_id", scope);
      if (opened) query.set("resource_group", opened);
      return api.get<EstateMap>(`/api/v1/attack-paths/estate?${query}`);
    },
    enabled: !walkKey,
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

  if (walkKey) {
    const to = new URLSearchParams({
      trace: walkKey,
      hop: params.get("hop") ?? "0",
    });
    return <Navigate to={`/attack-paths?${to}`} replace />;
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
  const select = (on: MapSelection | null) =>
    setSelection(on ? { lens: key, on } : null);
  // The estate's own nouns: a subscription on Azure, an account on AWS (§78).
  const w = words(map.boxes.find((box) => box.provider)?.provider);
  const titled = new Map(map.boxes.map((box) => [box.id, boxLabel(box).title]));
  // The text form of the arrows: reach, never containment.
  const reach = map.edges.filter((edge) => edgeLabel(edge.links) !== undefined);

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
        <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
          <div className="relative h-[28rem] min-w-0 lg:h-auto lg:flex-1">
            <Suspense fallback={<Skeleton className="size-full" />}>
              <EstateCanvas
                // A new lens is a new picture: remounting lays it out and
                // fits it, where an update would keep the old viewport.
                key={key}
                map={map}
                onOpen={openBox}
                takeFocus={focusFor === key}
                selected={selected}
                onSelect={select}
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
                titled={titled}
                onPick={pick}
                onOpen={openBox}
                onBack={() => select(null)}
              />
            ) : (
              <Tabs
                value={tab}
                onValueChange={(value) => setTab(value as PanelTab)}
                className="min-h-0 flex-1 gap-0"
              >
                <div className="border-b border-border p-2">
                  <TabsList className="w-full">
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

                <TabsContent value="contents" className="overflow-y-auto">
                  <Contents
                    map={map}
                    accounts={w.accounts}
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
                            <span className="font-medium">
                              {titled.get(edge.source)}
                            </span>
                            <span className="text-muted-foreground">
                              {edgeLabel(edge.links)}
                            </span>
                            <span className="font-medium">
                              {titled.get(edge.target)}
                            </span>
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
 * Where the attack-path page is narrowed to what runs through a box: an asset
 * by its id, a subscription by its scope, a group by its scope and group --
 * an empty group naming what sits directly in the subscription. The fold has
 * no one place, so no link.
 */
function routesHref(box: EstateBox): string | null {
  const query = new URLSearchParams();
  if (box.kind === "asset" && box.provider_resource_id) {
    query.set("through", box.provider_resource_id);
  } else if (box.kind === "scope") {
    query.set("scope", box.scope_id);
  } else if (box.kind === "group") {
    query.set("scope", box.scope_id);
    query.set("group", box.group ?? "");
  } else {
    return null;
  }
  return `/attack-paths?${query}`;
}

/**
 * What is selected, and the reach on either side of it.
 *
 * A box says what it is, with the same marks it carries on the canvas, offers
 * to open it -- the second act a click does not do -- and lists what reaches
 * it and what it reaches on this map, each of which selects that arrow. An
 * arrow says everything it carries and offers its two ends. Where attack
 * paths run through a box, one line says how many and links to them on the
 * attack-path page (§138): the map is for connections, and routes are read
 * there.
 */
function Selected({
  map,
  on,
  titled,
  onPick,
  onOpen,
  onBack,
}: {
  map: EstateMap;
  on: MapSelection;
  titled: ReadonlyMap<string, string>;
  onPick: (on: MapSelection) => void;
  onOpen: (box: EstateBox) => void;
  onBack: () => void;
}) {
  const box = on.kind === "box" ? map.boxes.find((each) => each.id === on.id) : undefined;
  const edge =
    on.kind === "edge"
      ? map.edges.find((each) => `${each.source}|${each.target}` === on.id)
      : undefined;
  const into = box ? map.edges.filter((each) => each.target === box.id) : [];
  const outOf = box ? map.edges.filter((each) => each.source === box.id) : [];
  const routes = box ? routesHref(box) : null;
  const Route = RISK_KIND_ICONS.ATTACK_PATH;

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
            {routes && box.routes > 0 && (
              <Link
                to={routes}
                className="flex items-center gap-1.5 self-start text-xs text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
              >
                <Route className="size-3.5" aria-hidden />
                On {box.routes} attack path{box.routes === 1 ? "" : "s"} — see
                them
              </Link>
            )}
            <ReachList
              title="What reaches it"
              empty="Nothing on this map reaches it."
              edges={into}
              name={(each) => titled.get(each.source)}
              onPick={onPick}
            />
            <ReachList
              title="What it reaches"
              empty="It reaches nothing else on this map."
              edges={outOf}
              name={(each) => titled.get(each.target)}
              onPick={onPick}
            />
          </>
        )}
        {edge && (
          <div className="flex flex-col gap-2">
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
            <div className="flex flex-wrap gap-2">
              {[edge.source, edge.target].map((end) => (
                <Button
                  key={end}
                  variant="outline"
                  size="sm"
                  onClick={() => onPick({ kind: "box", id: end })}
                >
                  {titled.get(end)}
                </Button>
              ))}
            </div>
          </div>
        )}
        {!box && !edge && (
          <p className="text-xs text-muted-foreground">That is no longer on this map.</p>
        )}
      </div>
    </div>
  );
}

/** One side of a box's reach, as rows that select the arrow. */
function ReachList({
  title,
  empty,
  edges,
  name,
  onPick,
}: {
  title: string;
  empty: string;
  edges: EstateEdge[];
  name: (edge: EstateEdge) => string | undefined;
  onPick: (on: MapSelection) => void;
}) {
  return (
    <div className="flex flex-col gap-1">
      <h4 className="text-xs font-medium text-muted-foreground">{title}</h4>
      {edges.length === 0 ? (
        <p className="text-xs text-muted-foreground">{empty}</p>
      ) : (
        <ul className="-mx-2 flex flex-col">
          {edges.map((edge) => (
            <li key={`${edge.source}|${edge.target}`}>
              <button
                type="button"
                onClick={() =>
                  onPick({ kind: "edge", id: `${edge.source}|${edge.target}` })
                }
                className={cn(
                  "flex w-full flex-wrap gap-x-1.5 rounded-md px-2 py-1 text-left text-sm transition-colors hover:bg-muted/60",
                  "focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
                )}
              >
                <span className="font-medium">{name(edge)}</span>
                <span className="text-muted-foreground">
                  {edgeLabel(edge.links) ?? "contains"}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
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
 * A row selects its box, as a click on the canvas does (§133).
 */
function Contents({
  map,
  accounts,
  onPick,
}: {
  map: EstateMap;
  accounts: string;
  onPick: (box: EstateBox) => void;
}) {
  const rows = map.boxes
    .filter((box) => box.inside)
    .sort(
      (a, b) =>
        // The fold is a remainder, so it always goes last.
        Number(a.kind === "fold") - Number(b.kind === "fold") ||
        b.findings.open - a.findings.open ||
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
  return (
    <GraphLegend
      label="How to read the map"
      items={[
        { mark: MARKS.exposure, label: "Reachable from the internet" },
        { mark: MARKS.sensitive, label: "Sensitive data" },
        { mark: MARKS.findings, label: "Open findings" },
      ]}
    >
      <p>
        Boxes are {accounts}, the directory, resource groups and assets. Arrows are reach
        that crosses between them: the identity a resource runs as, or a role held over
        another scope. A role over a box reaches everything inside it.
      </p>
      <p>
        Reach runs left to right: each box sits one column past the furthest box
        that reaches it, so the first column holds what nothing reaches. Where
        reach loops, one arrow has to run back, and it goes round under the
        boxes. A box reachable from the internet carries a globe wherever it
        sits.
      </p>
      <p>
        Pointing at a box fades what it does not touch. Pressing a box or an
        arrow selects it, and the panel shows what reaches it and what it
        reaches. Attack paths are on their own page; a box they run through
        links there. Double-click, or press Enter, to open one of the {accounts}{" "}
        or groups here, or an asset's own graph. In the map, arrow keys move
        between boxes.
      </p>
    </GraphLegend>
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
