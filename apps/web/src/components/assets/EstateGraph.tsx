import { lazy, Suspense, useRef, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ChevronRightIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { EstateBox, EstateMap, EstateMeta } from "@/lib/types";
import { GRAPH_ICON } from "@/lib/icons";
import { words } from "@/lib/vocabulary";
import { EmptyState } from "@/components/common/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { boxLabel, edgeLabel } from "@/components/graph/estateNames";

// React Flow is loaded only when somebody opens the graph view.
const EstateCanvas = lazy(() => import("@/components/graph/EstateCanvas"));

/** Links listed under the canvas before the list says how many more. */
const LISTED_LINKS = 12;

/** One drawn picture per lens. */
const lensKey = (scope: string | null, group: string | null) => `${scope ?? ""}|${group ?? ""}`;

/**
 * The estate as a graph: subscriptions, then the groups in one, then the
 * assets in one of those, with the reach that crosses between them
 * (DECISIONS.md §111).
 *
 * The neighbourhood on an asset's page answers "what is around this asset"
 * and never draws the whole tenant. This answers the question before it --
 * "how is my estate wired together, and where do I start looking" -- by
 * drawing containers instead of assets, and opening one at a time.
 *
 * **The lens is the list's scope filter.** `subscription_id` and
 * `resource_group` in the URL are what the map has opened, so switching to
 * the list shows the assets the map was drawing, and a link to an opened map
 * is a link like any other. Opening a box is a new history entry, as
 * re-centring the neighbourhood is (§101): each is a step somebody took, so
 * Back retraces it -- unlike narrowing a list, which replaces.
 */
export function EstateGraph({ scopeId, group }: { scopeId: string; group: string }) {
  const [, setParams] = useSearchParams();
  const scope = scopeId || null;
  const opened = scope ? group || null : null;
  const frame = useRef<HTMLDivElement>(null);
  // The picture whose canvas should take the keyboard when it draws: the one
  // a press inside the canvas asked for, never one reached by Back.
  const [focusFor, setFocusFor] = useState<string | null>(null);

  const { data, isLoading, isFetching, error } = useQuery({
    queryKey: ["estate", scope, opened],
    queryFn: () => {
      const query = new URLSearchParams();
      if (scope) query.set("subscription_id", scope);
      if (opened) query.set("resource_group", opened);
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
    }
  }

  if (isLoading) return <Skeleton className="h-[32rem] w-full rounded-xl" />;

  if (error) {
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
  // The estate's own nouns: a subscription on Azure, an account on AWS (§78).
  const w = words(map.boxes.find((box) => box.provider)?.provider);
  const titled = new Map(map.boxes.map((box) => [box.id, boxLabel(box).title]));
  // The text form of the arrows, reach on a route first.
  const reach = map.edges
    .filter((edge) => edgeLabel(edge.links) !== undefined)
    .sort((a, b) => Number(b.on_route) - Number(a.on_route));

  return (
    <div className="flex flex-col gap-3">
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

      <div
        ref={frame}
        role="group"
        aria-label={`Graph of ${opened ? groupName : scope ? scopeName : "the estate"}`}
        className="h-[32rem] w-full overflow-hidden rounded-xl border border-border bg-card"
      >
        <Suspense fallback={<Skeleton className="size-full" />}>
          <EstateCanvas
            // A new lens is a new picture: remounting fits it to the frame,
            // where an update would keep the old viewport.
            key={key}
            map={map}
            onOpen={openBox}
            takeFocus={focusFor === key}
          />
        </Suspense>
      </div>

      <p className="text-xs text-muted-foreground">
        Boxes are {w.accounts}, the directory, resource groups and assets; arrows are reach
        that crosses between them — the identity a resource runs as, a role held over another
        scope. Reach runs left to right, from the boxes holding something reachable from the
        internet, and a role over a box reaches everything inside it. A globe counts assets
        reachable from the internet, a cylinder assets holding sensitive data, the route mark
        attack paths through the box, and the number its open findings. Darker arrows are on an
        attack path. Pressing one of the {w.accounts} or groups opens it here; pressing an asset
        opens the graph around it. In the graph, arrow keys move between boxes.
        {meta && meta.folded_with_reach > 0 && (
          <>
            {" "}
            Past {meta.max_assets} assets the rest are counted in the dashed box;{" "}
            {meta.folded_with_reach} of them hold reach, drawn from that box.
          </>
        )}
      </p>

      {reach.length > 0 && (
        <Card>
          <CardContent>
            <h3 className="text-sm font-medium">
              Reach across boundaries
              {meta && (
                <span className="ml-2 font-normal text-muted-foreground tabular-nums">
                  {meta.routes_total} attack path{meta.routes_total === 1 ? "" : "s"} through
                  here
                </span>
              )}
            </h3>
            <ul className="mt-2 flex flex-col gap-1 text-sm">
              {reach.slice(0, LISTED_LINKS).map((edge) => (
                <li key={`${edge.source}|${edge.target}`} className="flex flex-wrap gap-x-1.5">
                  <span className="font-medium">{titled.get(edge.source)}</span>
                  <span className="text-muted-foreground">{edgeLabel(edge.links)}</span>
                  <span className="font-medium">{titled.get(edge.target)}</span>
                  {edge.on_route && (
                    <span className="text-xs text-muted-foreground">· on an attack path</span>
                  )}
                </li>
              ))}
            </ul>
            {reach.length > LISTED_LINKS && (
              <p className="mt-2 text-xs text-muted-foreground">
                And {reach.length - LISTED_LINKS} more on the graph.
              </p>
            )}
          </CardContent>
        </Card>
      )}
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
