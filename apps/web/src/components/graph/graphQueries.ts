import { queryOptions, type QueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { Asset, Neighborhood, RouteMap, RouteMapMeta } from "@/lib/types";
import { routeKeyOf } from "./routeKeys";

/**
 * The graph pages' queries, declared once so a link can load them ahead.
 *
 * A prefetch only helps if it fills the very entry the page reads, so the key
 * and the shape of what is cached live here rather than in each page: a page
 * that changed its key alone would quietly turn every prefetch into a wasted
 * request (DECISIONS.md §139).
 */

/** The depth the neighbourhood opens at when no route is being traced. */
export const NEIGHBORHOOD_DEPTH = 2;

export const assetQuery = <T extends Pick<Asset, "provider_resource_id"> = Asset>(
  assetId: string,
) =>
  queryOptions({
    queryKey: ["asset", assetId],
    queryFn: () => api.get<T>(`/api/v1/assets/${assetId}`).then((r) => r.data),
  });

export const neighborhoodQuery = (
  providerResourceId: string,
  around: string,
  depth: number,
  folds: string[],
) =>
  queryOptions({
    queryKey: ["neighborhood", providerResourceId, around, depth, folds],
    queryFn: () => {
      const query = new URLSearchParams({ depth: String(depth) });
      for (const fold of folds) query.append("expand", fold);
      return api.get<Neighborhood>(
        `/api/v1/attack-paths/neighborhood/${encodeURIComponent(around)}?${query}`,
      );
    },
  });

export const routeMapQuery = queryOptions({
  queryKey: ["attack-paths", "graph"],
  queryFn: () =>
    api.get<RouteMap>("/api/v1/attack-paths/graph").then((r) => ({
      map: r.data,
      meta: r.meta as unknown as RouteMapMeta,
    })),
});

/**
 * Where something opens in the graph. An asset opens on its Connections tab,
 * centred on itself; a route opens traced on the attack-path page, which is
 * where routes are read (§138).
 */
export type GraphTarget =
  | { kind: "asset"; assetId: string }
  | { kind: "route"; entryId: string; targetId: string };

export function graphHref(target: GraphTarget): string {
  if (target.kind === "asset") return `/assets/${target.assetId}?tab=connections`;
  return `/attack-paths?${new URLSearchParams({
    trace: routeKeyOf(target.entryId, target.targetId),
  })}`;
}

/**
 * Load what a target's page will ask for: its code, and the graph it draws.
 *
 * Every part is fire-and-forget. A prefetch that fails leaves the page to ask
 * again and show its own error, which is where an error belongs; the default
 * `staleTime` keeps a pointer passing twice from asking twice.
 */
export function preloadGraph(client: QueryClient, target: GraphTarget): void {
  if (target.kind === "route") {
    quietly(import("@/pages/AttackPaths"), import("./RouteMapCanvas"));
    void client.prefetchQuery(routeMapQuery);
    return;
  }
  quietly(import("@/pages/AssetDetail"), import("./NeighborhoodCanvas"));
  // The neighbourhood is addressed by the provider's id, which only the asset
  // row knows, so the two are asked in turn.
  client
    .fetchQuery(assetQuery(target.assetId))
    .then((asset) =>
      client.prefetchQuery(
        neighborhoodQuery(
          asset.provider_resource_id,
          asset.provider_resource_id,
          NEIGHBORHOOD_DEPTH,
          [],
        ),
      ),
    )
    .catch(() => {});
}

/** A chunk that fails to load here is loaded again, and reported, by the page. */
function quietly(...loads: Promise<unknown>[]): void {
  for (const load of loads) load.catch(() => {});
}
