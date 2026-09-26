import { LEVEL_RANK } from "@/lib/changes";
import type { MappedRoute, RouteMap, RouteMapNode, RoutePattern } from "@/lib/types";

/**
 * The routes in the order the attack-path panel lists them, narrowed the way
 * the page is narrowed. One function, because the list and the navigator's
 * "route 3 of 17" have to agree on what the seventeen are and which is third
 * (DECISIONS.md §142).
 */

export type RouteSort = "hops" | "sensitive" | "exposed" | "tracked";

export const ROUTE_SORTS: readonly RouteSort[] = ["hops", "sensitive", "exposed", "tracked"];

/**
 * A subscription, or a group in one, as the estate map opens it. `group`
 * undefined is anywhere in the subscription; null is what sits directly in it.
 */
export interface Place {
  scope: string;
  group: string | null | undefined;
}

/** ARM is case-insensitive about group names: `Prod` and `prod` are one group. */
const sameGroup = (a: string | null, b: string | null) =>
  (a ?? "").toLowerCase() === (b ?? "").toLowerCase();

export function inPlace(node: RouteMapNode | undefined, place: Place): boolean {
  if (!node || node.scope_id !== place.scope) return false;
  return place.group === undefined || sameGroup(node.group, place.group);
}

/** Where a node sits, as a name: "Production › web", or the subscription alone. */
export const placeName = (node: Pick<RouteMapNode, "scope_name" | "group">) =>
  node.group ? `${node.scope_name} › ${node.group}` : node.scope_name;

/** The estate map, opened on the place a node sits. */
export function mapHref(node: Pick<RouteMapNode, "scope_id" | "group">): string {
  const query = new URLSearchParams({ view: "graph", subscription_id: node.scope_id });
  if (node.group) query.set("resource_group", node.group);
  return `/assets?${query}`;
}

/** Every node a route visits, in order: its entry, then each step's target. */
export const visits = (route: MappedRoute) => [
  route.entry.id,
  ...route.steps.map((step) => step.target_id),
];

/** Every name a route passes, for the search box: a route is found by any stop on it. */
const names = (route: MappedRoute) => [
  route.entry.name,
  ...route.steps.map((step) => step.target),
];

export interface RouteNarrowing {
  /** A box: the routes through it. */
  picked: string | null;
  /** A subscription or group: the routes through anything in it. */
  place: Place | null;
  /** Words typed: the routes passing anything so named. */
  query: string;
  sort: RouteSort;
  /** The routes the risks queue tracks, by key, for sorting them first. */
  tracked?: ReadonlySet<string>;
}

export interface RouteListing {
  /** How many routes the narrowing keeps. */
  count: number;
  /** Groups with at least one member kept, each with only those members. */
  patterns: { pattern: RoutePattern; members: RoutePattern["varies"] }[];
  loose: MappedRoute[];
  /** Every kept route by key, in the order the panel lists them. */
  order: string[];
}

const rank = (level: string) => LEVEL_RANK[level] ?? 0;

/**
 * Hops is the server's order, which already ranks the shortest first; the
 * others break their ties by it. UNKNOWN sorts below LOW here, which is a
 * place in a list, not a claim that not knowing is safe.
 */
function comparing(sort: RouteSort, tracked?: ReadonlySet<string>) {
  return (a: MappedRoute, b: MappedRoute): number => {
    switch (sort) {
      case "hops":
        return 0;
      case "sensitive":
        return (
          rank(b.target.data_sensitivity) - rank(a.target.data_sensitivity) || a.hops - b.hops
        );
      case "exposed":
        return rank(b.entry.public_exposure) - rank(a.entry.public_exposure) || a.hops - b.hops;
      case "tracked":
        return (
          Number(tracked?.has(b.key) ?? false) - Number(tracked?.has(a.key) ?? false) ||
          a.hops - b.hops
        );
    }
  };
}

export function listRoutes(
  map: RouteMap,
  nodes: ReadonlyMap<string, RouteMapNode>,
  { picked, place, query, sort, tracked }: RouteNarrowing,
): RouteListing {
  const words = query.trim().toLowerCase();
  const kept = map.routes.filter(
    (route) =>
      (!picked || visits(route).includes(picked)) &&
      (!place || visits(route).some((id) => inPlace(nodes.get(id), place))) &&
      (!words || names(route).some((name) => name.toLowerCase().includes(words))),
  );
  const compare = comparing(sort, tracked);
  const byKey = new Map(kept.map((route) => [route.key, route]));

  // Patterns stay above the rest whatever the sort: a group is one thing to
  // decide about. Within the block they sort by their first member.
  const patterns = map.patterns
    .map((pattern) => ({
      pattern,
      members: pattern.varies
        .filter((member) => byKey.has(member.route))
        .sort((a, b) => compare(byKey.get(a.route)!, byKey.get(b.route)!)),
    }))
    .filter((group) => group.members.length > 0)
    .sort((a, b) => compare(byKey.get(a.members[0].route)!, byKey.get(b.members[0].route)!));
  const grouped = new Set(patterns.flatMap((group) => group.members.map((m) => m.route)));
  // A route whose pattern does not name it among its members is still listed,
  // on its own, rather than lost.
  const loose = kept.filter((route) => !grouped.has(route.key)).sort(compare);

  return {
    count: kept.length,
    patterns,
    loose,
    order: [
      ...patterns.flatMap((group) => group.members.map((member) => member.route)),
      ...loose.map((route) => route.key),
    ],
  };
}
