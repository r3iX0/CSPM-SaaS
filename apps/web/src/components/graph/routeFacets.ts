import { LEVEL_RANK } from "@/lib/changes";
import type { MappedRoute } from "@/lib/types";

/**
 * The facets an engineer narrows the routes by (DECISIONS.md §253), each in the
 * URL beside `trace`, `q` and `sort` so an investigation is a link.
 *
 * Narrowing never removes a route from the drawing: what does not match fades,
 * as everything off a selection does (`kept`), because a route read out of its
 * place is a route read wrong.
 */
export interface RouteFacets {
  /** The least a route's target must hold: HIGH or CRITICAL. */
  reaches: "HIGH" | "CRITICAL" | null;
  /** Where it starts: something on the internet, or an identity signing in. */
  wayIn: "internet" | "identity" | null;
  /** A kind of link it must cross. */
  link: LinkKind | null;
  /** Whether a risk tracks it. */
  tracked: "yes" | "no" | null;
  /** At most this many hops. */
  maxHops: number | null;
}

export type LinkKind = "role" | "network" | "identity";

/** The URL parameter each facet is kept in. */
export const FACET_PARAMS = {
  reaches: "reaches",
  wayIn: "way",
  link: "link",
  tracked: "tracked",
  maxHops: "hops_max",
} as const;

const IDENTITIES = new Set(["user", "service_principal", "group"]);

const LINKS: Record<LinkKind, ReadonlySet<string>> = {
  role: new Set(["grants_role", "can_grant_roles", "can_take_over", "member_of"]),
  network: new Set(["network_access"]),
  identity: new Set(["has_identity", "can_act_as"]),
};

function oneOf<T extends string>(value: string | null, allowed: readonly T[]): T | null {
  return allowed.find((each) => each === value) ?? null;
}

/** The facets a URL names; anything unrecognised is ignored rather than refused. */
export function readFacets(params: URLSearchParams): RouteFacets {
  const hops = Number(params.get(FACET_PARAMS.maxHops));
  return {
    reaches: oneOf(params.get(FACET_PARAMS.reaches), ["HIGH", "CRITICAL"] as const),
    wayIn: oneOf(params.get(FACET_PARAMS.wayIn), ["internet", "identity"] as const),
    link: oneOf(params.get(FACET_PARAMS.link), ["role", "network", "identity"] as const),
    tracked: oneOf(params.get(FACET_PARAMS.tracked), ["yes", "no"] as const),
    maxHops: Number.isInteger(hops) && hops > 0 ? hops : null,
  };
}

export function hasFacets(facets: RouteFacets): boolean {
  return Object.values(facets).some((value) => value !== null);
}

/** Whether a route passes every facet set. */
export function matchesFacets(route: MappedRoute, facets: RouteFacets): boolean {
  const { reaches, wayIn, link, tracked, maxHops } = facets;
  if (reaches && (LEVEL_RANK[route.target.data_sensitivity] ?? 0) < (LEVEL_RANK[reaches] ?? 0)) {
    return false;
  }
  if (wayIn && (wayIn === "identity") !== IDENTITIES.has(route.entry.resource_type)) return false;
  if (link && !route.steps.some((step) => LINKS[link].has(step.relationship))) return false;
  if (tracked && (tracked === "yes") !== Boolean(route.risk)) return false;
  if (maxHops !== null && route.hops > maxHops) return false;
  return true;
}
