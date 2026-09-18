import type { AttackPath } from "@/lib/types";

/**
 * One hop, keyed by its ends and its relationship. The relationship is part of
 * the key because one pair can be joined twice -- an identity that holds a
 * role over a scope and can also grant roles over it -- and tracing a route
 * along the grant must not light up the role beside it.
 */
export const hopKey = (source: string, relationship: string, target: string) =>
  `${source}|${relationship}|${target}`;

/** One route. It is the shortest from its entry to its target, so the pair names it. */
export const routeKeyOf = (entryId: string, targetId: string) => `${entryId}|${targetId}`;

export const routeKey = (route: AttackPath) => routeKeyOf(route.entry.id, route.target.id);
