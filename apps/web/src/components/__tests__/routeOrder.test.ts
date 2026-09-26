/**
 * The order the attack-path panel lists routes in, and the narrowing.
 *
 * The list and the navigator's "route 3 of 17" read the same answer, so a
 * route missing from one or counted twice by the other is a navigator that
 * skips or repeats. Worth checking without a page around it.
 */
import { describe, expect, it } from "vitest";

import { listRoutes } from "@/components/graph/routeOrder";
import type { MappedRoute, RouteMap, RouteMapNode } from "@/lib/types";

function route(
  key: string,
  entry: string,
  target: string,
  over: Partial<MappedRoute> = {},
): MappedRoute {
  return {
    key,
    pattern: null,
    entry: { id: entry, name: entry, resource_type: "virtual_machine", public_exposure: "HIGH" },
    target: { id: target, name: target, resource_type: "storage_account", data_sensitivity: "HIGH" },
    hops: 2,
    steps: [
      {
        source: entry,
        source_id: entry,
        relationship: "has_identity",
        target: "mi",
        target_id: "mi",
        description: "",
        facts: [],
        detail: "",
      },
      {
        source: "mi",
        source_id: "mi",
        relationship: "grants_role",
        target,
        target_id: target,
        description: "",
        facts: [],
        detail: "",
      },
    ],
    cheapest_break: null,
    ...over,
  };
}

function node(id: string, scope: string, group: string | null): RouteMapNode {
  return {
    id,
    asset_id: null,
    name: id,
    resource_type: "virtual_machine",
    provider: "AZURE",
    scope_id: scope,
    scope_name: scope,
    group,
    column: 0,
    public_exposure: "LOW",
    data_sensitivity: "LOW",
    entry: false,
    sensitive: false,
    routes: 1,
    findings: { open: 0, worst: null },
  };
}

const A = route("a|store", "a", "store", { pattern: "p" });
const B = route("b|store", "b", "store", { pattern: "p" });
const C = route("c|vault", "c", "vault", {
  hops: 3,
  target: { id: "vault", name: "vault", resource_type: "key_vault", data_sensitivity: "CRITICAL" },
});

const MAP: RouteMap = {
  nodes: [node("a", "sub-1", "web"), node("b", "sub-2", "web"), node("c", "sub-1", "ops")],
  edges: [],
  routes: [A, B, C],
  patterns: [
    {
      id: "p",
      kind: "many_entries",
      description: "2 machines reach store the same way",
      size: 2,
      hops: 2,
      exemplar: A.key,
      routes: [A.key, B.key],
      varies: [
        { id: "a", name: "a", route: A.key },
        { id: "b", name: "b", route: B.key },
      ],
    },
  ],
  loose: [C.key],
  choke_points: [],
};
const NODES = new Map(MAP.nodes.map((each) => [each.id, each]));
const ALL = { picked: null, place: null, query: "", sort: "hops" as const };

describe("listRoutes", () => {
  it("lists groups first, then the rest, and counts each route once", () => {
    const listing = listRoutes(MAP, NODES, ALL);
    expect(listing.order).toEqual([A.key, B.key, C.key]);
    expect(listing.count).toBe(3);
  });

  it("narrows a group's members to the place, not only the loose routes", () => {
    // A group used to be shown whole whatever place the list was narrowed to.
    const listing = listRoutes(MAP, NODES, {
      ...ALL,
      place: { scope: "sub-1", group: "web" },
    });
    expect(listing.patterns).toHaveLength(1);
    expect(listing.patterns[0].members.map((m) => m.route)).toEqual([A.key]);
    expect(listing.order).toEqual([A.key]);
  });

  it("finds a route by an asset in its middle", () => {
    expect(listRoutes(MAP, NODES, { ...ALL, query: "MI" }).count).toBe(3);
    expect(listRoutes(MAP, NODES, { ...ALL, query: "vault" }).order).toEqual([C.key]);
  });

  it("sorts the rest by what they reach, and tracked routes first when asked", () => {
    const plain = { ...MAP, patterns: [], routes: [A, B, C].map((r) => ({ ...r, pattern: null })) };
    expect(listRoutes(plain, NODES, { ...ALL, sort: "sensitive" }).order[0]).toBe(C.key);
    expect(
      listRoutes(plain, NODES, { ...ALL, sort: "tracked", tracked: new Set([B.key]) }).order[0],
    ).toBe(B.key);
    // Hops keeps the server's order, which already ranks the shortest first.
    expect(listRoutes(plain, NODES, ALL).order).toEqual([A.key, B.key, C.key]);
  });
});
