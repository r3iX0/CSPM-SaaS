/**
 * The query bar's facets (DECISIONS.md §253): read from the URL, ignored when
 * unrecognised, and each one a test of the route alone.
 */
import { describe, expect, it } from "vitest";

import { hasFacets, matchesFacets, readFacets } from "@/components/graph/routeFacets";
import type { MappedRoute } from "@/lib/types";

const ROUTE: MappedRoute = {
  key: "vm|kv",
  pattern: null,
  risk: null,
  entry: { id: "vm", name: "vm", resource_type: "virtual_machine", public_exposure: "HIGH" },
  target: { id: "kv", name: "kv", resource_type: "key_vault", data_sensitivity: "HIGH" },
  hops: 2,
  steps: [
    {
      source: "vm",
      source_id: "vm",
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
      target: "kv",
      target_id: "kv",
      description: "",
      facts: [],
      detail: "",
    },
  ],
  cheapest_break: null,
};

const facets = (query: string) => readFacets(new URLSearchParams(query));

describe("route facets", () => {
  it("reads what it knows from the URL and ignores the rest", () => {
    expect(facets("reaches=CRITICAL&way=identity&hops_max=3")).toEqual({
      reaches: "CRITICAL",
      wayIn: "identity",
      link: null,
      tracked: null,
      maxHops: 3,
    });
    expect(hasFacets(facets("reaches=SOMETHING&hops_max=-1"))).toBe(false);
  });

  it("tests each facet against the route alone", () => {
    expect(matchesFacets(ROUTE, facets("reaches=HIGH"))).toBe(true);
    expect(matchesFacets(ROUTE, facets("reaches=CRITICAL"))).toBe(false);
    expect(matchesFacets(ROUTE, facets("way=internet"))).toBe(true);
    expect(matchesFacets(ROUTE, facets("way=identity"))).toBe(false);
    expect(matchesFacets(ROUTE, facets("link=role"))).toBe(true);
    expect(matchesFacets(ROUTE, facets("link=network"))).toBe(false);
    expect(matchesFacets(ROUTE, facets("tracked=no"))).toBe(true);
    expect(matchesFacets(ROUTE, facets("hops_max=1"))).toBe(false);
  });
});
