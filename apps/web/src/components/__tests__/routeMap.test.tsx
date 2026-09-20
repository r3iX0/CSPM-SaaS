/**
 * Where the boxes on the route map go.
 *
 * Two promises, and both are about the drawing meaning something rather than
 * looking like something:
 *
 * The column is the data. It is the fewest hops from any way in, so reading
 * left to right is reading an attacker's progress — and a box must never drift
 * out of its column to make the picture tidier.
 *
 * The same estate draws the same picture. A force simulation settles somewhere
 * different on every run, so two people looking at one tenant would not be
 * looking at the same thing, and neither could describe what they saw to the
 * other.
 */
import { describe, expect, it } from "vitest";

import { layoutRouteMap } from "../graph/routeMapLayout";
import { COLUMN_GAP } from "../graph/neighborhoodLayout";
import type { RouteMap } from "@/lib/types";

const node = (id: string, column: number) => ({
  id,
  asset_id: null,
  name: id,
  resource_type: "virtual_machine",
  provider: "AZURE",
  column,
  public_exposure: "LOW" as const,
  data_sensitivity: "LOW" as const,
  entry: column === 0,
  sensitive: false,
  routes: 1,
  findings: { open: 0, worst: null },
});

const edge = (source: string, target: string) => ({
  source,
  relationship: "has_identity",
  target,
  label: "runs as",
  facts: [],
  detail: `${source} runs as ${target}`,
  severs: 0,
  closes: [],
  on_routes: 1,
  alternate: false,
});

const MAP: RouteMap = {
  // Deliberately out of order, so the answer cannot come from the sequence the
  // API happened to send.
  nodes: [
    node("mi-b", 1),
    node("web", 0),
    node("mi-a", 1),
    node("data", 2),
    node("api", 0),
  ],
  edges: [
    edge("web", "mi-a"),
    edge("api", "mi-b"),
    edge("mi-a", "data"),
    edge("mi-b", "data"),
  ],
  routes: [],
  patterns: [],
  loose: [],
  choke_points: [],
};

describe("the route map's layout", () => {
  it("puts every box in the column the graph said it was in", () => {
    const at = layoutRouteMap(MAP);

    expect(at.get("web")?.x).toBe(0);
    expect(at.get("api")?.x).toBe(0);
    expect(at.get("mi-a")?.x).toBe(COLUMN_GAP);
    expect(at.get("mi-b")?.x).toBe(COLUMN_GAP);
    expect(at.get("data")?.x).toBe(2 * COLUMN_GAP);
  });

  it("draws the same estate the same way every time", () => {
    const once = layoutRouteMap(MAP);
    const again = layoutRouteMap({ ...MAP, nodes: [...MAP.nodes].reverse() });

    for (const [id, at] of once) {
      expect(again.get(id)).toEqual(at);
    }
  });

  it("hangs a box beneath what leads to it, so a route reads as a line", () => {
    const at = layoutRouteMap(MAP);
    const above = (a: string, b: string) => at.get(a)!.y < at.get(b)!.y;

    // Whichever way in sorts first, its identity follows it rather than
    // landing under the other one's.
    expect(above("api", "web")).toBe(above("mi-b", "mi-a"));
  });
});
