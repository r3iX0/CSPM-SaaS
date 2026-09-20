import type { RouteMap } from "@/lib/types";
import { COLUMN_GAP, ROW_GAP } from "./neighborhoodLayout";

/**
 * Where every box on the route map goes: one column per hop from the outside in.
 *
 * The axis is the thing the page is about. Column 0 is every way in, and a
 * box's column is the fewest hops from any of them — so reading left to right
 * is reading an attacker's progress, and a target sitting in column 2 is
 * visibly a nearer problem than one in column 5 without anybody counting
 * lines.
 *
 * Not force-directed, for the reason the neighbourhood is not: a simulation
 * settles somewhere different every run, so one estate would draw a different
 * picture on each visit and two people looking at it would not be looking at
 * the same thing. Here the column comes from the API and the order within it
 * is a pure function of the data.
 *
 * Within a column, boxes sort by the average height of the boxes one column to
 * their left that they are joined to, so a route reads as a line rather than as
 * a zigzag. Ties fall back to name and id, compared by code unit rather than by
 * locale, so the drawing is identical on every machine.
 */
export function layoutRouteMap(map: RouteMap): Map<string, { x: number; y: number }> {
  const columns = new Map<number, string[]>();
  const columnOf = new Map<string, number>();
  const named = new Map<string, string>();
  for (const node of map.nodes) {
    columns.set(node.column, [...(columns.get(node.column) ?? []), node.id]);
    columnOf.set(node.id, node.column);
    named.set(node.id, node.name);
  }

  // What each box hangs from: only edges crossing in from the column on its
  // left, because those are the ones the eye follows across.
  const anchors = new Map<string, string[]>();
  for (const edge of map.edges) {
    const from = columnOf.get(edge.source);
    const to = columnOf.get(edge.target);
    if (from === undefined || to === undefined || to <= from) continue;
    anchors.set(edge.target, [...(anchors.get(edge.target) ?? []), edge.source]);
  }

  const placed = new Map<string, { x: number; y: number }>();
  for (const column of [...columns.keys()].sort((a, b) => a - b)) {
    const anchorOf = (id: string): number => {
      const found = (anchors.get(id) ?? [])
        .map((other) => placed.get(other)?.y)
        .filter((y): y is number => y !== undefined);
      return found.length === 0
        ? 0
        : found.reduce((sum, y) => sum + y, 0) / found.length;
    };

    const boxes = [...(columns.get(column) ?? [])]
      .map((id) => ({ id, anchor: anchorOf(id) }))
      .sort(
        (a, b) =>
          a.anchor - b.anchor ||
          byCodeUnit(named.get(a.id) ?? "", named.get(b.id) ?? "") ||
          byCodeUnit(a.id, b.id),
      );

    boxes.forEach(({ id }, index) => {
      placed.set(id, {
        x: column * COLUMN_GAP,
        y: (index - (boxes.length - 1) / 2) * ROW_GAP,
      });
    });
  }

  return placed;
}

function byCodeUnit(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
