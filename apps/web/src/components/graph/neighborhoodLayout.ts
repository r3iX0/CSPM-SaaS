import type { Neighborhood } from "@/lib/types";

/** Horizontal distance between hops: a 220px box and room for the longest edge label. */
export const COLUMN_GAP = 400;
/** Vertical distance between boxes in one hop. */
export const ROW_GAP = 72;

interface Item {
  id: string;
  layer: number;
  /** Assets before folded groups within a column. */
  kind: 0 | 1;
  type: string;
  name: string;
}

/**
 * Where every box goes: one column per hop, the focus at the origin.
 *
 * Deliberately not force-directed. A simulation settles somewhere different
 * each time it runs, so the same asset would draw a different picture on every
 * visit and two people looking at one estate would not be looking at the same
 * thing. Here the column is the hop count the API reported -- what reaches the
 * asset to the left, what it reaches to the right -- and the order within a
 * column is a pure function of the data.
 *
 * Columns are filled from the focus outward, and each box is placed by the
 * average height of the boxes one hop nearer the focus that it is joined to,
 * so children sit beside their parents and edges cross as little as a single
 * pass can manage. Ties fall back to kind, type, name and finally id, compared
 * by code unit rather than locale, so the result is the same on every machine.
 */
export function layoutNeighborhood(
  neighborhood: Neighborhood,
): Map<string, { x: number; y: number }> {
  const items: Item[] = [
    ...neighborhood.nodes.map((node) => ({
      id: node.id,
      layer: node.layer,
      kind: 0 as const,
      type: node.resource_type,
      name: node.name,
    })),
    ...neighborhood.groups.map((group) => ({
      id: group.id,
      layer: group.layer,
      kind: 1 as const,
      type: "",
      name: "",
    })),
  ];

  const joined = new Map<string, string[]>();
  for (const edge of neighborhood.edges) {
    joined.set(edge.source, [...(joined.get(edge.source) ?? []), edge.target]);
    joined.set(edge.target, [...(joined.get(edge.target) ?? []), edge.source]);
  }

  const columns = new Map<number, Item[]>();
  for (const item of items) {
    columns.set(item.layer, [...(columns.get(item.layer) ?? []), item]);
  }

  const placed = new Map<string, { x: number; y: number }>();
  const layerOf = new Map(items.map((item) => [item.id, item.layer]));

  // The focus, then one hop either way, then two: each column only ever looks
  // at the one inside it, which is always placed first.
  const order = [...columns.keys()].sort(
    (a, b) => Math.abs(a) - Math.abs(b) || b - a,
  );

  for (const layer of order) {
    const inner = layer - Math.sign(layer);
    const anchor = (item: Item): number => {
      const heights = (joined.get(item.id) ?? [])
        .filter((other) => layerOf.get(other) === inner)
        .map((other) => placed.get(other)?.y)
        .filter((y): y is number => y !== undefined);
      return heights.length === 0
        ? 0
        : heights.reduce((sum, y) => sum + y, 0) / heights.length;
    };

    const column = [...(columns.get(layer) ?? [])]
      .map((item) => ({ item, anchor: anchor(item) }))
      .sort(
        (a, b) =>
          a.anchor - b.anchor ||
          a.item.kind - b.item.kind ||
          byCodeUnit(a.item.type, b.item.type) ||
          byCodeUnit(a.item.name, b.item.name) ||
          byCodeUnit(a.item.id, b.item.id),
      );

    column.forEach(({ item }, index) => {
      placed.set(item.id, {
        x: layer * COLUMN_GAP,
        y: (index - (column.length - 1) / 2) * ROW_GAP,
      });
    });
  }

  return placed;
}

function byCodeUnit(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
