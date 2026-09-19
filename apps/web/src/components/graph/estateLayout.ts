import type { EstateBox, EstateMap } from "@/lib/types";

/** Horizontal distance between columns: a 240px box and room for an edge label. */
export const ESTATE_COLUMN_GAP = 380;
/** Vertical distance between boxes in one column. */
export const ESTATE_ROW_GAP = 76;
/** Boxes with no reach are stacked this many to a column, so a quiet estate is a grid. */
export const QUIET_ROWS = 8;

const KIND_ORDER: Record<EstateBox["kind"], number> = {
  scope: 0,
  group: 1,
  asset: 2,
  fold: 3,
};

/** A total order on boxes that depends on nothing but the boxes. */
function byBox(a: EstateBox, b: EstateBox): number {
  return (
    Number(b.inside) - Number(a.inside) ||
    KIND_ORDER[a.kind] - KIND_ORDER[b.kind] ||
    byCodeUnit(a.name ?? "", b.name ?? "") ||
    byCodeUnit(a.id, b.id)
  );
}

/**
 * Where every box goes: columns in the direction reach runs.
 *
 * Laid out rather than simulated, for the reason the neighbourhood is
 * (DECISIONS.md §101): the same estate draws the same picture on every visit.
 * There is no focus here to count hops from, so the columns count them from
 * where reach starts instead -- every box holding a way in, and every box
 * nothing reaches -- and each box sits at its shortest distance from one.
 * Reach therefore reads left to right, and a box holding an entry point is
 * always in the first column, because that is where an attacker starts.
 *
 * A cycle nothing leads into is entered at its first box in the fixed order,
 * so it is drawn rather than lost. Boxes with no reach at all go last, stacked
 * into a grid: they are part of the estate and are shown, but they are not on
 * the way anywhere.
 *
 * Within a column each box sits at the average height of the boxes it joins
 * in the columns already placed, so edges cross as little as one pass can
 * manage; ties fall back to the fixed order.
 */
export function layoutEstate(map: EstateMap): Map<string, { x: number; y: number }> {
  const boxes = [...map.boxes].sort(byBox);
  const out = new Map<string, Set<string>>();
  const into = new Set<string>();
  const joined = new Map<string, Set<string>>();
  for (const edge of map.edges) {
    if (edge.source === edge.target) continue;
    out.set(edge.source, (out.get(edge.source) ?? new Set<string>()).add(edge.target));
    into.add(edge.target);
    joined.set(edge.source, (joined.get(edge.source) ?? new Set<string>()).add(edge.target));
    joined.set(edge.target, (joined.get(edge.target) ?? new Set<string>()).add(edge.source));
  }

  const quiet = boxes.filter((box) => !joined.has(box.id));
  const wired = boxes.filter((box) => joined.has(box.id));

  const column = new Map<string, number>();
  const walk = (seeds: string[]) => {
    const queue = seeds.filter((id) => !column.has(id));
    for (const id of queue) column.set(id, 0);
    for (let i = 0; i < queue.length; i += 1) {
      const here = queue[i];
      for (const next of [...(out.get(here) ?? [])].sort(byCodeUnit)) {
        if (column.has(next)) continue;
        column.set(next, column.get(here)! + 1);
        queue.push(next);
      }
    }
  };
  walk(wired.filter((box) => box.entry > 0 || !into.has(box.id)).map((box) => box.id));
  for (const box of wired) {
    if (!column.has(box.id)) walk([box.id]);
  }

  const last = wired.reduce((most, box) => Math.max(most, column.get(box.id)! + 1), 0);
  quiet.forEach((box, index) => column.set(box.id, last + Math.floor(index / QUIET_ROWS)));

  const columns = new Map<number, EstateBox[]>();
  for (const box of boxes) {
    const at = column.get(box.id)!;
    columns.set(at, [...(columns.get(at) ?? []), box]);
  }

  const placed = new Map<string, { x: number; y: number }>();
  for (const at of [...columns.keys()].sort((a, b) => a - b)) {
    const anchor = (box: EstateBox, order: number): number => {
      const heights = [...(joined.get(box.id) ?? [])]
        .map((other) => placed.get(other)?.y)
        .filter((y): y is number => y !== undefined);
      // A box joined to nothing placed yet keeps its place in the fixed order.
      return heights.length === 0
        ? order * ESTATE_ROW_GAP
        : heights.reduce((sum, y) => sum + y, 0) / heights.length;
    };
    const sorted = (columns.get(at) ?? [])
      .map((box, order) => ({ box, anchor: anchor(box, order) }))
      .sort((a, b) => a.anchor - b.anchor || byBox(a.box, b.box));
    sorted.forEach(({ box }, index) => {
      placed.set(box.id, {
        x: at * ESTATE_COLUMN_GAP,
        y: (index - (sorted.length - 1) / 2) * ESTATE_ROW_GAP,
      });
    });
  }
  return placed;
}

function byCodeUnit(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
