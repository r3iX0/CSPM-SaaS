import type { EstateBox, EstateMap } from "@/lib/types";

/**
 * Horizontal distance between columns: a 240px box, and a gap wide enough for
 * an arrow's label and for backward arrows to run up and down beside the boxes.
 */
export const ESTATE_COLUMN_GAP = 440;
/** Vertical distance between boxes in one column. */
export const ESTATE_ROW_GAP = 76;
/** Boxes with no reach are stacked this many to a column, so a quiet estate is a grid. */
export const QUIET_ROWS = 8;
/** Sweeps, alternately rightwards and leftwards, that reorder columns to uncross arrows. */
const SWEEPS = 6;

type Point = { x: number; y: number };

/**
 * Where every box goes, and where an arrow that spans columns bends.
 *
 * `bends` holds, for an arrow `source|target` that crosses more than one gap,
 * the slot it passes through in each column between: a row kept empty for it,
 * so it crosses that column where no box is. Each point is the slot's top-left
 * corner, as a box's position is.
 */
export interface EstateLayout {
  at: Map<string, Point>;
  bends: Map<string, Point[]>;
}

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
 * Columns in the direction reach runs, with as few arrows running back as the
 * estate allows (DECISIONS.md §134).
 *
 * Laid out rather than simulated, for the reason the neighbourhood is (§101):
 * the same estate draws the same picture on every visit. It is a layered
 * drawing, in the usual four steps.
 *
 * 1. **Break the loops.** Reach between subscriptions loops, and a loop cannot
 *    be drawn left to right, so one arrow of each has to run back. The boxes
 *    are put in one order -- boxes nothing reaches first, boxes that reach
 *    nothing last, and in between the box whose arrows most run out -- and an
 *    arrow against that order is the one drawn back. Where a loop has to be
 *    entered somewhere, a box holding a way in goes first, because an attacker
 *    starts there.
 * 2. **One column past the furthest box that reaches it.** Every other arrow
 *    then runs strictly rightwards. A box nothing reaches is in the first
 *    column, so reach still reads from where it starts. A box holding a way in
 *    is no longer always there: when another box reaches it, it sits after
 *    that box, and its globe says it is a way in.
 * 3. **A slot for a long arrow.** An arrow crossing more than one gap gets a
 *    slot in every column between, and passes through it rather than over the
 *    boxes stacked there.
 * 4. **Uncross.** Sweeping right and left, each column is ordered by the
 *    average place of what it joins in the column beside, and the order with
 *    the fewest crossings is kept. Ties keep the fixed order.
 *
 * Boxes with no reach at all go last, stacked into a grid: they are part of
 * the estate and are shown, but they are not on the way anywhere.
 */
export function layoutEstate(map: EstateMap): EstateLayout {
  const boxes = [...map.boxes].sort(byBox);
  const rank = new Map(boxes.map((box, index) => [box.id, index]));

  // Every arrow once, between two boxes that are drawn.
  const arcs: [string, string][] = [];
  const seen = new Set<string>();
  for (const edge of map.edges) {
    const id = `${edge.source}|${edge.target}`;
    if (edge.source === edge.target || seen.has(id)) continue;
    if (!rank.has(edge.source) || !rank.has(edge.target)) continue;
    seen.add(id);
    arcs.push([edge.source, edge.target]);
  }
  arcs.sort(([a, b], [c, d]) => byCodeUnit(a, c) || byCodeUnit(b, d));

  const joined = new Set(arcs.flat());
  const quiet = boxes.filter((box) => !joined.has(box.id));
  const wired = boxes.filter((box) => joined.has(box.id));

  // 1. One order on the wired boxes; an arrow against it runs back.
  const order = acyclicOrder(wired, arcs, rank);
  const position = new Map(order.map((id, index) => [id, index]));
  const forward = arcs.filter(([source, target]) => position.get(source)! < position.get(target)!);
  const backward = arcs.filter(([source, target]) => position.get(source)! > position.get(target)!);

  // 2. One column past the furthest box that reaches it. An arrow drawn back
  // still holds its two ends apart, reversed, so it always runs leftwards.
  const column = new Map<string, number>();
  const before = new Map<string, string[]>();
  const hold = (earlier: string, later: string) =>
    before.set(later, [...(before.get(later) ?? []), earlier]);
  for (const [source, target] of forward) hold(source, target);
  for (const [source, target] of backward) hold(target, source);
  for (const id of order) {
    column.set(id, Math.max(0, ...(before.get(id) ?? []).map((from) => column.get(from)! + 1)));
  }

  // 3. A slot in every column a long forward arrow crosses. An arrow running
  // back goes round every box in a lane of its own instead (§132).
  const slots = new Map<string, string[]>();
  const segments: [string, string][] = [];
  for (const [source, target] of forward) {
    const id = `${source}|${target}`;
    const through: string[] = [];
    let from = source;
    for (let at = column.get(source)! + 1; at < column.get(target)!; at += 1) {
      const slot = `${id}#${at}`;
      column.set(slot, at);
      through.push(slot);
      segments.push([from, slot]);
      from = slot;
    }
    segments.push([from, target]);
    if (through.length > 0) slots.set(id, through);
  }

  // 4. Order each column to cross as few arrows as the sweeps can find.
  const width = order.length > 0 ? Math.max(...order.map((id) => column.get(id)!)) + 1 : 0;
  let layers: string[][] = Array.from({ length: width }, () => []);
  for (const id of order) layers[column.get(id)!].push(id);
  for (const through of slots.values()) {
    for (const slot of through) layers[column.get(slot)!].push(slot);
  }
  // Boxes in the fixed order to start; a slot beside its arrow's source.
  layers = layers.map((layer) =>
    [...layer].sort((a, b) => startingPlace(a, rank) - startingPlace(b, rank) || byCodeUnit(a, b)),
  );
  const leftOf = new Map<string, string[]>();
  const rightOf = new Map<string, string[]>();
  for (const [a, b] of segments) {
    rightOf.set(a, [...(rightOf.get(a) ?? []), b]);
    leftOf.set(b, [...(leftOf.get(b) ?? []), a]);
  }
  let best = layers.map((layer) => [...layer]);
  let fewest = crossings(best, rightOf);
  for (let sweep = 0; sweep < SWEEPS && fewest > 0; sweep += 1) {
    const rightwards = sweep % 2 === 0;
    for (let step = 1; step < width; step += 1) {
      const at = rightwards ? step : width - 1 - step;
      const beside = new Map(
        layers[rightwards ? at - 1 : at + 1].map((id, index) => [id, index]),
      );
      const joins = rightwards ? leftOf : rightOf;
      layers[at] = layers[at]
        .map((id, index) => {
          const places = (joins.get(id) ?? []).map((other) => beside.get(other)!);
          // Joined to nothing on that side, a box keeps where it is.
          const centre =
            places.length === 0 ? index : places.reduce((sum, p) => sum + p, 0) / places.length;
          return { id, centre, index };
        })
        .sort((a, b) => a.centre - b.centre || a.index - b.index)
        .map(({ id }) => id);
    }
    const count = crossings(layers, rightOf);
    if (count < fewest) {
      fewest = count;
      best = layers.map((layer) => [...layer]);
    }
  }

  const placed = new Map<string, Point>();
  best.forEach((layer, index) => {
    layer.forEach((id, row) => {
      placed.set(id, {
        x: index * ESTATE_COLUMN_GAP,
        y: (row - (layer.length - 1) / 2) * ESTATE_ROW_GAP,
      });
    });
  });

  const at = new Map<string, Point>();
  for (const box of wired) at.set(box.id, placed.get(box.id)!);
  quiet.forEach((box, index) => {
    const stack = Math.floor(index / QUIET_ROWS);
    const size = Math.min(QUIET_ROWS, quiet.length - stack * QUIET_ROWS);
    at.set(box.id, {
      x: (width + stack) * ESTATE_COLUMN_GAP,
      y: ((index % QUIET_ROWS) - (size - 1) / 2) * ESTATE_ROW_GAP,
    });
  });

  const bends = new Map<string, Point[]>();
  for (const [id, through] of slots) bends.set(id, through.map((slot) => placed.get(slot)!));
  return { at, bends };
}

/**
 * The wired boxes in one order that as few arrows as possible run against --
 * Eades, Lin and Smyth's greedy ordering. Boxes that reach nothing left are
 * taken off the end and boxes nothing left reaches off the front; when neither
 * is left, the next box is one holding a way in, then the one whose arrows
 * most run out, then the first in the fixed order.
 */
function acyclicOrder(
  wired: EstateBox[],
  arcs: [string, string][],
  rank: ReadonlyMap<string, number>,
): string[] {
  const out = new Map(wired.map((box) => [box.id, new Set<string>()]));
  const into = new Map(wired.map((box) => [box.id, new Set<string>()]));
  for (const [source, target] of arcs) {
    out.get(source)!.add(target);
    into.get(target)!.add(source);
  }
  const entry = new Map(wired.map((box) => [box.id, box.entry > 0]));
  const remaining = new Set(wired.map((box) => box.id));
  const inOrder = () => [...remaining].sort((a, b) => rank.get(a)! - rank.get(b)!);
  const remove = (id: string) => {
    remaining.delete(id);
    for (const next of out.get(id)!) into.get(next)!.delete(id);
    for (const prev of into.get(id)!) out.get(prev)!.delete(id);
  };

  const front: string[] = [];
  const end: string[] = [];
  while (remaining.size > 0) {
    let taken = true;
    while (taken) {
      taken = false;
      for (const id of inOrder().reverse()) {
        if (remaining.has(id) && out.get(id)!.size === 0) {
          end.unshift(id);
          remove(id);
          taken = true;
        }
      }
      for (const id of inOrder()) {
        if (remaining.has(id) && into.get(id)!.size === 0) {
          front.push(id);
          remove(id);
          taken = true;
        }
      }
    }
    if (remaining.size === 0) break;
    const lean = (id: string) => out.get(id)!.size - into.get(id)!.size;
    const [next] = inOrder().sort(
      (a, b) =>
        Number(entry.get(b)) - Number(entry.get(a)) ||
        lean(b) - lean(a) ||
        rank.get(a)! - rank.get(b)!,
    );
    front.push(next);
    remove(next);
  }
  return [...front, ...end];
}

/** Where a box or a slot starts before the sweeps: a slot just after its arrow's source. */
function startingPlace(id: string, rank: ReadonlyMap<string, number>): number {
  return rank.get(id) ?? (rank.get(id.slice(0, id.indexOf("|"))) ?? 0) + 0.5;
}

/** How many pairs of arrows cross, over every gap between two columns. */
function crossings(layers: string[][], rightOf: ReadonlyMap<string, string[]>): number {
  let total = 0;
  for (let at = 0; at < layers.length - 1; at += 1) {
    const place = new Map(layers[at + 1].map((id, index) => [id, index]));
    const ends: [number, number][] = [];
    layers[at].forEach((id, row) => {
      for (const next of rightOf.get(id) ?? []) {
        const to = place.get(next);
        if (to !== undefined) ends.push([row, to]);
      }
    });
    for (let i = 0; i < ends.length; i += 1) {
      for (let j = i + 1; j < ends.length; j += 1) {
        if ((ends[i][0] - ends[j][0]) * (ends[i][1] - ends[j][1]) < 0) total += 1;
      }
    }
  }
  return total;
}

function byCodeUnit(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
