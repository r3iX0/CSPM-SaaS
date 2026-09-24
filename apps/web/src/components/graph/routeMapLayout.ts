import type { RouteMap, RouteMapEdge } from "@/lib/types";
import { COLUMN_GAP, ROW_GAP } from "./neighborhoodLayout";
import { hopKey } from "./routeKeys";

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

/** The drawn size of a box. The canvas centres on these and labels are placed by them. */
export const BOX_WIDTH = 220;
export const BOX_HEIGHT = 44;

/** A line's label as the canvas would draw it, in the order it should win a tie for space. */
export interface LabelCandidate {
  id: string;
  text: string;
  from: { x: number; y: number };
  to: { x: number; y: number };
}

// The label's box, estimated rather than measured: React Flow draws labels
// after layout, and a measurement would make the drawing depend on the font
// that happened to load. 11px text runs a little over 6px a character, and the
// label's background pads it by 4px each side and 2px above and below.
const CHAR_WIDTH = 6.4;
const LABEL_PAD_X = 8;
const LABEL_HEIGHT = 18;
// Room kept between two labels, so a pair that only just misses still reads
// as two.
const LABEL_GAP = 4;

/**
 * Which labels to draw, so that no two print over each other.
 *
 * A line's label sits at the middle of its curve, which for a curve leaving a
 * box's right edge and entering another's left is the midpoint of the two
 * handles. Where several lines converge on one box, or a long line passes a
 * short one, those midpoints crowd, and labels drawn over each other read as
 * neither ("can gra can act over"). Candidates arrive most important first;
 * each is drawn only if its box clears every box already drawn. A label left
 * out is not lost: its line still carries its weight, and selecting either end
 * or tracing a route through it moves it to the front.
 */
export function placeLabels(candidates: LabelCandidate[]): Set<string> {
  const drawn: { x0: number; x1: number; y0: number; y1: number }[] = [];
  const kept = new Set<string>();
  for (const { id, text, from, to } of candidates) {
    if (!text) continue;
    const cx = (from.x + BOX_WIDTH + to.x) / 2;
    const cy = (from.y + to.y) / 2 + BOX_HEIGHT / 2;
    const half = (text.length * CHAR_WIDTH + LABEL_PAD_X) / 2 + LABEL_GAP / 2;
    const box = {
      x0: cx - half,
      x1: cx + half,
      y0: cy - LABEL_HEIGHT / 2 - LABEL_GAP / 2,
      y1: cy + LABEL_HEIGHT / 2 + LABEL_GAP / 2,
    };
    if (drawn.some((o) => box.x0 < o.x1 && o.x0 < box.x1 && box.y0 < o.y1 && o.y0 < box.y1)) {
      continue;
    }
    drawn.push(box);
    kept.add(id);
  }
  return kept;
}

/**
 * Which line speaks for each pair of boxes, and what it says.
 *
 * A role and the escalation it grants join one pair, drawn along one curve,
 * so two labels would print on the same spot. The pair speaks once, naming
 * both ("can act over · can grant roles over"), through the line that stands
 * highest by `standing` -- compared place by place, larger first -- and by
 * key when two stand level. Keyed by `source|target`.
 */
export function pairSpeakers(
  edges: RouteMapEdge[],
  standing: (edge: RouteMapEdge) => number[],
): Map<string, { key: string; text: string }> {
  const keyOf = (edge: RouteMapEdge) => hopKey(edge.source, edge.relationship, edge.target);
  const pairs = new Map<string, RouteMapEdge[]>();
  for (const edge of edges) {
    const pair = `${edge.source}|${edge.target}`;
    pairs.set(pair, [...(pairs.get(pair) ?? []), edge]);
  }
  const speakers = new Map<string, { key: string; text: string }>();
  for (const [pair, group] of pairs) {
    const first = [...group].sort((a, b) => {
      const [x, y] = [standing(a), standing(b)];
      const differs = x.findIndex((value, index) => value !== y[index]);
      return differs >= 0 ? y[differs] - x[differs] : byCodeUnit(keyOf(a), keyOf(b));
    })[0];
    speakers.set(pair, {
      key: keyOf(first),
      text: [...new Set([first, ...group].map((edge) => edge.label))].join(" · "),
    });
  }
  return speakers;
}
