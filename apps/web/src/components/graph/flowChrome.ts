import type { CSSProperties } from "react";

import type { Direction } from "./neighborhoodLayout";

/**
 * What every graph canvas shares: the tokens React Flow draws with and the
 * keys that move between boxes, with the zoom buttons in `ZoomButtons.tsx`.
 * One copy, so the asset neighbourhood and the estate map cannot drift into
 * two looks.
 */

// React Flow reads these variables for what it draws itself -- edges, the
// background -- so pointing them at the tokens is what makes dark mode work.
export const FLOW_TOKENS = {
  "--xy-edge-stroke": "var(--muted-foreground)",
  "--xy-background-color": "transparent",
  "--xy-background-pattern-color": "var(--border)",
} as CSSProperties;

export const FIT = { padding: 0.15 };

/** Handles exist for React Flow to route edges to; nobody can drag from them. */
export const HIDDEN_HANDLE: CSSProperties = { opacity: 0, pointerEvents: "none" };

/**
 * What is selected on a canvas: a box, or an arrow by its edge id. A click
 * selects, and opening is a second act, on every canvas (DECISIONS.md §133,
 * §134).
 */
export type GraphSelection = { kind: "box"; id: string } | { kind: "edge"; id: string };

/**
 * What a selection, or a preview under the pointer, keeps at full strength:
 * a box with its neighbours and the arrows between them, or an arrow with its
 * two ends. The rest fades rather than hides -- what is selected still has to
 * be read in its place, not on its own. Null when there is nothing to keep,
 * which draws everything as it is.
 */
export function kept(
  edges: readonly { id: string; source: string; target: string }[],
  on: GraphSelection | null,
): { boxes: Set<string>; edges: Set<string> } | null {
  if (!on) return null;
  const touching =
    on.kind === "box"
      ? edges.filter((edge) => edge.source === on.id || edge.target === on.id)
      : edges.filter((edge) => edge.id === on.id);
  if (on.kind === "edge" && touching.length === 0) return null;
  return {
    boxes: new Set([
      ...(on.kind === "box" ? [on.id] : []),
      ...touching.flatMap((edge) => [edge.source, edge.target]),
    ]),
    edges: new Set(touching.map((edge) => edge.id)),
  };
}

export const ARROWS: Record<string, Direction> = {
  ArrowLeft: "left",
  ArrowRight: "right",
  ArrowUp: "up",
  ArrowDown: "down",
};
