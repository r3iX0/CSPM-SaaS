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

export const ARROWS: Record<string, Direction> = {
  ArrowLeft: "left",
  ArrowRight: "right",
  ArrowUp: "up",
  ArrowDown: "down",
};
