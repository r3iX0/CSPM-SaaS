import { useMemo } from "react";
import { Link } from "react-router-dom";

import type { ExposureMapData, ExposureNode } from "@/lib/types";
import { useT } from "@/i18n";
import { cn } from "@/lib/format";

const COLUMN = 132;
const ROW = 58;
const MARGIN = 28;

/**
 * What the internet touches, and what that touches.
 *
 * This is the panel that replaces the overview's attack-path box, which was
 * empty for most tenants and could not help being: a route needs something
 * classified as sensitive at the far end, and a new customer has classified
 * nothing (docs/UI_REDESIGN.md §4.1). The map is drawn from the same graph and
 * always has something to say, because "nothing is exposed" is itself an
 * answer and reads as one here.
 *
 * **It is not an attack path and must not imply one.** An edge says one asset
 * can act on another; whether that reaches anything worth taking is the
 * attack-paths page's question. So the nodes carry exposure and sensitivity —
 * the two facts the graph actually knows — and nothing here is scored.
 */
export function ExposureMap({
  map,
  omitted = 0,
  className,
}: {
  map: ExposureMapData | undefined;
  /** Nodes the estate has and this drawing left out. Never silent. */
  omitted?: number;
  className?: string;
}) {
  const t = useT();
  const laid = useMemo(() => layout(map), [map]);

  // Defensive about the shape, not only about the emptiness: a panel that
  // throws on an unexpected payload takes the score down with it, and the
  // score is the one thing on this page that must render (DECISIONS.md §66).
  if (!map?.nodes?.length) {
    // A framed placeholder rather than a loose line of text: this panel holds
    // the larger half of the hero, and a sentence pinned to the top of it left
    // the rest of the card looking like a drawing that failed.
    return (
      <div
        className={cn(
          "flex min-h-40 flex-1 items-center justify-center rounded-lg border border-dashed px-6 py-8",
          className,
        )}
      >
        <p className="max-w-xs text-center text-[13px] text-muted-foreground">
          {t.dashboard.nothingExposed}
        </p>
      </div>
    );
  }

  const width = laid.columns * COLUMN + MARGIN * 2;
  const height = laid.rows * ROW + MARGIN * 2;

  return (
    <div className={cn("flex flex-col gap-2", className)}>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="h-auto w-full min-w-[420px]"
          role="img"
          aria-label={describe(map.nodes)}
        >
          {(map.edges ?? []).map((edge) => {
            const from = laid.at[edge.source];
            const to = laid.at[edge.target];
            if (!from || !to) return null;
            return (
              <line
                key={`${edge.source}-${edge.relationship}-${edge.target}`}
                x1={from.x}
                y1={from.y}
                x2={to.x}
                y2={to.y}
                stroke="var(--color-border)"
                strokeWidth={1}
                strokeDasharray={edge.relationship === "contains" ? "3 3" : undefined}
              />
            );
          })}

          {map.nodes.map((node) => {
            const at = laid.at[node.id];
            if (!at) return null;
            return (
              <g key={node.id}>
                <circle
                  cx={at.x}
                  cy={at.y}
                  r={13}
                  fill="var(--color-card)"
                  stroke={ringOf(node)}
                  strokeWidth={1.5}
                  strokeDasharray={undeclared(node) ? "3 3" : undefined}
                />
                <text
                  x={at.x}
                  y={at.y + 28}
                  textAnchor="middle"
                  className="fill-foreground font-mono"
                  style={{ fontSize: 9 }}
                >
                  {clip(node.name)}
                </text>
                <text
                  x={at.x}
                  y={at.y + 39}
                  textAnchor="middle"
                  className="fill-current text-meta-foreground"
                  style={{ fontSize: 8 }}
                >
                  {qualify(node, t)}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
        <span className="text-meta-foreground">
          {/* Said rather than truncated silently. */}
          {omitted > 0
            ? t.dashboard.mapOmitted.replace("{count}", String(omitted))
            : ""}
        </span>
        <Link
          to="/assets"
          className="shrink-0 font-medium text-foreground underline underline-offset-2"
        >
          {t.dashboard.openGraph}
        </Link>
      </div>
    </div>
  );
}

/**
 * Columns by distance from the internet, rows spread within a column.
 *
 * Not a force layout: the reader's question is "how far in does this go", and
 * distance from the exposed end is the only ordering that answers it. A force
 * layout would place the same graph differently on every render, which makes a
 * diagram somebody is comparing against last week's useless.
 */
function layout(map: ExposureMapData | undefined) {
  const at: Record<string, { x: number; y: number }> = {};
  if (!map?.nodes?.length) return { at, columns: 1, rows: 1 };

  const depth: Record<string, number> = {};
  for (const node of map.nodes) if (node.is_entry) depth[node.id] = 0;

  // Repeated relaxation rather than a traversal: the edge list is small and
  // may arrive in any order, and a node reachable two ways takes the shorter.
  for (let pass = 0; pass < map.nodes.length; pass += 1) {
    let moved = false;
    for (const edge of map.edges ?? []) {
      const from = depth[edge.source];
      if (from === undefined) continue;
      if (depth[edge.target] === undefined || depth[edge.target] > from + 1) {
        depth[edge.target] = from + 1;
        moved = true;
      }
    }
    if (!moved) break;
  }

  // A node nothing points at sits in the first column with the entries.
  const columns: Record<number, ExposureNode[]> = {};
  for (const node of map.nodes) {
    const column = depth[node.id] ?? 0;
    (columns[column] ??= []).push(node);
  }

  const indexes = Object.keys(columns).map(Number).sort((a, b) => a - b);
  const rows = Math.max(...indexes.map((index) => columns[index].length));

  indexes.forEach((index, position) => {
    const nodes = columns[index];
    nodes.forEach((node, row) => {
      at[node.id] = {
        x: MARGIN + position * COLUMN + COLUMN / 2,
        // Centred within the tallest column, so a single node sits opposite
        // the middle of a stack rather than at its top.
        y: MARGIN + ((rows - nodes.length) / 2 + row) * ROW + ROW / 2,
      };
    });
  });

  return { at, columns: indexes.length, rows };
}

/** The colour a node's ring carries, and it is never a score. */
function ringOf(node: ExposureNode): string {
  if (node.is_entry) return "var(--sev-critical)";
  if (node.data_sensitivity === "HIGH" || node.data_sensitivity === "CRITICAL")
    return "var(--sev-high)";
  if (undeclared(node)) return "var(--sev-unknown)";
  return "var(--color-border)";
}

/** Nothing has been said about what this holds. Dashed, as everywhere else. */
const undeclared = (node: ExposureNode) =>
  node.data_sensitivity === "UNKNOWN" && node.criticality === "UNKNOWN";

function qualify(node: ExposureNode, t: ReturnType<typeof useT>): string {
  if (node.is_entry) return t.dashboard.mapReachable;
  if (node.data_sensitivity === "HIGH" || node.data_sensitivity === "CRITICAL")
    return t.dashboard.mapSensitive;
  if (undeclared(node)) return t.dashboard.mapUnclassified;
  return node.resource_type.replace(/_/g, " ").toLowerCase();
}

const clip = (name: string) => (name.length > 18 ? `${name.slice(0, 17)}…` : name);

const describe = (nodes: ExposureNode[]) =>
  `Exposure map: ${nodes.length} assets, ${nodes.filter((n) => n.is_entry).length} reachable from the internet`;
