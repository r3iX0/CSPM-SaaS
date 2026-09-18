import { createElement, useMemo, type CSSProperties } from "react";
import { Link } from "react-router-dom";
import {
  Background,
  BackgroundVariant,
  Handle,
  MarkerType,
  Panel,
  Position,
  ReactFlow,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
// The structural stylesheet only. `style.css` is React Flow's own theme, and
// the colours here come from the tokens in index.css like everything else.
import "@xyflow/react/dist/base.css";
import { MaximizeIcon, MinusIcon, PlusIcon } from "lucide-react";

import type {
  AttackPath,
  Neighborhood,
  NeighborhoodGroup,
  NeighborhoodNode,
} from "@/lib/types";
import { cn, levelStyle, resourceTypeLabel } from "@/lib/format";
import { FACTOR_ICONS, resourceTypeIcon } from "@/lib/icons";
import { Button } from "@/components/ui/button";
import { layoutNeighborhood } from "./neighborhoodLayout";
import { hopKey } from "./routeKeys";

// `Pick` to a mapped type: React Flow wants node data to be a record, and an
// interface is never assignable to one, however plain its fields are.
type AssetFlowNode = Node<
  Pick<NeighborhoodNode, keyof NeighborhoodNode> & { focus: boolean; dimmed: boolean },
  "asset"
>;
type GroupFlowNode = Node<
  Pick<NeighborhoodGroup, keyof NeighborhoodGroup> & { dimmed: boolean },
  "group"
>;

/**
 * The canvas behind the graph view: React Flow, drawn with CloudGuard's tokens.
 *
 * Its own module so it can be a lazy chunk -- React Flow is the heaviest thing
 * on the asset page and most visits never open the graph. The default export is
 * what `lazy()` loads.
 *
 * Read-only on purpose. Nothing can be dragged, connected or selected: the
 * positions come from `layoutNeighborhood`, and a box a person had moved would
 * be a picture of their arrangement rather than of the estate.
 */
export default function NeighborhoodCanvas({
  neighborhood,
  traced = null,
}: {
  neighborhood: Neighborhood;
  /** A route to trace: its hops drawn strong, its cut marked, the rest faded. */
  traced?: AttackPath | null;
}) {
  const { nodes, edges } = useMemo(
    () => toFlow(neighborhood, traced),
    [neighborhood, traced],
  );

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={NODE_TYPES}
      style={FLOW_TOKENS}
      fitView
      fitViewOptions={FIT}
      minZoom={0.25}
      maxZoom={1.5}
      nodesDraggable={false}
      nodesConnectable={false}
      elementsSelectable={false}
      // The canvas sits in a scrolling page. A wheel that zoomed the graph
      // would trap somebody scrolling past it; zoom is on the buttons and on a
      // pinch instead.
      zoomOnScroll={false}
      preventScrolling={false}
    >
      <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="var(--border)" />
      <ZoomButtons />
    </ReactFlow>
  );
}

const FIT = { padding: 0.15 };

function ZoomButtons() {
  const flow = useReactFlow();
  return (
    <Panel position="top-right" className="flex gap-1">
      <Button variant="outline" size="icon-sm" onClick={() => flow.zoomIn()} aria-label="Zoom in">
        <PlusIcon />
      </Button>
      <Button variant="outline" size="icon-sm" onClick={() => flow.zoomOut()} aria-label="Zoom out">
        <MinusIcon />
      </Button>
      <Button
        variant="outline"
        size="icon-sm"
        onClick={() => flow.fitView(FIT)}
        aria-label="Fit the graph to the frame"
      >
        <MaximizeIcon />
      </Button>
    </Panel>
  );
}

// React Flow reads these variables for what it draws itself -- edges, the
// background -- so pointing them at the tokens is what makes dark mode work.
const FLOW_TOKENS = {
  "--xy-edge-stroke": "var(--muted-foreground)",
  "--xy-background-color": "transparent",
  "--xy-background-pattern-color": "var(--border)",
} as CSSProperties;

function toFlow(
  neighborhood: Neighborhood,
  traced: AttackPath | null,
): { nodes: Node[]; edges: Edge[] } {
  const at = layoutNeighborhood(neighborhood);
  const origin = { x: 0, y: 0 };

  // Every hop on any route through the focus, so that with nothing traced the
  // routes still stand out from reach that leads nowhere sensitive.
  const onAnyRoute = new Set(
    neighborhood.routes.flatMap((route) =>
      route.steps.map((step) => hopKey(step.source_id, step.relationship, step.target_id)),
    ),
  );
  const tracedHops = traced
    ? new Set(traced.steps.map((step) => hopKey(step.source_id, step.relationship, step.target_id)))
    : null;
  const tracedNodes = traced
    ? new Set(traced.steps.flatMap((step) => [step.source_id, step.target_id]))
    : null;
  const cut = traced?.cheapest_break
    ? hopKey(
        traced.cheapest_break.source_id,
        traced.cheapest_break.relationship,
        traced.cheapest_break.target_id,
      )
    : null;

  const nodes: Node[] = [
    ...neighborhood.nodes.map(
      (node): AssetFlowNode => ({
        id: node.id,
        type: "asset",
        position: at.get(node.id) ?? origin,
        data: {
          ...node,
          focus: node.id === neighborhood.focus,
          dimmed: tracedNodes !== null && !tracedNodes.has(node.id),
        },
      }),
    ),
    ...neighborhood.groups.map(
      (group): GroupFlowNode => ({
        id: group.id,
        type: "group",
        position: at.get(group.id) ?? origin,
        // Faded while a route is traced. A route can pass through a folded
        // member, and the canvas cannot say which; the line drawn under it in
        // the card is the whole route, and says so when part is off-canvas.
        data: { ...group, dimmed: tracedNodes !== null },
      }),
    ),
  ];

  const edges: Edge[] = neighborhood.edges.map((edge) => {
    const key = hopKey(edge.source, edge.relationship, edge.target);
    // Containment is where something lives; the other hops are what an
    // identity is allowed to do. Both are reach, but only the second kind is
    // ever the link somebody cuts, so it is the one drawn strong and named.
    const structural = edge.relationship === "contains";
    const base = {
      id: key,
      source: edge.source,
      target: edge.target,
      labelStyle: { fill: "var(--muted-foreground)", fontSize: 11 },
      labelBgStyle: { fill: "var(--card)" },
      labelBgPadding: [4, 2] as [number, number],
    };

    let stroke = structural ? "var(--border)" : "var(--muted-foreground)";
    let width = structural ? 1 : 1.5;
    let label: string | undefined = structural ? undefined : edge.label;
    let dash: string | undefined;
    let opacity = 1;
    let labelFill = "var(--muted-foreground)";

    if (tracedHops) {
      if (key === cut) {
        // Drawn the way `AttackPathRoute` draws a severed link: dashed, in the
        // colour that means "this makes it better".
        stroke = "var(--sev-ok)";
        width = 2;
        dash = "5 4";
        label = `${edge.label} · cut here`;
        labelFill = "var(--sev-ok)";
      } else if (tracedHops.has(key)) {
        stroke = "var(--foreground)";
        width = 2;
        label = edge.label;
        labelFill = "var(--foreground)";
      } else {
        opacity = 0.15;
        label = undefined;
      }
    } else if (onAnyRoute.has(key)) {
      stroke = "var(--foreground)";
      width = structural ? 1.25 : 1.75;
    }

    return {
      ...base,
      label,
      labelStyle: { ...base.labelStyle, fill: labelFill },
      style: { stroke, strokeWidth: width, strokeDasharray: dash, opacity },
      markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 14, height: 14 },
    };
  });

  return { nodes, edges };
}

const HIDDEN_HANDLE: CSSProperties = { opacity: 0, pointerEvents: "none" };

function AssetNode({ data }: NodeProps<AssetFlowNode>) {
  const body = (
    <>
      <span className="flex size-7 shrink-0 items-center justify-center rounded-md border border-border bg-background text-muted-foreground">
        {createElement(resourceTypeIcon(data.resource_type), {
          className: "size-3.5",
          "aria-hidden": true,
        })}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-xs font-medium text-foreground">{data.name}</span>
        <span className="block truncate text-[11px] text-muted-foreground">
          {resourceTypeLabel(data.resource_type)}
        </span>
      </span>
      <Markers node={data} />
    </>
  );
  const frame = cn(
    "flex w-[220px] items-center gap-2 rounded-lg border bg-card px-2 py-1.5 text-left transition-opacity",
    data.focus ? "border-foreground shadow-sm ring-3 ring-ring/20" : "border-border",
    data.dimmed && "opacity-30",
  );

  return (
    <>
      <Handle type="target" position={Position.Left} isConnectable={false} style={HIDDEN_HANDLE} />
      {data.focus || !data.asset_id ? (
        <div className={frame} aria-current={data.focus ? "true" : undefined}>
          {body}
        </div>
      ) : (
        // `nopan` so a click opens the asset rather than starting a drag of
        // the canvas underneath it.
        <Link
          to={`/assets/${data.asset_id}`}
          className={cn(
            frame,
            "nopan transition-colors hover:bg-muted/60 focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
          )}
        >
          {body}
        </Link>
      )}
      <Handle type="source" position={Position.Right} isConnectable={false} style={HIDDEN_HANDLE} />
    </>
  );
}

const LEVEL_TEXT: Record<string, string> = {
  CRITICAL: "text-critical",
  HIGH: "text-high",
};

/**
 * What makes a box matter on a route, beside its name.
 *
 * A globe for somewhere a route can start and a cylinder for somewhere it can
 * end, coloured by how exposed or how sensitive -- the same glyphs the asset
 * page uses for those factors. Exposure CloudGuard could not work out gets a
 * muted globe of its own rather than none, because "not a way in" and "do not
 * know" are different answers. Each carries its meaning as text for a screen
 * reader, which is also what a link's name is built from.
 */
function Markers({ node }: { node: AssetFlowNode["data"] }) {
  const Exposure = FACTOR_ICONS.exposure;
  const Sensitive = FACTOR_ICONS.dataSensitivity;
  const { open, worst } = node.findings;

  return (
    <span className="flex shrink-0 items-center gap-1">
      {node.entry && (
        <span title={`Internet exposure ${node.public_exposure.toLowerCase()}`}>
          <Exposure className={cn("size-3.5", LEVEL_TEXT[node.public_exposure])} aria-hidden />
          <span className="sr-only">, reachable from the internet</span>
        </span>
      )}
      {node.public_exposure === "UNKNOWN" && (
        <span title="Internet exposure unknown">
          <Exposure className="size-3.5 text-unknown opacity-60" aria-hidden />
          <span className="sr-only">, internet exposure unknown</span>
        </span>
      )}
      {node.sensitive && (
        <span title={`Data sensitivity ${node.data_sensitivity.toLowerCase()}`}>
          <Sensitive className={cn("size-3.5", LEVEL_TEXT[node.data_sensitivity])} aria-hidden />
          <span className="sr-only">, holds sensitive data</span>
        </span>
      )}
      {open > 0 && (
        <span
          title={`${open} open finding${open === 1 ? "" : "s"}, worst ${worst?.toLowerCase()}`}
          className={cn(
            "rounded border px-1 text-[10px] leading-4 font-medium tabular-nums",
            levelStyle(worst ?? "UNKNOWN"),
          )}
        >
          {open}
          <span className="sr-only"> open finding{open === 1 ? "" : "s"}</span>
        </span>
      )}
    </span>
  );
}

/**
 * Neighbours that were counted rather than drawn. Dashed, the way every gap in
 * what CloudGuard shows is drawn, so it cannot pass for one more asset.
 */
function GroupNode({ data }: NodeProps<GroupFlowNode>) {
  const kinds = Object.entries(data.by_type).slice(0, 2);
  return (
    <>
      <Handle type="target" position={Position.Left} isConnectable={false} style={HIDDEN_HANDLE} />
      <div
        className={cn(
          "w-[220px] rounded-lg border border-dashed border-border bg-background px-2 py-1.5 transition-opacity",
          data.dimmed && "opacity-30",
        )}
      >
        <span className="block text-xs font-medium text-foreground tabular-nums">
          {data.count} more
        </span>
        <span className="block truncate text-[11px] text-muted-foreground">
          {kinds.map(([type, count]) => `${resourceTypeLabel(type)} · ${count}`).join(", ")}
          {Object.keys(data.by_type).length > kinds.length && ", …"}
        </span>
      </div>
      <Handle type="source" position={Position.Right} isConnectable={false} style={HIDDEN_HANDLE} />
    </>
  );
}

// Module-level: React Flow re-mounts every node when this object's identity
// changes, and it warns when a new one arrives on each render.
const NODE_TYPES = { asset: AssetNode, group: GroupNode };
