import {
  createContext,
  createElement,
  useContext,
  useMemo,
  useState,
  type KeyboardEvent,
} from "react";
import {
  Background,
  BackgroundVariant,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
// The structural stylesheet only. `style.css` is React Flow's own theme, and
// the colours here come from the tokens in index.css like everything else.
import "@xyflow/react/dist/base.css";

import type { MappedRoute, RouteMap, RouteMapEdge, RouteMapNode } from "@/lib/types";
import { cn, levelStyle, resourceTypeLabel } from "@/lib/format";
import { FACTOR_ICONS, resourceTypeIcon } from "@/lib/icons";
import { DURATION, usePrefersReducedMotion } from "@/lib/motion";
import {
  ARROWS,
  FIT,
  FLOW_TOKENS,
  HIDDEN_HANDLE,
  kept,
  type GraphSelection,
} from "./flowChrome";
import { ZoomButtons } from "./ZoomButtons";
import { layoutRouteMap } from "./routeMapLayout";
import { stepFrom } from "./neighborhoodLayout";
import { hopKey } from "./routeKeys";

/** One hop, named by its ends and its relationship. */
export interface Hop {
  source: string;
  relationship: string;
  target: string;
}

type AssetFlowNode = Node<
  Pick<RouteMapNode, keyof RouteMapNode> & {
    /** Faded, because a route is traced and this box is not on it. */
    dimmed: boolean;
    /** Out of reach if the considered link were cut. The point of simulating. */
    closed: boolean;
    /** Which column it arrives with, so the drawing reads outside-in once. */
    arrival: number;
  },
  "asset"
>;

interface CanvasActions {
  active: string;
  setActive: (id: string) => void;
  pick: (id: string) => void;
  /** Previewed under the pointer or the keyboard: faded around, not picked. */
  preview: (id: string | null) => void;
  picked: string | null;
  /** The boxes a pick or a preview keeps, if any. */
  lit: ReadonlySet<string> | null;
}

const Actions = createContext<CanvasActions | null>(null);

function useActions(): CanvasActions {
  const actions = useContext(Actions);
  if (!actions) throw new Error("A route map node rendered outside RouteMapCanvas");
  return actions;
}

export interface RouteMapCanvasProps {
  map: RouteMap;
  /** The route being read: its hops drawn strong, everything else faded. */
  traced?: MappedRoute | null;
  /** A link somebody is considering cutting, and the routes that close with it. */
  simulated?: { link: Hop; closes: Set<string> } | null;
  /** The box picked, whose routes the rail is showing. */
  picked?: string | null;
  /** Called when a box is pressed: the rail shows what runs through it. */
  onPickNode: (id: string) => void;
  /** Called when the empty canvas is pressed: the pick is put down. */
  onClearPick?: () => void;
  /** Called when a link is pressed: the page asks what cutting it would do. */
  onPickLink: (edge: RouteMapEdge) => void;
}

/**
 * Every route in the estate, drawn.
 *
 * Its own module so it can be a lazy chunk — React Flow is the heaviest thing
 * this page loads and a tenant with no routes never needs it. The default
 * export is what `lazy()` loads.
 *
 * Nothing can be dragged, connected or selected. The positions come from
 * `layoutRouteMap`, and a box somebody had moved would be a picture of their
 * arrangement rather than of the estate. What a box does is ask a question:
 * pressing one shows the routes through it, pressing a link asks what cutting
 * it would close. A picked box is ringed and kept with its neighbours while
 * the rest fades, as a selection is on the estate map and the neighbourhood,
 * and with nothing picked the box or line under the pointer previews the same
 * fading (DECISIONS.md §134).
 *
 * One tab stop, then arrow keys — the way the neighbourhood canvas is reached,
 * because tabbing through eighty boxes to get to the list beside them would
 * make the canvas a wall.
 */
export default function RouteMapCanvas(props: RouteMapCanvasProps) {
  return (
    <ReactFlowProvider>
      <Canvas {...props} />
    </ReactFlowProvider>
  );
}

function Canvas({
  map,
  traced = null,
  simulated = null,
  picked = null,
  onPickNode,
  onPickLink,
  onClearPick,
}: RouteMapCanvasProps) {
  const reduced = usePrefersReducedMotion();
  const { nodes, edges: drawn, at } = useMemo(
    () => toFlow(map, traced, simulated, reduced),
    [map, traced, simulated, reduced],
  );
  // A traced route or a simulated cut draws its own fading, and wins.
  const [previewed, setPreviewed] = useState<GraphSelection | null>(null);
  const pickedOn = useMemo<GraphSelection | null>(
    () => (picked && at.has(picked) ? { kind: "box", id: picked } : null),
    [picked, at],
  );
  const on = traced || simulated ? null : (pickedOn ?? previewed);
  const around = useMemo(() => kept(drawn, on), [drawn, on]);
  const edges = useMemo(
    () =>
      around
        ? drawn.map((edge) =>
            around.edges.has(edge.id)
              ? { ...edge, zIndex: 1, style: { ...edge.style, opacity: 1 } }
              : {
                  ...edge,
                  animated: false,
                  style: { ...edge.style, opacity: 0.12 },
                  labelStyle: { ...edge.labelStyle, opacity: 0.15 },
                },
          )
        : drawn,
    [drawn, around],
  );
  const [active, setActive] = useState(() => map.nodes[0]?.id ?? "");
  const flow = useReactFlow();
  const marked = at.has(active) ? active : (map.nodes[0]?.id ?? "");

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const direction = ARROWS[event.key];
    if (!direction || event.altKey || event.ctrlKey || event.metaKey) return;
    event.preventDefault();
    const next = stepFrom(at, marked, direction);
    if (!next) return;
    setActive(next);
    document
      .querySelector<HTMLElement>(`[data-graph-node="${CSS.escape(next)}"]`)
      ?.focus({ preventScroll: true });
    const to = at.get(next)!;
    // Brought into view rather than left for the reader to pan to: a mark that
    // moves off-screen is a mark nobody can see.
    void flow.setCenter(to.x + BOX_WIDTH / 2, to.y + BOX_HEIGHT / 2, {
      zoom: flow.getZoom(),
      duration: reduced ? 0 : DURATION.quick,
    });
  }

  return (
    <Actions.Provider
      value={{
        active: marked,
        setActive,
        pick: onPickNode,
        preview: (id) => setPreviewed(id ? { kind: "box", id } : null),
        picked,
        lit: around?.boxes ?? null,
      }}
    >
      <div className="size-full" onKeyDown={onKeyDown}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={NODE_TYPES}
          style={FLOW_TOKENS}
          fitView
          fitViewOptions={FIT}
          minZoom={0.2}
          maxZoom={1.5}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable={false}
          nodesFocusable={false}
          edgesFocusable={false}
          onEdgeClick={(_, edge) => {
            const found = map.edges.find((candidate) => keyOf(candidate) === edge.id);
            if (found) onPickLink(found);
          }}
          onEdgeMouseEnter={(_, edge) => setPreviewed({ kind: "edge", id: edge.id })}
          onEdgeMouseLeave={() => setPreviewed(null)}
          onPaneClick={() => onClearPick?.()}
          // The canvas sits in a scrolling page. A wheel that zoomed the graph
          // would trap somebody scrolling past it; zoom is on the buttons.
          zoomOnScroll={false}
          preventScrolling={false}
        >
          <Background
            variant={BackgroundVariant.Dots}
            gap={20}
            size={1}
            color="var(--border)"
          />
          <ZoomButtons />
        </ReactFlow>
      </div>
    </Actions.Provider>
  );
}

/** The drawn size of a box, for centring the view on one. */
const BOX_WIDTH = 220;
const BOX_HEIGHT = 44;

const keyOf = (edge: RouteMapEdge) =>
  hopKey(edge.source, edge.relationship, edge.target);

const hopOf = (hop: Hop) => hopKey(hop.source, hop.relationship, hop.target);

function toFlow(
  map: RouteMap,
  traced: MappedRoute | null,
  simulated: { link: Hop; closes: Set<string> } | null,
  reduced: boolean,
): { nodes: Node[]; edges: Edge[]; at: Map<string, { x: number; y: number }> } {
  const at = layoutRouteMap(map);
  const origin = { x: 0, y: 0 };

  const tracedHops = traced
    ? new Set(
        traced.steps.map((step) =>
          hopKey(step.source_id, step.relationship, step.target_id),
        ),
      )
    : null;
  const tracedNodes = traced
    ? new Set(traced.steps.flatMap((step) => [step.source_id, step.target_id]))
    : null;
  const cutHop =
    simulated?.link ??
    (traced?.cheapest_break
      ? {
          source: traced.cheapest_break.source_id,
          relationship: traced.cheapest_break.relationship,
          target: traced.cheapest_break.target_id,
        }
      : null);
  const cut = cutHop ? hopOf(cutHop) : null;

  // What the considered cut would put out of reach. Worked from the routes the
  // API said would close rather than by re-walking the drawing: the number in
  // the bar and the boxes that grey out have to be one claim.
  const closedNodes = new Set<string>();
  if (simulated) {
    const surviving = new Set<string>();
    for (const route of map.routes) {
      if (simulated.closes.has(route.key)) continue;
      surviving.add(route.entry.id);
      for (const step of route.steps) surviving.add(step.target_id);
    }
    for (const route of map.routes) {
      if (!simulated.closes.has(route.key)) continue;
      for (const id of [route.entry.id, ...route.steps.map((step) => step.target_id)]) {
        if (!surviving.has(id)) closedNodes.add(id);
      }
    }
  }

  const nodes: Node[] = map.nodes.map(
    (node): AssetFlowNode => ({
      id: node.id,
      type: "asset",
      position: at.get(node.id) ?? origin,
      data: {
        ...node,
        dimmed: tracedNodes !== null && !tracedNodes.has(node.id),
        closed: closedNodes.has(node.id),
        // Columns arrive left to right, so the first thing read is where an
        // attacker starts. Off entirely for a reader who asked for less motion.
        arrival: reduced ? 0 : node.column,
      },
    }),
  );

  const edges: Edge[] = map.edges.map((edge) => {
    const key = keyOf(edge);
    const onTraced = tracedHops?.has(key) ?? false;
    const isCut = key === cut;
    // Weighted by what it closes, never by what it sits on. The whole point of
    // carrying both numbers is that "on forty routes" and "closes forty
    // routes" are different claims, and the drawing must not blur them.
    const weight = Math.min(1 + edge.severs / 4, 4);

    let stroke = edge.severs > 0 ? "var(--foreground)" : "var(--muted-foreground)";
    let width = edge.severs > 0 ? weight : 1;
    let dash: string | undefined;
    let opacity = edge.severs > 0 ? 1 : 0.55;
    let label = edge.severs > 0 ? `${edge.label} · closes ${edge.severs}` : edge.label;
    let labelFill = "var(--muted-foreground)";

    if (isCut) {
      // Drawn the way `AttackPathRoute` draws a severed link: dashed, in the
      // colour that means "this makes it better".
      stroke = "var(--sev-ok)";
      width = Math.max(width, 2);
      dash = "5 4";
      label = `${edge.label} · cut`;
      labelFill = "var(--sev-ok)";
      opacity = 1;
    } else if (tracedHops) {
      if (onTraced) {
        stroke = "var(--foreground)";
        width = Math.max(width, 2);
        labelFill = "var(--foreground)";
        opacity = 1;
      } else {
        opacity = 0.12;
        label = "";
      }
    } else if (simulated && closedNodes.has(edge.target)) {
      opacity = 0.2;
    }

    return {
      id: key,
      source: edge.source,
      target: edge.target,
      label: label || undefined,
      // Marching dashes along the route being read, in the direction reach
      // runs. The one animation here that says something the static picture
      // cannot — and it is off for a reader who asked for less motion.
      animated: !reduced && onTraced && !isCut,
      labelStyle: { fill: labelFill, fontSize: 11 },
      labelBgStyle: { fill: "var(--card)" },
      labelBgPadding: [4, 2] as [number, number],
      style: { stroke, strokeWidth: width, strokeDasharray: dash, opacity },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: stroke,
        width: 14,
        height: 14,
      },
    };
  });

  return { nodes, edges, at };
}

const LEVEL_TEXT: Record<string, string> = {
  CRITICAL: "text-critical",
  HIGH: "text-high",
};

function AssetNode({ id, data }: NodeProps<AssetFlowNode>) {
  const actions = useActions();
  const Exposure = FACTOR_ICONS.exposure;
  const Sensitive = FACTOR_ICONS.dataSensitivity;

  return (
    <>
      <Handle
        type="target"
        position={Position.Left}
        isConnectable={false}
        style={HIDDEN_HANDLE}
      />
      <button
        type="button"
        data-graph-node={id}
        tabIndex={actions.active === id ? 0 : -1}
        aria-pressed={actions.picked === id}
        onFocus={() => {
          actions.setActive(id);
          actions.preview(id);
        }}
        onBlur={() => actions.preview(null)}
        onPointerEnter={() => actions.preview(id)}
        onPointerLeave={() => actions.preview(null)}
        onClick={() => actions.pick(id)}
        style={{ animationDelay: `${Math.min(data.arrival, 6) * 60}ms` }}
        className={cn(
          "nopan flex w-[220px] cursor-pointer items-center gap-2 rounded-lg border bg-card px-2 py-1.5 text-left",
          "transition-[opacity,filter] hover:bg-muted/60 focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
          data.arrival > 0 && "animate-[cg-rise_180ms_ease-out_both]",
          data.entry
            ? "border-critical-border"
            : data.sensitive
              ? "border-high-border"
              : "border-border",
          (data.dimmed || (actions.lit && !actions.lit.has(id))) && "opacity-30",
          actions.picked === id && "ring-2 ring-foreground/70 ring-offset-2 ring-offset-card",
          // Out of reach once the considered link is gone. Desaturated rather
          // than hidden: the asset is still in the estate, it is the route to
          // it that would be over.
          data.closed && "opacity-40 grayscale",
        )}
      >
        <span className="flex size-7 shrink-0 items-center justify-center rounded-md border border-border bg-background text-muted-foreground">
          {createElement(resourceTypeIcon(data.resource_type), {
            className: "size-3.5",
            "aria-hidden": true,
          })}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-xs font-medium text-foreground">
            {data.name}
          </span>
          <span className="block truncate text-[11px] text-muted-foreground">
            {resourceTypeLabel(data.resource_type)}
          </span>
        </span>
        <span className="flex shrink-0 items-center gap-1">
          {data.entry && (
            <span title={`Internet exposure ${data.public_exposure.toLowerCase()}`}>
              <Exposure
                className={cn("size-3.5", LEVEL_TEXT[data.public_exposure])}
                aria-hidden
              />
              <span className="sr-only">, reachable from the internet</span>
            </span>
          )}
          {data.sensitive && (
            <span title={`Data sensitivity ${data.data_sensitivity.toLowerCase()}`}>
              <Sensitive
                className={cn("size-3.5", LEVEL_TEXT[data.data_sensitivity])}
                aria-hidden
              />
              <span className="sr-only">, holds sensitive data</span>
            </span>
          )}
          {data.findings.open > 0 && (
            <span
              title={`${data.findings.open} open finding${data.findings.open === 1 ? "" : "s"}`}
              className={cn(
                "rounded border px-1 text-[10px] leading-4 font-medium tabular-nums",
                levelStyle(data.findings.worst ?? "UNKNOWN"),
              )}
            >
              {data.findings.open}
              <span className="sr-only">
                {" "}
                open finding{data.findings.open === 1 ? "" : "s"}
              </span>
            </span>
          )}
        </span>
        <span className="sr-only">
          . On {data.routes} route{data.routes === 1 ? "" : "s"}. Show them
        </span>
      </button>
      <Handle
        type="source"
        position={Position.Right}
        isConnectable={false}
        style={HIDDEN_HANDLE}
      />
    </>
  );
}

// Module-level: React Flow re-mounts every node when this object's identity
// changes, and warns when a new one arrives on each render.
const NODE_TYPES = { asset: AssetNode };
