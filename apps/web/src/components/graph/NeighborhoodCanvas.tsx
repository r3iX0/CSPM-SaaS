import {
  createContext,
  createElement,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
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

import type {
  AttackPath,
  Neighborhood,
  NeighborhoodGroup,
  NeighborhoodNode,
} from "@/lib/types";
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
import { layoutNeighborhood, stepFrom } from "./neighborhoodLayout";
import { hopKey } from "./routeKeys";

// `Pick` to a mapped type: React Flow wants node data to be a record, and an
// interface is never assignable to one, however plain its fields are.
/** One hop, named by its ends and its relationship. */
type Hop = { source_id: string; relationship: string; target_id: string };

type AssetFlowNode = Node<
  Pick<NeighborhoodNode, keyof NeighborhoodNode> & { focus: boolean; dimmed: boolean },
  "asset"
>;
type GroupFlowNode = Node<
  Pick<NeighborhoodGroup, keyof NeighborhoodGroup> & { dimmed: boolean },
  "group"
>;

/**
 * What a box can do, handed to the nodes through context rather than through
 * each node's data, so moving the keyboard mark does not rebuild every node.
 */
interface CanvasActions {
  /** The box that holds the single tab stop into the canvas. */
  active: string;
  setActive: (id: string) => void;
  /** Select a box: the panel beside the canvas says what it is. */
  select: (id: string) => void;
  /** Open a box: re-centre on it, open its page, or draw a fold's members. */
  open: (id: string) => void;
  /** Previewed under the pointer or the keyboard: faded around, not selected. */
  preview: (id: string | null) => void;
  selected: string | null;
  /** The boxes a selection or a preview keeps, if any. */
  lit: ReadonlySet<string> | null;
  /** The asset whose page this is: its box is where the reader already is. */
  pageAsset: string;
}

const Actions = createContext<CanvasActions | null>(null);

function useActions(): CanvasActions {
  const actions = useContext(Actions);
  if (!actions) throw new Error("A graph node rendered outside NeighborhoodCanvas");
  return actions;
}

/**
 * The canvas behind the graph view: React Flow, drawn with CloudGuard's tokens.
 *
 * Its own module so it can be a lazy chunk -- React Flow is the heaviest thing
 * on the asset page and most visits never open the graph. The default export is
 * what `lazy()` loads.
 *
 * Nothing can be dragged or connected: the positions come from
 * `layoutNeighborhood`, and a box a person had moved would be a picture of
 * their arrangement rather than of the estate.
 *
 * A press selects, as on the estate map (DECISIONS.md §133, §134): the box,
 * its neighbours and the arrows between them stay and the rest fades, and the
 * panel beside the canvas says what it is and which routes run through it.
 * Moving the question is the second act -- a double click, Enter, or the
 * panel's button centres the graph on a box, opens the centre's page, or
 * draws a folded group's members. An arrow is selected the same way. With
 * nothing selected, the box or arrow under the pointer is faded around
 * without being selected, so the graph can be scanned before a click.
 *
 * One tab stop, then arrow keys. Tabbing through a hundred boxes to reach the
 * panel would make the canvas a wall; a single stop with arrows inside is how
 * a grid of controls is reached everywhere else. Space selects, Enter opens.
 */
export default function NeighborhoodCanvas(props: CanvasProps) {
  return (
    <ReactFlowProvider>
      <Canvas {...props} />
    </ReactFlowProvider>
  );
}

interface CanvasProps {
  neighborhood: Neighborhood;
  /** A route to trace: its hops drawn strong, its cut marked, the rest faded. */
  traced?: AttackPath | null;
  /** The hop to draw as cut, when somebody picked one other than the cheapest. */
  cut?: Hop | null;
  pageAsset: string;
  selected?: GraphSelection | null;
  onSelect: (selection: GraphSelection | null) => void;
  /** The second act on a box: re-centre, open the centre's page, or open a fold. */
  onOpen: (id: string) => void;
  /** Put the keyboard on the focus box once drawn -- after a recentre made by key. */
  takeFocus?: boolean;
}

function Canvas({
  neighborhood,
  traced = null,
  cut = null,
  pageAsset,
  selected = null,
  onSelect,
  onOpen,
  takeFocus = false,
}: CanvasProps) {
  const { nodes, edges: drawn, at } = useMemo(
    () => toFlow(neighborhood, traced, cut),
    [neighborhood, traced, cut],
  );
  // With nothing selected, what the pointer or keyboard is on previews the
  // same fading. A traced route draws its own, and wins over both.
  const [previewed, setPreviewed] = useState<GraphSelection | null>(null);
  const on = traced ? null : (selected ?? previewed);
  const around = useMemo(() => kept(drawn, on), [drawn, on]);
  const edges = useMemo(
    () =>
      around
        ? drawn.map((edge) =>
            around.edges.has(edge.id)
              ? {
                  ...edge,
                  label: edge.data?.label as string | undefined,
                  labelStyle: { ...edge.labelStyle, fill: "var(--foreground)" },
                  style: {
                    ...edge.style,
                    stroke: "var(--foreground)",
                    strokeWidth: Number(edge.style?.strokeWidth ?? 1.5) + 1,
                  },
                  zIndex: 1,
                }
              : {
                  ...edge,
                  style: { ...edge.style, opacity: 0.15 },
                  labelStyle: { ...edge.labelStyle, opacity: 0.15 },
                },
          )
        : drawn,
    [drawn, around],
  );
  const [active, setActive] = useState(neighborhood.focus);
  const frame = useRef<HTMLDivElement>(null);
  const flow = useReactFlow();
  const reduced = usePrefersReducedMotion();
  // The mark belongs to a box that exists: after a fold opens or the focus
  // moves, a mark on a box that is gone would leave no tab stop at all.
  const marked = at.has(active) ? active : neighborhood.focus;

  const focusBox = (id: string) =>
    frame.current
      ?.querySelector<HTMLElement>(`[data-graph-node="${CSS.escape(id)}"]`)
      ?.focus({ preventScroll: true });

  useEffect(() => {
    if (!takeFocus) return;
    // React Flow draws its nodes a frame after it mounts.
    const frameId = requestAnimationFrame(() => focusBox(neighborhood.focus));
    return () => cancelAnimationFrame(frameId);
    // Once per canvas: the card remounts it for every new focus.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const direction = ARROWS[event.key];
    if (!direction || event.altKey || event.ctrlKey || event.metaKey) return;
    event.preventDefault();
    const next = stepFrom(at, marked, direction);
    if (!next) return;
    setActive(next);
    focusBox(next);
    const to = at.get(next)!;
    // Brought into view rather than left for the reader to pan to: a mark
    // that moves off-screen is a mark nobody can see.
    void flow.setCenter(to.x + BOX_WIDTH / 2, to.y + BOX_HEIGHT / 2, {
      zoom: flow.getZoom(),
      duration: reduced ? 0 : DURATION.quick,
    });
  }

  const actions: CanvasActions = {
    active: marked,
    setActive,
    select: (id) => onSelect({ kind: "box", id }),
    open: onOpen,
    preview: (id) => setPreviewed(id ? { kind: "box", id } : null),
    selected: selected?.kind === "box" ? selected.id : null,
    lit: around?.boxes ?? null,
    pageAsset,
  };

  return (
    <Actions.Provider value={actions}>
      <div ref={frame} className="size-full" onKeyDown={onKeyDown}>
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
          // The box inside each node is the tab stop; React Flow's own node
          // wrapper being one too would put two stops on every box.
          nodesFocusable={false}
          edgesFocusable={false}
          // An arrow is selected by pointer; by keyboard, from its box's panel.
          onEdgeClick={(_, edge) => onSelect({ kind: "edge", id: edge.id })}
          onEdgeMouseEnter={(_, edge) => setPreviewed({ kind: "edge", id: edge.id })}
          onEdgeMouseLeave={() => setPreviewed(null)}
          onPaneClick={() => onSelect(null)}
          // The canvas sits in a scrolling page. A wheel that zoomed the graph
          // would trap somebody scrolling past it; zoom is on the buttons and on
          // a pinch instead.
          zoomOnScroll={false}
          preventScrolling={false}
        >
          <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="var(--border)" />
          <ZoomButtons />
        </ReactFlow>
      </div>
    </Actions.Provider>
  );
}

/** The drawn size of a box, for centring the view on one. */
const BOX_WIDTH = 220;
const BOX_HEIGHT = 44;

function toFlow(
  neighborhood: Neighborhood,
  traced: AttackPath | null,
  chosenCut: Hop | null,
): { nodes: Node[]; edges: Edge[]; at: Map<string, { x: number; y: number }> } {
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
  const cutHop = traced ? (chosenCut ?? traced.cheapest_break) : null;
  const cut = cutHop ? hopKey(cutHop.source_id, cutHop.relationship, cutHop.target_id) : null;

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
      className: "cursor-pointer",
      // What a selection shows, even where a trace had hidden it.
      data: { label: structural ? undefined : edge.label },
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

  return { nodes, edges, at };
}

function AssetNode({ id, data }: NodeProps<AssetFlowNode>) {
  const actions = useActions();
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
  // The centre is where the graph is; opening it again means its page, and
  // on the page's own asset there is nowhere further to go.
  const opens = !data.focus
    ? "centre the graph here"
    : id !== actions.pageAsset && data.asset_id
      ? "open its page"
      : null;
  return (
    <>
      <Handle type="target" position={Position.Left} isConnectable={false} style={HIDDEN_HANDLE} />
      <BoxButton
        id={id}
        opens={opens}
        dimmed={data.dimmed}
        aria-current={data.focus || undefined}
        className={cn(
          "flex w-[220px] items-center gap-2 bg-card",
          data.focus ? "border-foreground shadow-sm ring-3 ring-ring/20" : "border-border",
        )}
      >
        {body}
      </BoxButton>
      <Handle type="source" position={Position.Right} isConnectable={false} style={HIDDEN_HANDLE} />
    </>
  );
}

/**
 * A box on the canvas: one button that selects on a press and opens on a
 * double click or Enter, and previews under the pointer or the keyboard.
 */
function BoxButton({
  id,
  opens,
  dimmed,
  className,
  children,
  ...rest
}: {
  id: string;
  /** What opening it does, for a screen reader; null when there is nothing to open. */
  opens: string | null;
  dimmed: boolean;
  className: string;
  children: ReactNode;
  "aria-current"?: boolean;
}) {
  const actions = useActions();
  const selected = actions.selected === id;
  return (
    <button
      type="button"
      {...rest}
      data-graph-node={id}
      tabIndex={actions.active === id ? 0 : -1}
      aria-pressed={selected}
      onFocus={() => {
        actions.setActive(id);
        actions.preview(id);
      }}
      onBlur={() => actions.preview(null)}
      onPointerEnter={() => actions.preview(id)}
      onPointerLeave={() => actions.preview(null)}
      onClick={() => actions.select(id)}
      onDoubleClick={() => opens && actions.open(id)}
      onKeyDown={(event) => {
        if (event.key !== "Enter") return;
        event.preventDefault();
        if (opens) actions.open(id);
      }}
      className={cn(
        "nopan cursor-pointer rounded-lg border px-2 py-1.5 text-left transition-[opacity,box-shadow] hover:bg-muted/60",
        "focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
        className,
        (dimmed || (actions.lit && !actions.lit.has(id))) && "opacity-30",
        selected && "ring-2 ring-foreground/70 ring-offset-2 ring-offset-card",
      )}
    >
      {children}
      {opens && <span className="sr-only">. Enter to {opens}</span>}
    </button>
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
function GroupNode({ id, data }: NodeProps<GroupFlowNode>) {
  const kinds = Object.entries(data.by_type).slice(0, 2);
  return (
    <>
      <Handle type="target" position={Position.Left} isConnectable={false} style={HIDDEN_HANDLE} />
      <BoxButton
        id={id}
        opens="show them"
        dimmed={data.dimmed}
        className="block w-[220px] border-dashed border-border bg-background"
      >
        <span className="block text-xs font-medium text-foreground tabular-nums">
          {data.count} more <span className="font-normal text-muted-foreground">· not drawn</span>
        </span>
        <span className="block truncate text-[11px] text-muted-foreground">
          {kinds.map(([type, count]) => `${resourceTypeLabel(type)} · ${count}`).join(", ")}
          {Object.keys(data.by_type).length > kinds.length && ", …"}
        </span>
      </BoxButton>
      <Handle type="source" position={Position.Right} isConnectable={false} style={HIDDEN_HANDLE} />
    </>
  );
}

// Module-level: React Flow re-mounts every node when this object's identity
// changes, and it warns when a new one arrives on each render.
const NODE_TYPES = { asset: AssetNode, group: GroupNode };
