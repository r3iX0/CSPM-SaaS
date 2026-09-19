import {
  createContext,
  createElement,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
} from "react";
import { Link, useLocation } from "react-router-dom";
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
// The structural stylesheet only, as in NeighborhoodCanvas.
import "@xyflow/react/dist/base.css";

import type { EstateBox, EstateMap } from "@/lib/types";
import { cn } from "@/lib/format";
import { DURATION, usePrefersReducedMotion } from "@/lib/motion";
import { ARROWS, FIT, FLOW_TOKENS, HIDDEN_HANDLE } from "./flowChrome";
import { ZoomButtons } from "./ZoomButtons";
import { layoutEstate } from "./estateLayout";
import { boxHref, boxIcon, boxLabel, edgeLabel } from "./estateNames";
import { Markers } from "./estateMarkers";
import { stepFrom } from "./neighborhoodLayout";

// `Pick` to a mapped type: React Flow wants node data to be a record.
type BoxFlowNode = Node<Pick<EstateBox, keyof EstateBox>, "box">;

interface CanvasActions {
  /** The box holding the single tab stop into the canvas. */
  active: string;
  setActive: (id: string) => void;
  /** Open a scope or a group: the map redraws with its contents. */
  open: (box: EstateBox) => void;
  /** The two ends of the arrow picked from the list under the map, if any. */
  lit: ReadonlySet<string> | null;
  /** Where an asset's page trail should lead back to: this map, as opened. */
  from: string;
}

const Actions = createContext<CanvasActions | null>(null);

function useActions(): CanvasActions {
  const actions = useContext(Actions);
  if (!actions) throw new Error("An estate box rendered outside EstateCanvas");
  return actions;
}

/** The drawn size of a box, for centring the view on one. */
const BOX_WIDTH = 240;
const BOX_HEIGHT = 52;

/**
 * The canvas behind the estate map: boxes for subscriptions, groups and
 * assets, and the reach between them (DECISIONS.md §111).
 *
 * Its own module so it is a lazy chunk, sharing React Flow with the asset
 * neighbourhood. Read-only for the same reason that one is: the positions come
 * from `layoutEstate`, and a box somebody had dragged would be a picture of
 * their arrangement rather than of the estate.
 *
 * Pressing a subscription or a group opens it -- the map redraws with its
 * contents -- which is how the estate is walked; pressing an asset opens its
 * page with its own graph drawn, and pressing the fold lists what is in it.
 * One tab stop, then arrow keys, as on the neighbourhood.
 */
export default function EstateCanvas(props: CanvasProps) {
  return (
    <ReactFlowProvider>
      <Canvas {...props} />
    </ReactFlowProvider>
  );
}

interface CanvasProps {
  map: EstateMap;
  onOpen: (box: EstateBox) => void;
  /**
   * One arrow, `source|target`, to pick out of the picture: it and its two
   * boxes stay, everything else fades. Chosen from the list of reach under
   * the map, which is where a person reads the arrows one at a time.
   */
  highlight?: string | null;
  /** Put the keyboard on the first box once drawn -- after opening one by key. */
  takeFocus?: boolean;
}

function Canvas({ map, onOpen, takeFocus = false, highlight = null }: CanvasProps) {
  const { nodes, edges: drawn, at, first } = useMemo(() => toFlow(map), [map]);
  const location = useLocation();
  // A picked arrow fades the rest rather than hiding it: the arrow still has
  // to be read in its place in the estate, not on its own.
  const picked = highlight ? drawn.find((edge) => edge.id === highlight) : undefined;
  const lit = useMemo(
    () => (picked ? new Set([picked.source, picked.target]) : null),
    [picked],
  );
  const edges = useMemo(
    () =>
      picked
        ? drawn.map((edge) =>
            edge.id === picked.id
              ? {
                  ...edge,
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
    [drawn, picked],
  );
  const [active, setActive] = useState(first);
  const frame = useRef<HTMLDivElement>(null);
  const flow = useReactFlow();
  const reduced = usePrefersReducedMotion();
  const marked = at.has(active) ? active : first;

  const focusBox = (id: string) =>
    frame.current
      ?.querySelector<HTMLElement>(`[data-graph-node="${CSS.escape(id)}"]`)
      ?.focus({ preventScroll: true });

  useEffect(() => {
    if (!takeFocus) return;
    // React Flow draws its nodes a frame after it mounts.
    const frameId = requestAnimationFrame(() => focusBox(first));
    return () => cancelAnimationFrame(frameId);
    // Once per canvas: the map remounts it for every lens.
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
        open: onOpen,
        lit,
        from: `${location.pathname}${location.search}`,
      }}
    >
      <div ref={frame} className="size-full" onKeyDown={onKeyDown}>
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
          // The box inside each node is the tab stop.
          nodesFocusable={false}
          edgesFocusable={false}
          // The canvas sits in a scrolling page; zoom is on the buttons.
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

function toFlow(map: EstateMap): {
  nodes: Node[];
  edges: Edge[];
  at: Map<string, { x: number; y: number }>;
  first: string;
} {
  const at = layoutEstate(map);
  const origin = { x: 0, y: 0 };

  const nodes: Node[] = map.boxes.map(
    (box): BoxFlowNode => ({
      id: box.id,
      type: "box",
      position: at.get(box.id) ?? origin,
      data: box,
    }),
  );

  const edges: Edge[] = map.edges.map((edge) => {
    const label = edgeLabel(edge.links);
    const total = edge.links.reduce((sum, link) => sum + link.count, 0);
    // Containment is drawn only where a route runs along it, and unlabelled,
    // as on the neighbourhood: it is where things live, never what is cut.
    const structural = label === undefined;
    const stroke = edge.on_route ? "var(--foreground)" : "var(--muted-foreground)";
    // Thicker with more links, but only a little: the count is on the label,
    // and a line twenty times wider would say the same thing less exactly.
    const width = (structural ? 1 : 1.5) + Math.min(Math.log2(total), 3) * 0.5;
    return {
      id: `${edge.source}|${edge.target}`,
      source: edge.source,
      target: edge.target,
      label,
      labelStyle: {
        fill: edge.on_route ? "var(--foreground)" : "var(--muted-foreground)",
        fontSize: 11,
      },
      labelBgStyle: { fill: "var(--card)" },
      labelBgPadding: [4, 2] as [number, number],
      style: { stroke, strokeWidth: width },
      markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 14, height: 14 },
    };
  });

  // The keyboard's first stop: the top of the first column, where reach starts.
  const first =
    [...at.entries()].sort(([, a], [, b]) => a.x - b.x || a.y - b.y)[0]?.[0] ??
    map.boxes[0]?.id ??
    "";

  return { nodes, edges, at, first };
}

function BoxNode({ id, data }: NodeProps<BoxFlowNode>) {
  const actions = useActions();
  const { title, detail } = boxLabel(data);
  const fold = data.kind === "fold";
  const frame = cn(
    "flex w-[240px] items-center gap-2 rounded-lg border px-2 py-1.5 text-left",
    "nopan focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
    // Dashed, the way every gap in what CloudGuard draws is: counted, not drawn.
    fold && "border-dashed border-border bg-background",
    !fold && (data.inside ? "border-border bg-card" : "border-border bg-muted/40"),
    !fold && data.routes > 0 && "border-foreground/40",
    "transition-opacity",
    actions.lit && !actions.lit.has(id) && "opacity-30",
  );
  const stop = {
    "data-graph-node": id,
    tabIndex: actions.active === id ? 0 : -1,
    onFocus: () => actions.setActive(id),
  };
  const body = (
    <>
      {!fold && (
        <span className="flex size-7 shrink-0 items-center justify-center rounded-md border border-border bg-background text-muted-foreground">
          {createElement(boxIcon(data), { className: "size-3.5", "aria-hidden": true })}
        </span>
      )}
      <span className="min-w-0 flex-1">
        <span
          className={cn(
            "block truncate text-xs font-medium",
            data.inside ? "text-foreground" : "text-muted-foreground",
          )}
        >
          {title}
        </span>
        <span className="block truncate text-[11px] text-muted-foreground">{detail}</span>
      </span>
      <Markers box={data} />
    </>
  );

  let box;
  const href = boxHref(data);
  if (data.kind === "scope" || data.kind === "group") {
    box = (
      <button
        type="button"
        {...stop}
        onClick={() => actions.open(data)}
        className={cn(frame, "cursor-pointer hover:bg-muted/60")}
      >
        {body}
        <span className="sr-only">. Open it on the map</span>
      </button>
    );
  } else if (href) {
    box = (
      <Link
        to={href}
        state={{ from: actions.from }}
        {...stop}
        className={cn(frame, "hover:bg-muted/60")}
      >
        {body}
        <span className="sr-only">{fold ? ". List them" : ". Open its page"}</span>
      </Link>
    );
  } else {
    box = (
      <div {...stop} className={frame}>
        {body}
      </div>
    );
  }

  return (
    <>
      <Handle type="target" position={Position.Left} isConnectable={false} style={HIDDEN_HANDLE} />
      {box}
      <Handle type="source" position={Position.Right} isConnectable={false} style={HIDDEN_HANDLE} />
    </>
  );
}

// Module-level: React Flow re-mounts every node when this object's identity changes.
const NODE_TYPES = { box: BoxNode };
