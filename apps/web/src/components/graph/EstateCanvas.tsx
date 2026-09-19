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
import { Link } from "react-router-dom";
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
import { cn, levelStyle } from "@/lib/format";
import { DIRECTORY_ICON, FACTOR_ICONS, RISK_KIND_ICONS, resourceTypeIcon } from "@/lib/icons";
import { DURATION, usePrefersReducedMotion } from "@/lib/motion";
import { ARROWS, FIT, FLOW_TOKENS, HIDDEN_HANDLE } from "./flowChrome";
import { ZoomButtons } from "./ZoomButtons";
import { layoutEstate } from "./estateLayout";
import { boxHref, boxLabel, edgeLabel } from "./estateNames";
import { stepFrom } from "./neighborhoodLayout";

// `Pick` to a mapped type: React Flow wants node data to be a record.
type BoxFlowNode = Node<Pick<EstateBox, keyof EstateBox>, "box">;

interface CanvasActions {
  /** The box holding the single tab stop into the canvas. */
  active: string;
  setActive: (id: string) => void;
  /** Open a scope or a group: the map redraws with its contents. */
  open: (box: EstateBox) => void;
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
  /** Put the keyboard on the first box once drawn -- after opening one by key. */
  takeFocus?: boolean;
}

function Canvas({ map, onOpen, takeFocus = false }: CanvasProps) {
  const { nodes, edges, at, first } = useMemo(() => toFlow(map), [map]);
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
    <Actions.Provider value={{ active: marked, setActive, open: onOpen }}>
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

function boxIcon(box: EstateBox) {
  if (box.kind === "asset") return resourceTypeIcon(box.resource_type ?? "unknown");
  // A scope, or what sits directly in one, is drawn as the scope.
  if (box.kind === "scope" || (box.kind === "group" && box.group === null)) {
    return box.scope_id === "directory" ? DIRECTORY_ICON : resourceTypeIcon("subscription");
  }
  return resourceTypeIcon("resource_group");
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
      <Link to={href} {...stop} className={cn(frame, "hover:bg-muted/60")}>
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

const LEVEL_TEXT: Record<string, string> = {
  CRITICAL: "text-critical",
  HIGH: "text-high",
};

/**
 * Ways in, sensitive data, attack paths and open findings, counted.
 *
 * The neighbourhood's markers, with a number wherever a box holds more than
 * one asset: a globe for assets a route may start from, a cylinder for ones it
 * may end at, the route glyph for attack paths passing through, and open
 * findings tinted by the worst. Each carries its meaning as screen-reader
 * text, which is also what a box's link is named from.
 */
function Markers({ box }: { box: EstateBox }) {
  const Exposure = FACTOR_ICONS.exposure;
  const Sensitive = FACTOR_ICONS.dataSensitivity;
  const Route = RISK_KIND_ICONS.ATTACK_PATH;
  const single = box.kind === "asset";
  const { open, worst } = box.findings;

  return (
    <span className="flex shrink-0 items-center gap-1.5 text-[10px] text-muted-foreground">
      {box.entry > 0 && (
        <span className="flex items-center gap-0.5" title="Reachable from the internet">
          <Exposure
            className={cn(
              "size-3.5",
              single ? LEVEL_TEXT[box.public_exposure ?? ""] : "text-high",
            )}
            aria-hidden
          />
          {!single && <span className="tabular-nums">{box.entry}</span>}
          <span className="sr-only">
            {single ? ", reachable from the internet" : " reachable from the internet"}
          </span>
        </span>
      )}
      {box.sensitive > 0 && (
        <span className="flex items-center gap-0.5" title="Holds sensitive data">
          <Sensitive
            className={cn(
              "size-3.5",
              single ? LEVEL_TEXT[box.data_sensitivity ?? ""] : "text-high",
            )}
            aria-hidden
          />
          {!single && <span className="tabular-nums">{box.sensitive}</span>}
          <span className="sr-only">
            {single ? ", holds sensitive data" : " holding sensitive data"}
          </span>
        </span>
      )}
      {box.routes > 0 && (
        <span className="flex items-center gap-0.5 text-foreground" title="On attack paths">
          <Route className="size-3.5" aria-hidden />
          <span className="tabular-nums">{box.routes}</span>
          <span className="sr-only"> attack path{box.routes === 1 ? "" : "s"}</span>
        </span>
      )}
      {open > 0 && (
        <span
          title={`${open} open finding${open === 1 ? "" : "s"}, worst ${worst?.toLowerCase()}`}
          className={cn(
            "rounded border px-1 leading-4 font-medium tabular-nums",
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

// Module-level: React Flow re-mounts every node when this object's identity changes.
const NODE_TYPES = { box: BoxNode };
