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
import {
  Background,
  BaseEdge,
  BackgroundVariant,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type EdgeProps,
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
import { boxIcon, boxLabel, edgeLabel, edgeLabelShort } from "./estateNames";
import { Markers } from "./estateMarkers";
import { stepFrom } from "./neighborhoodLayout";

// `Pick` to a mapped type: React Flow wants node data to be a record.
type BoxFlowNode = Node<Pick<EstateBox, keyof EstateBox>, "box">;

interface ArrowData extends Record<string, unknown> {
  /** Every kind of reach the arrow carries, for when it is picked out. */
  full?: string;
  /** A backward arrow's own lane under the boxes, and its own gutter offset. */
  lane?: number;
  gutter?: number;
}

type ArrowFlowEdge = Edge<ArrowData>;

/**
 * What is selected on the map: a box, or an arrow (`source|target`). A click
 * selects and the panel beside the canvas answers for it; opening is a second,
 * deliberate act (DECISIONS.md §133).
 */
export type MapSelection = { kind: "box"; id: string } | { kind: "edge"; id: string };

interface CanvasActions {
  /** The box holding the single tab stop into the canvas. */
  active: string;
  setActive: (id: string) => void;
  /** Select a box: the panel shows it and the routes through it. */
  select: (id: string) => void;
  /** Open a box: a scope or group redraws the map, an asset opens its page. */
  open: (box: EstateBox) => void;
  /** The selected box, if a box is what is selected. */
  selected: string | null;
  /** The boxes picked out -- a link's two ends, or a traced route's -- if any. */
  lit: ReadonlySet<string> | null;
  /** Where each box sits along the traced route, as its badge reads: "2", "3–5". */
  order: ReadonlyMap<string, string>;
  /** The boxes the hop being read runs between. */
  current: ReadonlySet<string>;
}

const Actions = createContext<CanvasActions | null>(null);

function useActions(): CanvasActions {
  const actions = useContext(Actions);
  if (!actions) throw new Error("An estate box rendered outside EstateCanvas");
  return actions;
}

/**
 * One attack path laid over the map, and the hop being read on it.
 *
 * `boxes` is the route placed on this lens's boxes (`EstateRoute.boxes`): step
 * `i` runs from `boxes[i]` to `boxes[i + 1]`, and null is somewhere the lens
 * does not draw.
 */
export interface MapTrace {
  key: string;
  boxes: (string | null)[];
  hop: number;
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
 * Pressing a box or an arrow selects it, and the panel beside the canvas says
 * what it is and which attack paths run through it (§133). Opening is the
 * second act -- a double click, Enter, or the panel's button: a subscription
 * or group redraws the map with its contents, an asset opens its page with its
 * own graph drawn, and the fold lists what is in it. One tab stop, then arrow
 * keys, as on the neighbourhood; Space selects, Enter opens.
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
   * What is selected, and how to change it. A selected box keeps itself, its
   * neighbours and the arrows between them, and fades the rest; a selected
   * arrow keeps its two ends. The selection is brought into view when it is
   * made from the panel rather than on the canvas.
   */
  selected?: MapSelection | null;
  onSelect: (selection: MapSelection | null) => void;
  /** Put the keyboard on the first box once drawn -- after opening one by key. */
  takeFocus?: boolean;
  /**
   * A route to trace: its boxes numbered in the order it visits them, its
   * arrows drawn, the hop being read marked, and everything else faded. Takes
   * the place of `highlight` while set.
   */
  trace?: MapTrace | null;
}

function Canvas({
  map,
  onOpen,
  onSelect,
  takeFocus = false,
  selected = null,
  trace = null,
}: CanvasProps) {
  const { nodes, edges: drawn, at, first } = useMemo(() => toFlow(map), [map]);
  const reduced = usePrefersReducedMotion();
  const traced = useMemo(
    () => (trace ? traceOnMap(trace, at, new Set(drawn.map((edge) => edge.id))) : null),
    [trace, at, drawn],
  );
  // A selection fades the rest rather than hiding it: what is selected still
  // has to be read in its place in the estate, not on its own.
  const picked =
    !traced && selected?.kind === "edge"
      ? drawn.find((edge) => edge.id === selected.id)
      : undefined;
  const box = !traced && selected?.kind === "box" && at.has(selected.id) ? selected.id : null;
  const touching = useMemo(
    () =>
      box
        ? drawn.filter((edge) => edge.source === box || edge.target === box)
        : picked
          ? [picked]
          : null,
    [box, picked, drawn],
  );
  const lit = useMemo(
    () =>
      traced?.lit ??
      (touching
        ? new Set([...(box ? [box] : []), ...touching.flatMap((e) => [e.source, e.target])])
        : null),
    [box, touching, traced],
  );
  const edges = useMemo(
    () =>
      traced
        ? drawn.map((edge) => {
            const now = edge.id === traced.currentEdge;
            if (!now && !traced.edges.has(edge.id)) {
              return {
                ...edge,
                label: undefined,
                style: { ...edge.style, opacity: 0.12 },
              };
            }
            const stroke = now ? "var(--primary)" : "var(--foreground)";
            return {
              ...edge,
              // The hop being read says everything it carries; the rest of
              // the route keeps its short label, and the step bar says it all.
              label: now ? edge.data?.full : edge.label,
              labelStyle: { ...edge.labelStyle, fill: stroke, fontWeight: now ? 600 : 400 },
              style: {
                ...edge.style,
                stroke,
                strokeWidth: Number(edge.style?.strokeWidth ?? 1.5) + (now ? 2 : 1),
              },
              markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 14, height: 14 },
              // The hop being read moves; the rest of the route holds still.
              animated: now && !reduced,
              zIndex: now ? 2 : 1,
            };
          })
        : touching
        ? drawn.map((edge) =>
            touching.includes(edge)
              ? {
                  ...edge,
                  // A selected arrow says everything it carries. Around a
                  // selected box the arrows keep their short labels: a hub
                  // touches most of the map, and every label in full would
                  // cover the boxes beside them. The panel says them all.
                  label: picked ? edge.data?.full : edge.label,
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
    [drawn, touching, picked, traced, reduced],
  );
  const [active, setActive] = useState(first);
  const frame = useRef<HTMLDivElement>(null);
  const flow = useReactFlow();
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

  // Whether every one of these boxes is on screen at the current viewport.
  function inView(ids: Iterable<string>): boolean {
    const { x: dx, y: dy, zoom } = flow.getViewport();
    const width = frame.current?.clientWidth ?? 0;
    const height = frame.current?.clientHeight ?? 0;
    // A canvas with no size yet shows nothing to move towards.
    if (width === 0 || height === 0) return true;
    return [...ids].every((id) => {
      const p = at.get(id);
      return (
        !p ||
        (p.x * zoom + dx >= 0 &&
          (p.x + BOX_WIDTH) * zoom + dx <= width &&
          p.y * zoom + dy >= 0 &&
          (p.y + BOX_HEIGHT) * zoom + dy <= height)
      );
    });
  }

  function centreOn(ids: string[]) {
    const ends = ids.map((id) => at.get(id)).filter((p) => p !== undefined);
    if (ends.length === 0 || inView(ids)) return;
    const x = ends.reduce((sum, p) => sum + p.x, 0) / ends.length + BOX_WIDTH / 2;
    const y = ends.reduce((sum, p) => sum + p.y, 0) / ends.length + BOX_HEIGHT / 2;
    void flow.setCenter(x, y, { zoom: flow.getZoom(), duration: reduced ? 0 : DURATION.quick });
  }

  // A selection made in the panel is brought into view; one made on the
  // canvas is already there, so nothing moves.
  useEffect(() => {
    if (!selected) return;
    const edge = selected.kind === "edge" ? drawn.find((e) => e.id === selected.id) : undefined;
    centreOn(selected.kind === "box" ? [selected.id] : edge ? [edge.source, edge.target] : []);
    // Only a new selection moves the view.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.kind, selected?.id]);

  // A route picked is framed whole; a step along it pans to the hop only when
  // the hop is out of view, keeping the zoom, so the route stays where the
  // reader left it rather than jumping.
  const framed = useRef<string | null>(null);
  useEffect(() => {
    if (!trace || !traced) {
      framed.current = null;
      return;
    }
    const duration = reduced ? 0 : DURATION.quick;
    if (framed.current !== trace.key) {
      // A route running back along the lanes is framed down to them.
      const laned = drawn.some((edge) => edge.type === "back" && traced.edges.has(edge.id));
      // Two frames on: the step bar arriving above shrinks the canvas, and
      // React Flow learns its new size from a resize observer. Fitted any
      // sooner, the route is framed for the taller canvas and its foot is cut.
      let frameId = requestAnimationFrame(() => {
        frameId = requestAnimationFrame(() => {
          // Only once it has run: a step taken before then frames it again.
          framed.current = trace.key;
          void flow.fitView({
            nodes: [...traced.lit, ...(laned ? ["lanes"] : [])].map((id) => ({ id })),
            padding: 0.3,
            maxZoom: 1.1,
            duration,
          });
        });
      });
      return () => cancelAnimationFrame(frameId);
    }
    // Framed whole, the hop is usually already in view: then nothing moves.
    centreOn([...traced.current]);
    // The route and the hop are what move the view; `traced` follows them.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [trace?.key, trace?.hop]);

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
        select: (id) => onSelect({ kind: "box", id }),
        open: onOpen,
        selected: selected?.kind === "box" ? selected.id : null,
        lit,
        order: traced?.order ?? NO_ORDER,
        current: traced?.current ?? NO_BOXES,
      }}
    >
      <div ref={frame} className="size-full" onKeyDown={onKeyDown}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={NODE_TYPES}
          edgeTypes={EDGE_TYPES}
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
          // An arrow is selected by pointer; by keyboard, from the panel's
          // list of links, which is the arrows' text form.
          onEdgeClick={(_, edge) => onSelect({ kind: "edge", id: edge.id })}
          onPaneClick={() => onSelect(null)}
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
  edges: ArrowFlowEdge[];
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

  // Below every box: where backward arrows run, each in a lane of its own.
  const floor = Math.max(0, ...[...at.values()].map((p) => p.y)) + BOX_HEIGHT + 40;
  let backward = 0;

  const edges: ArrowFlowEdge[] = map.edges.map((edge) => {
    const label = edgeLabel(edge.links);
    const total = edge.links.reduce((sum, link) => sum + link.count, 0);
    // Containment is drawn only where a route runs along it, and unlabelled,
    // as on the neighbourhood: it is where things live, never what is cut.
    const structural = label === undefined;
    const stroke = edge.on_route ? "var(--foreground)" : "var(--muted-foreground)";
    // Thicker with more links, but only a little: the count is on the label,
    // and a line twenty times wider would say the same thing less exactly.
    const width = (structural ? 1 : 1.5) + Math.min(Math.log2(total), 3) * 0.5;
    // Reach that runs back against the columns -- into a box level with, or
    // left of, where it starts -- goes round rather than across: out into the
    // gap beside its source, down to a lane under every box, along, and up the
    // gap beside its target. The gaps and the lane hold no boxes, so the arrow
    // crosses none, and each backward arrow has its own lane and gutter so two
    // never run along one line.
    const from = at.get(edge.source) ?? origin;
    const to = at.get(edge.target) ?? origin;
    const back = to.x <= from.x;
    const lane = back ? backward++ : 0;
    return {
      id: `${edge.source}|${edge.target}`,
      source: edge.source,
      target: edge.target,
      type: back ? "back" : "default",
      className: "cursor-pointer",
      // Several kinds of reach on one arrow read as their first and a count on
      // the canvas; picked, the arrow says them all, and the list under the
      // map always does.
      label: edgeLabelShort(edge.links),
      data: back
        ? { full: label, lane: floor + lane * 18, gutter: 20 + (lane % 6) * 10 }
        : { full: label },
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

  // Fitting the view fits boxes, and the lanes run under them: a point below
  // the last lane is what brings them, and their labels, into the frame.
  if (backward > 0) {
    nodes.push({
      id: "lanes",
      type: "floor",
      position: { x: Math.min(...[...at.values()].map((p) => p.x)), y: floor + backward * 18 },
      data: {},
      selectable: false,
      focusable: false,
      // Not a box: nothing for a screen reader to find here.
      domAttributes: { "aria-hidden": true, "aria-describedby": undefined },
    });
  }

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
    "transition-[opacity,box-shadow]",
    actions.lit && !actions.lit.has(id) && "opacity-30",
    actions.current.has(id) && "border-primary ring-3 ring-primary/30",
  );
  const order = actions.order.get(id);
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

  const selected = actions.selected === id;
  const opens =
    data.kind === "scope" || data.kind === "group"
      ? "open it on the map"
      : fold
        ? "list them"
        : "open its page";
  const box = (
    <button
      type="button"
      {...stop}
      aria-pressed={selected}
      onClick={() => actions.select(id)}
      onDoubleClick={() => actions.open(data)}
      onKeyDown={(event) => {
        if (event.key !== "Enter") return;
        event.preventDefault();
        actions.open(data);
      }}
      className={cn(
        frame,
        "cursor-pointer hover:bg-muted/60",
        selected && "ring-2 ring-foreground/70 ring-offset-2 ring-offset-card",
      )}
    >
      {body}
      <span className="sr-only">. Enter to {opens}</span>
    </button>
  );

  return (
    <>
      <Handle type="target" position={Position.Left} isConnectable={false} style={HIDDEN_HANDLE} />
      {order && (
        // Where the traced route visits this box, as the step bar counts it.
        <span
          aria-hidden
          className={cn(
            "pointer-events-none absolute -top-2.5 -left-2.5 z-10 flex h-5 min-w-5 items-center justify-center rounded-full border px-1 text-[10px] font-semibold tabular-nums",
            actions.current.has(id)
              ? "border-primary bg-primary text-primary-foreground"
              : "border-foreground/40 bg-card text-foreground",
          )}
        >
          {order}
        </span>
      )}
      {box}
      <Handle type="source" position={Position.Right} isConnectable={false} style={HIDDEN_HANDLE} />
    </>
  );
}

const NO_ORDER: ReadonlyMap<string, string> = new Map();
const NO_BOXES: ReadonlySet<string> = new Set();

/**
 * What a traced route lights on this map: the boxes it visits and the badge
 * each carries, the arrows it runs along, and the hop being read.
 *
 * A step between two nodes in one box is inside that box and has no arrow; a
 * step to somewhere the lens does not draw has no box at that end. Both are
 * still steps -- the bar counts them -- and the map lights what it can.
 */
function traceOnMap(
  trace: MapTrace,
  at: ReadonlyMap<string, unknown>,
  drawnEdges: ReadonlySet<string>,
): {
  lit: Set<string>;
  order: Map<string, string>;
  edges: Set<string>;
  current: Set<string>;
  currentEdge: string | null;
} {
  const visits = new Map<string, number[]>();
  trace.boxes.forEach((box, index) => {
    if (box && at.has(box)) visits.set(box, [...(visits.get(box) ?? []), index + 1]);
  });
  const edgeOf = (i: number): string | null => {
    const a = trace.boxes[i];
    const b = trace.boxes[i + 1];
    if (!a || !b || a === b) return null;
    const id = `${a}|${b}`;
    return drawnEdges.has(id) ? id : null;
  };
  const edges = new Set<string>();
  for (let i = 0; i < trace.boxes.length - 1; i += 1) {
    const id = edgeOf(i);
    if (id) edges.add(id);
  }
  const current = new Set(
    [trace.boxes[trace.hop], trace.boxes[trace.hop + 1]].filter(
      (box): box is string => box !== null && box !== undefined && at.has(box),
    ),
  );
  return {
    lit: new Set(visits.keys()),
    order: new Map([...visits].map(([box, at]) => [box, spans(at)])),
    edges,
    current,
    currentEdge: edgeOf(trace.hop),
  };
}

/** 1, 3, 4, 5 as "1, 3–5": where a route visits one box, compactly. */
function spans(positions: number[]): string {
  const parts: string[] = [];
  let start = positions[0];
  for (let i = 1; i <= positions.length; i += 1) {
    if (positions[i] === positions[i - 1] + 1) continue;
    const end = positions[i - 1];
    parts.push(start === end ? `${start}` : `${start}–${end}`);
    start = positions[i];
  }
  return parts.join(", ");
}

/** Nothing to see: the bottom edge of the lanes, for the view to fit to. */
function Floor() {
  return <div aria-hidden className="size-px" />;
}

/**
 * A backward arrow, drawn round the boxes: out of its source's right side
 * into the gap, down to its lane under every box, along it, up the gap
 * before its target, and in from the left like every other arrow.
 */
function BackEdge({
  sourceX,
  sourceY,
  targetX,
  targetY,
  data,
  label,
  labelStyle,
  labelBgStyle,
  labelBgPadding,
  style,
  markerEnd,
}: EdgeProps<ArrowFlowEdge>) {
  const lane = data?.lane ?? sourceY;
  const gutter = data?.gutter ?? 20;
  const out = sourceX + gutter;
  const into = targetX - gutter;
  return (
    <BaseEdge
      path={orthogonal([
        [sourceX, sourceY],
        [out, sourceY],
        [out, lane],
        [into, lane],
        [into, targetY],
        [targetX, targetY],
      ])}
      label={label}
      labelX={(out + into) / 2}
      labelY={lane}
      labelStyle={labelStyle}
      labelBgStyle={labelBgStyle}
      labelBgPadding={labelBgPadding}
      style={style}
      markerEnd={markerEnd}
    />
  );
}

/** A path through right-angled corners, each rounded a little. */
function orthogonal(points: [number, number][], radius = 8): string {
  let d = `M ${points[0][0]} ${points[0][1]}`;
  for (let i = 1; i < points.length - 1; i += 1) {
    const [px, py] = points[i - 1];
    const [x, y] = points[i];
    const [nx, ny] = points[i + 1];
    const r = Math.min(radius, Math.hypot(x - px, y - py) / 2, Math.hypot(nx - x, ny - y) / 2);
    const ax = x - Math.sign(x - px) * r;
    const ay = y - Math.sign(y - py) * r;
    const bx = x + Math.sign(nx - x) * r;
    const by = y + Math.sign(ny - y) * r;
    d += ` L ${ax} ${ay} Q ${x} ${y} ${bx} ${by}`;
  }
  const [lx, ly] = points[points.length - 1];
  return `${d} L ${lx} ${ly}`;
}

// Module-level: React Flow re-mounts every node when this object's identity changes.
const NODE_TYPES = { box: BoxNode, floor: Floor };
const EDGE_TYPES = { back: BackEdge };
