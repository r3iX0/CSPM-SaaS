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
import {
  ARROWS,
  FIT,
  FLOW_TOKENS,
  HIDDEN_HANDLE,
  kept,
  type GraphSelection,
} from "./flowChrome";
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
  /**
   * Where a long arrow crosses each column between its ends: the left edge of
   * the slot kept for it, at the height it runs through (DECISIONS.md §134).
   */
  bends?: { x: number; y: number }[];
}

type ArrowFlowEdge = Edge<ArrowData>;

/**
 * What is selected on the map: a box, or an arrow (`source|target`). A click
 * selects and the panel beside the canvas answers for it; opening is a second,
 * deliberate act (DECISIONS.md §133).
 */
export type MapSelection = GraphSelection;

interface CanvasActions {
  /** The box holding the single tab stop into the canvas. */
  active: string;
  setActive: (id: string) => void;
  /** Select a box: the panel shows it and what reaches it and what it reaches. */
  select: (id: string) => void;
  /** Open a box: a scope or group redraws the map, an asset opens its page. */
  open: (box: EstateBox) => void;
  /** The selected box, if a box is what is selected. */
  selected: string | null;
  /** Previewed under the pointer or the keyboard: faded around, not selected. */
  preview: (id: string | null) => void;
  /** The boxes picked out -- a selection and what it touches -- if any. */
  lit: ReadonlySet<string> | null;
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
 * Pressing a box or an arrow selects it, and the panel beside the canvas says
 * what it is and what reaches it (§133). Attack paths are not drawn here:
 * walking one is the attack-path page's (§138). Opening is the
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
}

function Canvas({
  map,
  onOpen,
  onSelect,
  takeFocus = false,
  selected = null,
}: CanvasProps) {
  const { nodes, edges: drawn, at, first } = useMemo(() => toFlow(map), [map]);
  const reduced = usePrefersReducedMotion();
  // What the pointer or the keyboard is on, faded around as a selection is
  // but without selecting it, so the map can be scanned before a click. Only
  // with nothing selected: the panel answers for a selection, and a preview
  // that redrew the canvas under it would contradict the panel.
  const [previewed, setPreviewed] = useState<MapSelection | null>(null);
  const looking = selected ?? previewed;
  // A selection fades the rest rather than hiding it: what is selected still
  // has to be read in its place in the estate, not on its own.
  // A box this lens is not drawing keeps nothing.
  const on = looking?.kind === "box" && !at.has(looking.id) ? null : looking;
  const picked = on?.kind === "edge";
  const around = useMemo(() => kept(drawn, on), [drawn, on]);
  const lit = around?.boxes ?? null;
  const edges = useMemo(
    () =>
      around
        ? drawn.map((edge) =>
            around.edges.has(edge.id)
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
    [drawn, around, picked],
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
        preview: (id) => setPreviewed(id ? { kind: "box", id } : null),
        lit,
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
          onEdgeMouseEnter={(_, edge) => setPreviewed({ kind: "edge", id: edge.id })}
          onEdgeMouseLeave={() => setPreviewed(null)}
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
  const { at, bends } = layoutEstate(map);
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
    const stroke = "var(--muted-foreground)";
    // Thicker with more links, but only a little: the count is on the label,
    // and a line twenty times wider would say the same thing less exactly.
    const width = (structural ? 1 : 1.5) + Math.min(Math.log2(total), 3) * 0.5;
    // Reach that runs back against the columns -- into a box level with, or
    // left of, where it starts -- goes round rather than across: out into the
    // gap beside its source, down to a lane under every box, along, and up the
    // gap beside its target. The gaps and the lane hold no boxes, so the arrow
    // crosses none, and each backward arrow has its own lane and gutter so two
    // never run along one line.
    // Reach that crosses more than one gap runs through the slot each column
    // between keeps for it, rather than over the boxes stacked there.
    const id = `${edge.source}|${edge.target}`;
    const from = at.get(edge.source) ?? origin;
    const to = at.get(edge.target) ?? origin;
    const back = to.x <= from.x;
    const lane = back ? backward++ : 0;
    const through = back ? undefined : bends.get(id);
    return {
      id,
      source: edge.source,
      target: edge.target,
      type: back ? "back" : through ? "long" : "default",
      className: "cursor-pointer",
      // Several kinds of reach on one arrow read as their first and a count on
      // the canvas; picked, the arrow says them all, and the list under the
      // map always does.
      label: edgeLabelShort(edge.links),
      data: back
        ? { full: label, lane: floor + lane * 18, gutter: 20 + (lane % 6) * 10 }
        : through
          ? { full: label, bends: through.map((p) => ({ x: p.x, y: p.y + BOX_HEIGHT / 2 })) }
          : { full: label },
      labelStyle: { fill: "var(--muted-foreground)", fontSize: 11 },
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

  // Fitting the view fits boxes, and a slot kept for a long arrow can sit
  // above or below every box in its column: an empty node in each keeps it,
  // and the arrow through it, in the frame.
  for (const [id, through] of bends) {
    through.forEach((p, index) =>
      nodes.push({
        id: `bend:${id}#${index}`,
        type: "floor",
        position: p,
        data: {},
        selectable: false,
        focusable: false,
        domAttributes: { "aria-hidden": true, "aria-describedby": undefined },
      }),
    );
  }

  // The lanes run under the boxes: a point below the last lane is what
  // brings them, and their labels, into the frame.
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
    !fold &&
      (data.inside ? "border-border bg-card" : "border-border bg-muted/40"),
    "transition-[opacity,box-shadow]",
    actions.lit && !actions.lit.has(id) && "opacity-30",
  );
  const stop = {
    "data-graph-node": id,
    tabIndex: actions.active === id ? 0 : -1,
    onFocus: () => {
      actions.setActive(id);
      actions.preview(id);
    },
    onBlur: () => actions.preview(null),
    onPointerEnter: () => actions.preview(id),
    onPointerLeave: () => actions.preview(null),
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
      <Handle
        type="target"
        position={Position.Left}
        isConnectable={false}
        style={HIDDEN_HANDLE}
      />
      {box}
      <Handle type="source" position={Position.Right} isConnectable={false} style={HIDDEN_HANDLE} />
    </>
  );
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

/**
 * A forward arrow that crosses more than one gap: out of its source, through
 * the slot kept for it in each column between -- straight across the slot,
 * which holds no box -- and into its target. Each gap is the same curve a
 * one-gap arrow draws, so the long arrow reads as several short ones joined.
 */
function LongEdge({
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
  const bends = data?.bends ?? [];
  let d = `M ${sourceX} ${sourceY}`;
  let [x, y] = [sourceX, sourceY];
  const curve = (toX: number, toY: number) => {
    const k = (toX - x) / 2;
    d += ` C ${x + k} ${y} ${toX - k} ${toY} ${toX} ${toY}`;
  };
  for (const bend of bends) {
    curve(bend.x, bend.y);
    d += ` L ${bend.x + BOX_WIDTH} ${bend.y}`;
    [x, y] = [bend.x + BOX_WIDTH, bend.y];
  }
  curve(targetX, targetY);
  // The label sits in the first gap, beside the arrow's source, where a
  // one-gap arrow's would.
  const first = bends[0] ?? { x: targetX, y: targetY };
  return (
    <BaseEdge
      path={d}
      label={label}
      labelX={(sourceX + first.x) / 2}
      labelY={(sourceY + first.y) / 2}
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
const EDGE_TYPES = { back: BackEdge, long: LongEdge };
