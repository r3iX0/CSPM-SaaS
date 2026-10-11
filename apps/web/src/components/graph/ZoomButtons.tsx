import { Panel, useReactFlow, useStore, type PanelPosition } from "@xyflow/react";
import { MaximizeIcon, MinusIcon, PlusIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/format";
import { FIT } from "./flowChrome";

/**
 * Zoom on buttons, because a wheel over a canvas in a scrolling page is a trap.
 *
 * `island` draws them as the route map's floating bar (§259): one frosted
 * pill with the zoom said between minus and plus, and fit set apart.
 */
export function ZoomButtons({
  position = "top-right",
  island = false,
  onFit,
}: {
  position?: PanelPosition;
  island?: boolean;
  /** What "fit" frames, where the canvas knows better than the whole graph. */
  onFit?: () => void;
}) {
  const flow = useReactFlow();
  const zoom = useStore((state) => state.transform[2]);
  const fit = onFit ?? (() => void flow.fitView(FIT));
  const variant = island ? "ghost" : "outline";
  return (
    // At the foot, lifted clear of React Flow's attribution, which sits there
    // too (`!`: base.css is unlayered and outranks a utility).
    <Panel
      position={position}
      className={cn(
        "flex items-center gap-1",
        position.startsWith("bottom") && "mb-8!",
        island &&
          "gap-0.5 rounded-xl bg-popover/85 p-1 shadow-2xl shadow-black/30 ring-1 ring-foreground/8 backdrop-blur-xl",
      )}
    >
      {island ? (
        <>
          <Button
            variant={variant}
            size="icon-sm"
            onClick={() => void flow.zoomOut()}
            aria-label="Zoom out"
          >
            <MinusIcon />
          </Button>
          <span className="w-11 text-center text-caption font-medium tabular-nums" aria-hidden>
            {Math.round(zoom * 100)}%
          </span>
          <Button
            variant={variant}
            size="icon-sm"
            onClick={() => void flow.zoomIn()}
            aria-label="Zoom in"
          >
            <PlusIcon />
          </Button>
          <span aria-hidden className="mx-0.5 h-4 w-px bg-border" />
        </>
      ) : (
        <>
          <Button
            variant={variant}
            size="icon-sm"
            onClick={() => void flow.zoomIn()}
            aria-label="Zoom in"
          >
            <PlusIcon />
          </Button>
          <Button
            variant={variant}
            size="icon-sm"
            onClick={() => void flow.zoomOut()}
            aria-label="Zoom out"
          >
            <MinusIcon />
          </Button>
        </>
      )}
      <Button
        variant={variant}
        size="icon-sm"
        onClick={fit}
        aria-label="Fit the graph to the frame"
      >
        <MaximizeIcon />
      </Button>
    </Panel>
  );
}
