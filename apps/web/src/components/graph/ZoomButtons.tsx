import { Panel, useReactFlow, type PanelPosition } from "@xyflow/react";
import { MaximizeIcon, MinusIcon, PlusIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/format";
import { FIT } from "./flowChrome";

/** Zoom on buttons, because a wheel over a canvas in a scrolling page is a trap. */
export function ZoomButtons({ position = "top-right" }: { position?: PanelPosition }) {
  const flow = useReactFlow();
  return (
    // At the foot, lifted clear of React Flow's attribution, which sits there
    // too (`!`: base.css is unlayered and outranks a utility).
    <Panel
      position={position}
      className={cn("flex gap-1", position.startsWith("bottom") && "mb-8!")}
    >
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
