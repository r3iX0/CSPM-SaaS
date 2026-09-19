import { Panel, useReactFlow } from "@xyflow/react";
import { MaximizeIcon, MinusIcon, PlusIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { FIT } from "./flowChrome";

/** Zoom on buttons, because a wheel over a canvas in a scrolling page is a trap. */
export function ZoomButtons() {
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
