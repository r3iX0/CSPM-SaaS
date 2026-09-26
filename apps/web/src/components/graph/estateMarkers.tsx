import type { EstateBox } from "@/lib/types";
import { cn, levelStyle } from "@/lib/format";
import { FACTOR_ICONS } from "@/lib/icons";

/**
 * The marks a box on the estate map carries, shared by the canvas and the
 * map's contents list.
 *
 * Its own module, not part of `EstateCanvas`, because that one is a lazy chunk
 * holding React Flow: the contents list renders before the canvas has loaded,
 * and importing the markers from the canvas would pull React Flow into the
 * page's own bundle.
 */

const LEVEL_TEXT: Record<string, string> = {
  CRITICAL: "text-critical",
  HIGH: "text-high",
};

/**
 * Ways in, sensitive data and open findings, counted.
 *
 * The neighbourhood's markers, with a number wherever a box holds more than
 * one asset: a globe for assets a route may start from, a cylinder for ones it
 * may end at, and open findings tinted by the worst. Attack paths are counted
 * on the panel's link to them, not here (DECISIONS.md §138). Each carries its
 * meaning as screen-reader text, which is also what a box's link is named from.
 */
export function Markers({ box, className }: { box: EstateBox; className?: string }) {
  const Exposure = FACTOR_ICONS.exposure;
  const Sensitive = FACTOR_ICONS.dataSensitivity;
  const single = box.kind === "asset";
  const { open, worst } = box.findings;

  return (
    <span
      className={cn(
        "flex shrink-0 items-center gap-1.5 text-[10px] text-muted-foreground",
        className,
      )}
    >
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
