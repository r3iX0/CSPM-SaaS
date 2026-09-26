import type { ReactNode } from "react";
import { CircleHelpIcon, MoveRightIcon } from "lucide-react";

import { FACTOR_ICONS, RISK_KIND_ICONS } from "@/lib/icons";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";

/** One mark a canvas draws, and the word for it. */
export interface LegendItem {
  mark: ReactNode;
  label: string;
}

/**
 * The marks a graph draws, each once with its word, and the rest of how to
 * read it behind a question mark (DECISIONS.md §136).
 *
 * Every canvas has one -- the estate map, the neighbourhood and the route map
 * -- built from this component and the marks below, so one glyph means one
 * thing wherever it is drawn. How to read a graph was a paragraph under the
 * canvas, which is the one place a legend is not read; the legend sits above.
 */
export function GraphLegend({
  items,
  label,
  children,
}: {
  items: LegendItem[];
  /** The question mark's name: "How to read the map". */
  label: string;
  /** What the question mark opens. */
  children: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
      {items.map((item) => (
        <span key={item.label} className="flex items-center gap-1">
          {item.mark}
          {item.label}
        </span>
      ))}
      <Popover>
        <PopoverTrigger
          render={
            <Button variant="ghost" size="icon-sm" aria-label={label}>
              <CircleHelpIcon />
            </Button>
          }
        />
        <PopoverContent align="end" className="w-80 text-xs leading-relaxed">
          {children}
        </PopoverContent>
      </Popover>
    </div>
  );
}

const Exposure = FACTOR_ICONS.exposure;
const Sensitive = FACTOR_ICONS.dataSensitivity;
const Route = RISK_KIND_ICONS.ATTACK_PATH;

/**
 * The marks, drawn as the canvases draw them. Glyphs come from `lib/icons`
 * (§86); the lines are hand-drawn, as a one-off visual is.
 */
export const MARKS = {
  exposure: <Exposure className="size-3.5 text-high" aria-hidden />,
  exposureUnknown: <Exposure className="size-3.5 text-unknown opacity-60" aria-hidden />,
  sensitive: <Sensitive className="size-3.5 text-high" aria-hidden />,
  routes: <Route className="size-3.5 text-foreground" aria-hidden />,
  findings: (
    <span aria-hidden className="rounded border px-1 leading-4 font-medium">
      3
    </span>
  ),
  onRoute: <MoveRightIcon className="size-3.5 text-foreground" aria-hidden />,
  /** A dashed box: counted, not drawn. */
  counted: (
    <span
      aria-hidden
      className="inline-block h-2.5 w-4 rounded-[2px] border border-dashed border-foreground/60"
    />
  ),
  /** A thin line and a thick one: the thicker, the more routes it closes. */
  weight: (
    <svg aria-hidden viewBox="0 0 18 10" className="h-2.5 w-4.5 text-foreground">
      <line x1="0" y1="2" x2="18" y2="2" stroke="currentColor" strokeWidth="1" />
      <line x1="0" y1="7.5" x2="18" y2="7.5" stroke="currentColor" strokeWidth="3" />
    </svg>
  ),
  /** Dashed, in the colour that means "this makes it better": a link cut. */
  cut: (
    <svg aria-hidden viewBox="0 0 18 4" className="h-1 w-4.5 text-ok">
      <line
        x1="0"
        y1="2"
        x2="18"
        y2="2"
        stroke="currentColor"
        strokeWidth="2"
        strokeDasharray="4 3"
      />
    </svg>
  ),
  /** A greyed box: out of reach once the link is cut. */
  closed: (
    <span
      aria-hidden
      className="inline-block h-2.5 w-4 rounded-[2px] border border-foreground/25 bg-muted-foreground/20"
    />
  ),
} satisfies Record<string, ReactNode>;
