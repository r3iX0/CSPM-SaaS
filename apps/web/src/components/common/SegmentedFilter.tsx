import { cn } from "@/lib/format";

export type Segment = { value: string; label: string };

/**
 * A filter whose choices are few enough to show all at once.
 *
 * A select hides its options behind a click, which is right for a long list
 * and wrong for four: the reader cannot see what else there is to look at, and
 * switching between two views costs two clicks each way. Laid out as a row of
 * toggles, every view is named on screen and one click away -- the pattern the
 * issue trackers people already use have taught them to read as "which slice
 * am I looking at".
 *
 * Buttons with `aria-pressed` inside a labelled group rather than a tab list:
 * these narrow one table, they do not swap between panels, and a tab list
 * without panels announces something that is not there.
 */
export function SegmentedFilter({
  label,
  value,
  segments,
  onChange,
  className,
}: {
  label: string;
  value: string;
  segments: Segment[];
  onChange: (value: string) => void;
  className?: string;
}) {
  return (
    <div
      role="group"
      aria-label={label}
      className={cn(
        "inline-flex max-w-full items-center gap-0.5 overflow-x-auto rounded-lg border border-border bg-muted/40 p-0.5",
        className,
      )}
    >
      {segments.map((segment) => {
        const active = segment.value === value;
        return (
          <button
            key={segment.value}
            type="button"
            aria-pressed={active}
            onClick={() => onChange(segment.value)}
            className={cn(
              "h-7 shrink-0 rounded-md px-3 text-sm whitespace-nowrap transition-colors outline-none",
              "focus-visible:ring-3 focus-visible:ring-ring/50",
              active
                ? "bg-background font-medium text-foreground shadow-xs ring-1 ring-border"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            {segment.label}
          </button>
        );
      })}
    </div>
  );
}
