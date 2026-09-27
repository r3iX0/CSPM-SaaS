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
        "inline-flex max-w-full items-stretch overflow-x-auto rounded-[9px] border border-border bg-card",
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
            // The chosen slice is the brand's soft fill with a 2px rule along
            // its foot, the way a selected tab reads; the rest are muted words
            // divided by a hairline.
            className={cn(
              "shrink-0 border-l border-border px-3 py-1.5 text-[12.5px] whitespace-nowrap transition-colors outline-none first:border-l-0",
              "focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:ring-inset",
              active
                ? "bg-primary-soft font-medium text-foreground shadow-[inset_0_-2px_0_var(--primary)]"
                : "text-muted-foreground hover:bg-muted/60 hover:text-foreground",
            )}
          >
            {segment.label}
          </button>
        );
      })}
    </div>
  );
}
