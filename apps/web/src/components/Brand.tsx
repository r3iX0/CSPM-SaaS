import { useT } from "@/i18n";
import { cn } from "@/lib/format";

/**
 * The cut mark: one line, severed. The left half is the route as it stood, in
 * the text colour; the right half is what is left once the link is cut, in the
 * brand. It is what the product does -- find the one link that, cut, closes the
 * most routes -- drawn in two strokes (DECISIONS.md §144).
 */
export function CleaveMark({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      className={cn("size-6", className)}
      fill="none"
      strokeWidth="2"
      strokeLinecap="round"
      aria-hidden="true"
    >
      <line x1="1.5" y1="17" x2="9" y2="9.5" className="stroke-foreground" />
      <line x1="15" y1="14.5" x2="22.5" y2="7" className="stroke-primary" />
    </svg>
  );
}

/**
 * The mark and the name. Lowercase is the wordmark's typography, not the name:
 * the text is `app.name` and a screen reader reads "Cleave".
 */
export function Wordmark({
  className,
  markClassName,
  labelClassName,
}: {
  className?: string;
  markClassName?: string;
  labelClassName?: string;
}) {
  const t = useT();
  return (
    <span className={cn("flex items-center gap-2", className)}>
      <CleaveMark className={cn("shrink-0", markClassName)} />
      <span
        className={cn(
          "truncate text-base font-semibold tracking-[-0.045em] lowercase",
          labelClassName,
        )}
      >
        {t.app.name}
      </span>
    </span>
  );
}
