import { cn, levelStyle } from "@/lib/format";

/**
 * A risk score as a tile, tinted by the level it falls in.
 *
 * The number is what ranks a list of risks, so it leads each row rather than
 * trailing it in grey at the far edge; the tint is the severity scale's own
 * (`levelStyle`), so a 96 and a Critical badge beside it are visibly the same
 * claim. The level is also named in the tile's accessible label, because a
 * colour on its own says nothing to somebody who cannot see it.
 *
 * An UNKNOWN level shows "?" rather than a number, dashed like every other
 * unknown: a score computed over evidence that could not be read is not a
 * figure to rank by.
 */
export function ScoreTile({
  score,
  level,
  className,
}: {
  score: number;
  level: string;
  className?: string;
}) {
  const unknown = level === "UNKNOWN";
  return (
    <span
      className={cn(
        "flex size-10 shrink-0 flex-col items-center justify-center rounded-lg border tabular-nums",
        levelStyle(level),
        className,
      )}
      // `img`, so the label is read: a name on a role-less span is ignored.
      role="img"
      aria-label={
        unknown ? "Risk score: no verdict" : `Risk score ${Math.round(score)}, ${level.toLowerCase()}`
      }
    >
      <span className="text-[15px] leading-none font-semibold" aria-hidden>
        {unknown ? "?" : Math.round(score)}
      </span>
    </span>
  );
}
