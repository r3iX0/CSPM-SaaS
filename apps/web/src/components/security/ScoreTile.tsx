import { cn, levelStyle } from "@/lib/format";

/**
 * A risk score as a tile, tinted by the level it falls in.
 *
 * The number is what ranks a list of risks, so it leads each row rather than
 * trailing it in grey at the far edge; the tint is the severity scale's own
 * (`levelStyle`), so a 96 and a Critical badge beside it are visibly the same
 * claim. The level is also named in the tile's accessible label, because a
 * colour on its own says nothing to somebody who cannot see it.
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
  return (
    <span
      className={cn(
        "flex size-12 shrink-0 flex-col items-center justify-center rounded-lg border tabular-nums",
        levelStyle(level),
        className,
      )}
      aria-label={`Risk score ${Math.round(score)}, ${level.toLowerCase()}`}
    >
      <span className="text-lg leading-none font-semibold" aria-hidden>
        {Math.round(score)}
      </span>
    </span>
  );
}
