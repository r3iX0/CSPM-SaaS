import { m } from "motion/react";

import { drawPath } from "@/lib/motion";
import { cn } from "@/lib/utils";

/**
 * Lucide's check, as a stroke that can draw itself (DECISIONS.md §180, §181).
 *
 * `draw` when the check is news -- a fix just proved, a setup step just
 * finished while the reader watched -- and not otherwise: a check that was
 * already true when the page opened is drawn whole, because it is the state of
 * things rather than something that happened. Reduced motion draws it whole.
 */
export function DrawnCheck({
  draw = false,
  className,
  strokeWidth = 3,
}: {
  draw?: boolean;
  className?: string;
  strokeWidth?: number;
}) {
  return (
    <svg
      viewBox="0 0 24 24"
      className={cn("size-4", className)}
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      {draw ? (
        <m.path d="M20 6 9 17l-5-5" variants={drawPath} initial="initial" animate="animate" />
      ) : (
        <path d="M20 6 9 17l-5-5" />
      )}
    </svg>
  );
}
