import { cn, label } from "@/lib/format";

/**
 * A finding or scan's state.
 *
 * Not the severity scale, and the separation is load-bearing: RESOLVED here
 * means *a scan observed the fix*, while ACCEPTED_RISK means a person decided
 * to live with it. Rendering the second as a success would let a dashboard
 * report risk that was waved through as risk that was fixed.
 *
 * So only a scan's proof gets a colour. Open, in progress and risk accepted
 * are all states a person holds a finding in, and they share the neutral tone;
 * the word tells them apart (DECISIONS.md §144).
 */
export function StatusPill({
  status,
  size = "default",
  className,
}: {
  status: string;
  size?: "default" | "sm";
  className?: string;
}) {
  const tone =
    status === "RESOLVED" || status === "COMPLETED" || status === "DONE"
      ? "bg-ok-bg text-ok border-ok-border"
      : status === "FAILED"
        ? "bg-critical-bg text-critical border-critical-border"
        : status === "PARTIAL"
          ? "bg-medium-bg text-medium border-medium-border"
          : "bg-muted text-muted-foreground border-border";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border font-medium whitespace-nowrap",
        size === "sm" ? "px-1.5 py-0 text-[10.5px] leading-4" : "px-2 py-px text-[11px]",
        tone,
        className,
      )}
    >
      {label(status)}
    </span>
  );
}
