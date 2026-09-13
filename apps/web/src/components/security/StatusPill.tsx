import { cn, label } from "@/lib/format";
import { STATUS_ICONS } from "@/lib/icons";
import { CircleIcon } from "lucide-react";

/**
 * A finding or scan's state.
 *
 * Not the severity scale, and the separation is load-bearing: RESOLVED here
 * means *a scan observed the fix*, while ACCEPTED_RISK means a person decided
 * to live with it. Rendering the second as a success would let a dashboard
 * report risk that was waved through as risk that was fixed.
 *
 * The icon carries the same distinction in shape, so it survives for a reader
 * who cannot tell the tones apart: a tick for a fix, a shield switched off for
 * a decision to accept.
 */
export function StatusPill({ status }: { status: string }) {
  // Indexed rather than called through `statusIcon`: the hooks lint reads a
  // function's return value rendered as a tag as a component made in render.
  const Icon = STATUS_ICONS[status] ?? CircleIcon;
  const tone =
    status === "RESOLVED" || status === "COMPLETED" || status === "DONE"
      ? "bg-ok-bg text-ok border-ok-border"
      : status === "FAILED"
        ? "bg-critical-bg text-critical border-critical-border"
        : status === "PARTIAL"
          ? "bg-medium-bg text-medium border-medium-border"
          : // A finding says ACCEPTED_RISK and a risk says ACCEPTED; they are
            // the same decision by a person, and the second used to fall
            // through to the neutral tone and read as "no state yet".
            status === "ACCEPTED_RISK" || status === "ACCEPTED"
            ? "bg-unknown-bg text-unknown border-unknown-border"
            : "bg-muted text-muted-foreground border-border";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        tone,
      )}
    >
      <Icon className="size-3 shrink-0" aria-hidden />
      {label(status)}
    </span>
  );
}
