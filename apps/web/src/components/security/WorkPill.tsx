import type { WorkState } from "@/lib/remediation";
import { useT } from "@/i18n";
import { cn } from "@/lib/format";

/**
 * Where a tracked fix has got to (`workState`, DECISIONS.md §208).
 *
 * Drawn like `StatusPill`, and coloured by the same rule: only a scan's
 * verdict gets a colour. Fixed is green because a scan saw it; still failing is
 * red because scans kept looking and disagreed; could not verify is dashed,
 * because the evidence never arrived and that is not the person's failure.
 * Everything a person put the task in stays neutral, and the word tells them
 * apart.
 */
export function WorkPill({ state, className }: { state: WorkState; className?: string }) {
  const t = useT();
  const tone =
    state === "fixed"
      ? "bg-ok-bg text-ok border-ok-border"
      : state === "still_failing"
        ? "bg-critical-bg text-critical border-critical-border"
        : state === "unverified"
          ? "bg-unknown-bg text-unknown border-unknown-border border-dashed"
          : "bg-muted text-muted-foreground border-border";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-px text-caption font-medium whitespace-nowrap",
        tone,
        className,
      )}
    >
      {t.remediation.work[state]}
    </span>
  );
}
