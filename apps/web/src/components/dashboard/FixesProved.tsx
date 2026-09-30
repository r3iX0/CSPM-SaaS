import type { LucideIcon } from "lucide-react";

import { VERDICT_ICONS } from "@/lib/icons";
import { useCountUp } from "@/lib/motion";
import { cn } from "@/lib/format";

/**
 * Whether anything is being fixed -- counted the only way this product counts
 * a fix: a later scan observed it.
 *
 * Three figures, and the middle one is the honest part. Work somebody has
 * taken on is not work that is done, and it is kept apart from the verified
 * count so a busy week never reads as a safer one. Nobody closes a finding by
 * hand; the scan does, or it stays open.
 */
export function FixesProved({
  verified,
  inProgress,
  open,
}: {
  verified: number;
  inProgress: number;
  open: number;
}) {
  return (
    <section
      aria-labelledby="fixes-proved"
      className="flex flex-col overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <header className="px-5 py-4">
        <h2 id="fixes-proved" className="text-body font-semibold">
          Fixes proved
        </h2>
        <p className="mt-1 text-xs text-muted-foreground">
          A finding closes when a later scan observes the fix. Nobody can close
          one by hand.
        </p>
      </header>
      <dl className="grid flex-1 grid-cols-1 gap-px border-t bg-border sm:grid-cols-3">
        <Cell
          icon={VERDICT_ICONS.pass}
          label="Verified closed · 30 days"
          value={verified}
          className="text-ok"
        />
        <Cell icon={VERDICT_ICONS.pending} label="In progress, not yet proved" value={inProgress} />
        <Cell icon={VERDICT_ICONS.fail} label="Still open" value={open} />
      </dl>
    </section>
  );
}

function Cell({
  icon: Icon,
  label,
  value,
  className,
}: {
  icon: LucideIcon;
  label: string;
  value: number;
  className?: string;
}) {
  const shown = Math.round(useCountUp(value));
  return (
    <div className="flex flex-col gap-2 bg-card px-5 py-4">
      <span
        className="inline-flex size-[22px] items-center justify-center rounded-md bg-muted text-muted-foreground"
        aria-hidden
      >
        <Icon className="size-3" strokeWidth={1.5} />
      </span>
      <dt className="text-caption text-muted-foreground">{label}</dt>
      <dd className={cn("text-page leading-none font-semibold tabular-nums", className)}>
        {shown}
      </dd>
    </div>
  );
}
