import { useT } from "@/i18n";
import type { ControlStatus } from "@/lib/types";
import { cn, controlStatusStyle, label } from "@/lib/format";
/**
 * Shared compliance chrome.
 *
 * The bar and the pill live together because they encode the same judgement:
 * which statuses count as *knowing something*. Splitting them across two files
 * is how a green segment and a green pill eventually come to disagree.
 */

/** Segment order, worst first — the same reading order as the findings list. */
const SEGMENTS: { status: ControlStatus; className: string }[] = [
  { status: "FAILING", className: "bg-critical" },
  { status: "INCONCLUSIVE", className: "bg-unknown" },
  { status: "PASSING", className: "bg-ok" },
  { status: "NOT_ASSESSED", className: "bg-muted-foreground/50" },
  { status: "NOT_COVERED", className: "bg-muted-foreground/20" },
];

export function CoverageBar({
  counts,
  total,
}: {
  counts: Record<ControlStatus, number>;
  total: number;
}) {
  if (total === 0) return null;

  return (
    <div>
      <StatusBar counts={counts} total={total} />
      <StatusLegend counts={counts} className="mt-2" />
    </div>
  );
}

/**
 * A set of controls divided by status, worst first, as one bar.
 *
 * Drawn the same for a framework and for one of its sections, so a section's
 * row and the framework's own bar read in one vocabulary (DECISIONS.md §206).
 * The bar is a picture of the counts said beside it, never their only
 * statement, so it is hidden from assistive technology.
 */
export function StatusBar({
  counts,
  total,
  className,
}: {
  counts: Partial<Record<ControlStatus, number>>;
  total: number;
  className?: string;
}) {
  if (total === 0) return null;
  return (
    <div
      className={cn("flex h-2 w-full overflow-hidden rounded-full bg-muted", className)}
      aria-hidden="true"
    >
      {SEGMENTS.map(({ status, className: tone }) => {
        const count = counts[status] ?? 0;
        if (count === 0) return null;
        return (
          <div
            key={status}
            className={tone}
            style={{ width: `${(count / total) * 100}%` }}
            title={`${label(status)}: ${count}`}
          />
        );
      })}
    </div>
  );
}

/**
 * What each colour of a `StatusBar` is, with its count where one is given.
 *
 * Without counts it is the key to a set of bars -- every status, so a colour
 * never has to be guessed from a row that happens to lack it.
 */
export function StatusLegend({
  counts,
  className,
}: {
  counts?: Partial<Record<ControlStatus, number>>;
  className?: string;
}) {
  const t = useT();
  return (
    <div className={cn("flex flex-wrap gap-x-4 gap-y-1", className)}>
      {SEGMENTS.map(({ status, className: tone }) => {
        const count = counts?.[status];
        if (counts && !count) return null;
        return (
          <span
            key={status}
            className="flex items-center gap-1.5 text-caption text-muted-foreground"
            title={t.compliance.statusHelp[status]}
          >
            <span className={cn("h-2 w-2 rounded-full", tone)} aria-hidden="true" />
            {count === undefined ? label(status) : `${count} ${label(status).toLowerCase()}`}
          </span>
        );
      })}
    </div>
  );
}

export function ControlStatusPill({ status }: { status: ControlStatus }) {
  const t = useT();
  return (
    <span
      title={t.compliance.statusHelp[status]}
      className={cn(
        "inline-flex shrink-0 items-center rounded-full border px-2 py-0.5 text-xs font-medium",
        controlStatusStyle(status),
      )}
    >
      {label(status)}
    </span>
  );
}

/**
 * The disclaimer. Shown on every compliance screen, never collapsed behind a
 * "learn more" — the whole page invites a reading this product cannot support,
 * and the correction has to travel with it.
 */
export function EvidenceNotice() {
  const t = useT();
  return (
    <p className="rounded-lg border border-border bg-muted/40 px-4 py-3 text-xs leading-relaxed text-muted-foreground">
      {t.compliance.notALegalClaim}
    </p>
  );
}
