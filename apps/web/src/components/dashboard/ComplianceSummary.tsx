import { Link } from "react-router-dom";

import type { ComplianceFramework } from "@/lib/types";
import { buttonVariants } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/format";
import { useT } from "@/i18n";
import { InfoTip } from "@/components/common/InfoTip";

/**
 * How much of each framework Cleave can speak to -- coverage, never a verdict.
 *
 * The figure is `coverage_ratio`: the share of a framework's catalogued
 * controls that reached a conclusion (passing or failing) at the last scan.
 * It is deliberately not "share passing", which would be a compliance score,
 * and this product does not issue those. Each row prints it as a count out of
 * the framework's controls rather than a percentage, which read as a grade
 * (DECISIONS.md §185); the bar draws the same share.
 */
export function ComplianceSummary({
  frameworks,
  loading,
}: {
  frameworks: ComplianceFramework[] | undefined;
  loading: boolean;
}) {
  const t = useT();
  const rows = Array.isArray(frameworks) ? frameworks.slice(0, LISTED) : [];

  return (
    <section
      aria-labelledby="compliance-summary"
      className="flex flex-col overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <header className="flex items-start justify-between gap-4 px-5 py-4">
        <div>
          <div className="flex items-center gap-1">
            <h2 id="compliance-summary" className="text-body font-semibold">
              Compliance coverage
            </h2>
            <InfoTip label={t.dashboard.complianceExplainLabel}>
              {t.dashboard.complianceExplain}
            </InfoTip>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            What Cleave can speak to, never a verdict.
          </p>
        </div>
        <Link
          to="/compliance"
          className={cn(buttonVariants({ variant: "outline", size: "sm" }), "shrink-0")}
        >
          All frameworks
        </Link>
      </header>

      {loading && (
        <div className="flex flex-col gap-3 border-t px-5 py-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-6 w-full" />
          ))}
        </div>
      )}

      {!loading && rows.length === 0 && (
        <p className="border-t px-5 py-4 text-body text-muted-foreground">
          No framework assessed yet. Coverage appears after the first scan.
        </p>
      )}

      {!loading && rows.length > 0 && (
        <ul className="flex-1 divide-y border-t">
          {rows.map((framework) => (
            <FrameworkRow key={framework.id} framework={framework} />
          ))}
        </ul>
      )}
    </section>
  );
}

/** How many frameworks the panel lists before handing over to the page. */
const LISTED = 5;

/**
 * One framework: its name, how many of its controls reached a conclusion out
 * of how many there are, and that share drawn as a bar. The bar grows by
 * `scaleX`, so a new reading moves it and a mount does not (§167, §178).
 */
function FrameworkRow({ framework }: { framework: ComplianceFramework }) {
  // Null is not zero: a framework nothing has been assessed against has no
  // ratio, and 0% would read as total failure.
  const ratio = framework.coverage_ratio;
  const concluded = ratio === null ? null : Math.round(ratio * framework.control_count);
  const detail =
    concluded === null
      ? "Not assessed yet"
      : `${concluded} of ${framework.control_count} controls reached a conclusion`;
  return (
    <li>
      <Link
        to={`/compliance/${framework.id}`}
        title={detail}
        className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1.5 px-5 py-2.5 transition-colors hover:bg-muted/60 focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring-inset focus-visible:ring-inset"
      >
        <span className="truncate text-body font-medium">{framework.short_name}</span>
        <span className="text-body font-semibold tabular-nums">
          {concluded === null ? "—" : `${concluded}/${framework.control_count}`}
        </span>
        <span className="sr-only">{detail}</span>
        <span className="col-span-2 h-1 overflow-hidden rounded-full bg-muted" aria-hidden>
          <span
            className="block h-full origin-left rounded-full bg-primary transition-transform duration-600 ease-out"
            style={{ transform: `scaleX(${ratio ?? 0})` }}
          />
        </span>
      </Link>
    </li>
  );
}
