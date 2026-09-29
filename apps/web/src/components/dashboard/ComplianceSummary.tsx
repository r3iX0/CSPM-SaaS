import { Link } from "react-router-dom";

import type { ComplianceFramework } from "@/lib/types";
import { buttonVariants } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/format";

/**
 * How much of each framework Cleave can speak to -- coverage, never a verdict.
 *
 * The figure is `coverage_ratio`: the share of a framework's catalogued
 * controls that reached a conclusion (passing or failing) at the last scan.
 * It is deliberately not "share passing", which would be a compliance score,
 * and this product does not issue those. The count under it says the same
 * thing in controls, so the percentage is never read as a grade.
 */
export function ComplianceSummary({
  frameworks,
  loading,
}: {
  frameworks: ComplianceFramework[] | undefined;
  loading: boolean;
}) {
  const rows = Array.isArray(frameworks) ? frameworks : [];

  return (
    <section
      aria-labelledby="compliance-summary"
      className="flex flex-col overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <header className="flex items-start justify-between gap-4 px-5 py-4">
        <div>
          <h2 id="compliance-summary" className="text-[13.5px] font-semibold">
            Compliance coverage
          </h2>
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
        <div className="grid grid-cols-2 gap-3 border-t px-5 py-4 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-16 w-full" />
          ))}
        </div>
      )}

      {!loading && rows.length === 0 && (
        <p className="border-t px-5 py-4 text-[13px] text-muted-foreground">
          No framework has been assessed yet. Coverage appears once a scan has
          run against the rule catalogue.
        </p>
      )}

      {!loading && rows.length > 0 && (
        // Hairlines drawn by each cell rather than by a gap over a border
        // fill: with fewer frameworks than columns, a gap-filled grid painted
        // the empty places as a solid grey block. The right and bottom lines
        // of the last column and row fall under the card's edge.
        <ul className="-mr-px -mb-px grid grid-cols-1 border-t sm:grid-cols-2 lg:grid-cols-4">
          {rows.map((framework) => {
            // Null is not zero: a framework nothing has been assessed against
            // has no ratio, and 0% would read as total failure.
            const concluded =
              framework.coverage_ratio === null
                ? null
                : Math.round(framework.coverage_ratio * framework.control_count);
            return (
              <li key={framework.id} className="border-r border-b bg-card">
                <Link
                  to={`/compliance/${framework.id}`}
                  className="flex h-full flex-col gap-1 px-5 py-4 transition-colors hover:bg-muted/60 focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring-inset focus-visible:ring-inset"
                >
                  <span className="truncate text-[12.5px] font-medium">
                    {framework.short_name}
                  </span>
                  <span className="text-[19px] leading-tight font-semibold tabular-nums">
                    {framework.coverage_ratio === null
                      ? "—"
                      : `${Math.round(framework.coverage_ratio * 100)}%`}
                  </span>
                  <span className="text-[11.5px] text-muted-foreground tabular-nums">
                    {concluded === null
                      ? "Not assessed yet"
                      : `${concluded} of ${framework.control_count} controls reached a conclusion`}
                  </span>
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
