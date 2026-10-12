import { Link } from "react-router-dom";

import type { FixProgress, Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { useFixProgress } from "@/lib/remediation";
import { useCurrentOrganization } from "@/lib/useDemo";
import { cn, formatDay } from "@/lib/format";
import { StatStrip } from "@/components/common/StatStrip";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const WINDOW_DAYS = 30;

/** Whether the organization holds any work to a deadline by policy. */
function hasPolicy(organization: Organization | undefined): boolean {
  const days = organization?.fix_within_days;
  return days !== undefined && Object.values(days).some((value) => value !== null);
}

/**
 * What a scan observed fixed in the last thirty days (DECISIONS.md §225).
 *
 * Finished work used to leave the queue and the page with it, so the one place
 * work is done never showed any being done. Verified fixes only -- a finding
 * closes when a scan sees the change, never when a task is marked done -- and
 * every fix, tracked or not. Each severity's median days from first detection
 * says how fast, and the deadline count says whether fast enough; with no
 * deadlines set it says so rather than reading a hollow "0 of 0".
 */
export function FixProgressSection() {
  const t = useT();
  const progress = useFixProgress(WINDOW_DAYS);

  // A failure here is not worth an error over the queue: the section is left
  // out, and the queue above it still works.
  if (progress.error) return null;

  return (
    <section
      aria-labelledby="fixed-recently"
      className="overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <h2 id="fixed-recently" className="px-5 pt-4 pb-3 text-body font-semibold">
        {t.remediation.progress.title(WINDOW_DAYS)}
      </h2>
      {progress.data ? (
        <ProgressBody progress={progress.data} />
      ) : (
        <div className="flex flex-col gap-2 px-5 pb-4">
          <Skeleton className="h-14 w-full" />
          <Skeleton className="h-4 w-2/3" />
        </div>
      )}
    </section>
  );
}

function ProgressBody({ progress }: { progress: FixProgress }) {
  const t = useT();
  const organization = useCurrentOrganization();
  const held = progress.on_time + progress.late;

  if (progress.fixed === 0) {
    return (
      <p className="border-t px-5 py-4 text-body text-muted-foreground">
        {t.remediation.progress.empty}
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-4 border-t px-5 py-4">
      <StatStrip
        stats={[
          { label: t.remediation.progress.fixed, value: progress.fixed },
          {
            label: t.remediation.progress.onTime,
            value: held > 0 ? t.remediation.progress.onTimeOf(progress.on_time, held) : "—",
            alert: progress.late > 0,
          },
        ]}
      />
      {!hasPolicy(organization) && <NoDeadlines organization={organization} />}

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>{t.remediation.progress.severity}</TableHead>
            <TableHead className="text-right">{t.remediation.progress.count}</TableHead>
            <TableHead className="text-right">{t.remediation.progress.median}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {progress.by_severity
            .filter((row) => row.fixed > 0)
            .map((row) => (
              <TableRow key={row.severity}>
                <TableCell>
                  <SeverityBadge level={row.severity} />
                </TableCell>
                <TableCell className="text-right tabular-nums">
                  {row.fixed}
                  {row.late > 0 && (
                    <span className="ml-2 text-critical">
                      {t.remediation.progress.late(row.late)}
                    </span>
                  )}
                </TableCell>
                <TableCell className="text-right tabular-nums">
                  {row.median_days_to_fix === null
                    ? "—"
                    : t.remediation.progress.days(row.median_days_to_fix)}
                </TableCell>
              </TableRow>
            ))}
        </TableBody>
      </Table>

      <div>
        <h3 className="text-caption font-medium text-muted-foreground">
          {t.remediation.progress.recentTitle}
        </h3>
        <ul className="mt-1 divide-y">
          {progress.recent.map((fix) => (
            <li key={fix.finding_id} className="flex items-center gap-3 py-2">
              <SeverityBadge level={fix.severity} />
              <div className="min-w-0 flex-1">
                <Link
                  to={`/findings/${fix.finding_id}`}
                  className="block max-w-full truncate rounded-sm text-body outline-none hover:underline focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring"
                >
                  {fix.title}
                </Link>
                <p className="text-caption text-muted-foreground">
                  {t.remediation.progress.fixedOn(
                    formatDay(fix.resolved_at),
                    t.remediation.progress.days(Math.round(fix.days_to_fix)),
                  )}
                </p>
              </div>
              {fix.on_time !== null && (
                <span
                  className={cn(
                    "shrink-0 text-caption",
                    fix.on_time ? "text-muted-foreground" : "font-medium text-critical",
                  )}
                >
                  {fix.on_time ? t.remediation.progress.wasOnTime : t.remediation.progress.wasLate}
                </span>
              )}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

/** Said where the deadline count would be, with the way to set them for whoever may. */
function NoDeadlines({ organization }: { organization: Organization | undefined }) {
  const t = useT();
  const editor =
    (organization?.role === "OWNER" || organization?.role === "ADMIN") && !organization.is_demo;
  return (
    <p className="text-caption text-muted-foreground">
      {t.remediation.progress.noDeadlines}{" "}
      {editor && (
        <Link
          to="/settings/general#deadlines"
          className="rounded-sm underline underline-offset-2 outline-none hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring"
        >
          {t.remediation.progress.setDeadlines}
        </Link>
      )}
    </p>
  );
}
