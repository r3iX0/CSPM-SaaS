import { Link } from "react-router-dom";
import { ArrowRightIcon } from "lucide-react";

import { PageHeader } from "@/components/common/states";
import { buttonVariants } from "@/components/ui/button";
import { formatDateTime } from "@/lib/format";

/** Past this, a reading describes an environment that has since moved on. */
const STALE_AFTER_HOURS = 24;

/**
 * The page's title, and whether anything under it can be trusted today.
 *
 * The freshness state belongs here rather than beside the score, because it
 * qualifies the whole page: a posture is a reading of a moment, and every panel
 * below is only as current as the scan that produced it. Three states, and they
 * are genuinely different news — a scan running now means these numbers are
 * about to change, a stale one means they describe last week.
 *
 * It reads as the header's status line rather than as a pill beside the title
 * (docs/UI_REDESIGN.md §3): the line under a title is where every other screen
 * says what was read and when, and a pill made this page the exception. The
 * epigram it replaces — "Your cloud security posture, and what CloudGuard could
 * see while forming it" — said nothing a reader could act on.
 */
export function PostureHeader({
  scannedAt,
  staleHours,
  scanning,
}: {
  scannedAt: string | null;
  staleHours: number | null;
  scanning: boolean;
}) {
  const stale = !scanning && staleHours !== null && staleHours > STALE_AFTER_HOURS;

  return (
    <PageHeader
      title="Overview"
      dot={scanning ? "running" : stale ? "stale" : "ok"}
      description={
        scanning ? (
          "Scan in progress — these numbers are about to change"
        ) : (
          <>
            Last scan {scannedAt ? formatDateTime(scannedAt) : "not yet run"}
            {staleHours !== null && (
              <>
                {" · evidence "}
                <span className="font-mono">{Math.round(staleHours)}</span> h old
              </>
            )}
          </>
        )
      }
      actions={
        <>
          <Link
            to="/reports"
            className={buttonVariants({ variant: "outline", size: "sm" })}
          >
            Reports
            <ArrowRightIcon data-icon="inline-end" />
          </Link>
          <Link to="/scans" className={buttonVariants({ size: "sm" })}>
            Scan now
          </Link>
        </>
      }
    />
  );
}
