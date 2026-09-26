import { Link } from "react-router-dom";
import { LoaderIcon, PlayIcon, TriangleAlertIcon } from "lucide-react";

import { Button, buttonVariants } from "@/components/ui/button";
import { useScanWizard } from "@/components/scans/ScanWizardProvider";
import { useIsDemo } from "@/lib/useDemo";
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
  const scanWizard = useScanWizard();
  // The demo is a recording; there is nothing to scan and the API refuses to.
  const isDemo = useIsDemo();

  return (
    <header className="flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-[22px] font-semibold tracking-[-0.02em]">Overview</h1>
        {/* "Cloud", not a provider: a sentence stays neutral even where an
            identifier keeps Azure's name (DECISIONS.md §78). */}
        <p className="mt-1.5 max-w-[70ch] text-[13px] text-muted-foreground">
          Your cloud posture, and what Cleave could see while forming it.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2.5">
        <FreshnessPill
          scannedAt={scannedAt}
          staleHours={staleHours}
          scanning={scanning}
        />
        <Link to="/reports" className={buttonVariants({ variant: "outline", size: "sm" })}>
          Export evidence
        </Link>
        {/* Starts the scan here, in the wizard the shell mounts, rather than
            linking to the scans page and leaving the button to be found
            again there. While one is running, the wizard offers to follow it. */}
        {!isDemo && (
          <Button size="sm" onClick={() => scanWizard.start()}>
            <PlayIcon data-icon="inline-start" aria-hidden />
            Run scan
          </Button>
        )}
      </div>
    </header>
  );
}

function FreshnessPill({
  scannedAt,
  staleHours,
  scanning,
}: {
  scannedAt: string | null;
  staleHours: number | null;
  scanning: boolean;
}) {
  if (scanning) {
    return (
      <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <LoaderIcon className="size-3 animate-spin" aria-hidden />
        Scan in progress
      </span>
    );
  }

  const stale = staleHours !== null && staleHours > STALE_AFTER_HOURS;

  // Quiet when the reading is current -- it is a date, not an achievement --
  // and in the caution tone once it describes an environment that has moved on.
  if (stale) {
    return (
      <span className="flex items-center gap-1.5 rounded-full border border-medium-border bg-medium-bg px-2 py-px text-[11.5px] font-medium text-medium">
        <TriangleAlertIcon className="size-3" aria-hidden />
        Evidence {Math.round(staleHours ?? 0)} hours old
      </span>
    );
  }

  return (
    <span className="text-xs text-muted-foreground tabular-nums">
      Assessed {scannedAt ? formatDateTime(scannedAt) : "recently"}
    </span>
  );
}
