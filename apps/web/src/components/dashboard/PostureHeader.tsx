import { Link } from "react-router-dom";
import {
  ArrowRightIcon,
  CheckIcon,
  LoaderIcon,
  PlayIcon,
  TriangleAlertIcon,
} from "lucide-react";

import { Button, buttonVariants } from "@/components/ui/button";
import { useScanWizard } from "@/components/scans/ScanWizardProvider";
import { useIsDemo } from "@/lib/useDemo";
import { cn, formatDateTime } from "@/lib/format";

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
        <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Your cloud security posture, and what CloudGuard could see while
          forming it.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <FreshnessPill
          scannedAt={scannedAt}
          staleHours={staleHours}
          scanning={scanning}
        />
        <Link to="/reports" className={buttonVariants({ variant: "ghost" })}>
          Reports
          <ArrowRightIcon data-icon="inline-end" />
        </Link>
        {/* Starts the scan here, in the wizard the shell mounts, rather than
            linking to the scans page and leaving the button to be found
            again there. While one is running, the wizard offers to follow it. */}
        {!isDemo && (
          <Button onClick={() => scanWizard.start()}>
            <PlayIcon data-icon="inline-start" aria-hidden />
            Scan now
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
      <span className="flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs text-muted-foreground">
        <LoaderIcon className="size-3 animate-spin" aria-hidden />
        Scan in progress
      </span>
    );
  }

  const stale = staleHours !== null && staleHours > STALE_AFTER_HOURS;

  return (
    <span
      className={cn(
        "flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs",
        stale
          ? "border-medium-border bg-medium-bg/50 text-medium"
          : "border-ok-border bg-ok-bg/40 text-ok",
      )}
    >
      {stale ? (
        <TriangleAlertIcon className="size-3" aria-hidden />
      ) : (
        <CheckIcon className="size-3" aria-hidden />
      )}
      {stale ? (
        <>Evidence {Math.round(staleHours ?? 0)} hours old</>
      ) : (
        <>Assessed {scannedAt ? formatDateTime(scannedAt) : "recently"}</>
      )}
    </span>
  );
}
