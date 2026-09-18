import { useEffect, useRef } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "motion/react";
import { CheckIcon, RotateCcwIcon, XIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { FindingStatus, ScanDetail } from "@/lib/types";
import { DURATION, EASE_OUT } from "@/lib/motion";
import { cn, formatDateTime } from "@/lib/format";
import { IN_FLIGHT } from "@/components/scans/status";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";

const PHASES = ["Queued", "Reading your environment", "Checking the rule", "Result"] as const;

/** Where a scan status sits among the phases a reader is shown. */
function phaseOf(status: string): number {
  if (status === "QUEUED") return 0;
  if (status === "DISCOVERING") return 1;
  if (IN_FLIGHT.includes(status)) return 2;
  return 3;
}

/**
 * The rescan a reader asked for, followed on the finding it is about.
 *
 * "Rescan to verify" used to end on a toast and leave the reader to come back
 * later and see whether the finding had closed. The verification is the most
 * persuasive moment in the product -- a fix, proved by looking again -- and it
 * happened off-screen. This panel follows the exact scan the request queued
 * (`scan_id` from the rescan endpoint), phase by phase from its real status,
 * and when it ends it re-reads the finding and says what the scan concluded.
 *
 * The verdict is the finding's, never this panel's. A finished scan with the
 * finding still open is "still failing"; resolved is "verified fixed"; a scan
 * that failed proves nothing either way and says so. Nothing here is inferred
 * from elapsed time.
 */
export function FixVerification({
  scanId,
  findingId,
  findingStatus,
  resourceName,
  onRetry,
  onClose,
  retrying,
}: {
  scanId: string;
  findingId: string;
  findingStatus: FindingStatus;
  resourceName: string | null;
  onRetry: () => void;
  onClose: () => void;
  retrying: boolean;
}) {
  const queryClient = useQueryClient();

  const scan = useQuery({
    queryKey: ["scan-detail", scanId],
    queryFn: () => api.get<ScanDetail>(`/api/v1/scans/${scanId}/detail`).then((r) => r.data),
    refetchInterval: (query) => {
      const status = (query.state.data as ScanDetail | undefined)?.status;
      return status && !IN_FLIGHT.includes(status) ? false : 3000;
    },
  });

  const status = scan.data?.status ?? "QUEUED";
  const finished = !IN_FLIGHT.includes(status);
  const phase = phaseOf(status);

  // Once, when the scan ends: the finding's status is what changed, and the
  // verdict below is read from it.
  const settled = useRef(false);
  useEffect(() => {
    if (!finished || settled.current) return;
    settled.current = true;
    void queryClient.invalidateQueries({ queryKey: ["finding", findingId] });
    void queryClient.invalidateQueries({ queryKey: ["findings"] });
    void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
  }, [finished, findingId, queryClient]);

  const failedScan = finished && (status === "FAILED" || status === "CANCELLED");
  const verified = finished && !failedScan && findingStatus === "RESOLVED";
  const stillFailing = finished && !failedScan && findingStatus !== "RESOLVED";

  const tone = verified
    ? "border-ok-border bg-ok-bg"
    : stillFailing
      ? "border-high-border bg-high-bg"
      : failedScan
        ? "border-critical-border bg-critical-bg"
        : "border-border bg-card";

  return (
    <motion.section
      aria-live="polite"
      aria-label="Fix verification"
      initial={{ opacity: 0, y: -6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: DURATION.quick / 1000, ease: EASE_OUT }}
      className={cn("rounded-xl border p-5", tone)}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex min-w-0 items-start gap-3">
          <span
            className={cn(
              "flex size-9 shrink-0 items-center justify-center rounded-full",
              verified && "bg-ok text-background",
              stillFailing && "bg-high text-background",
              failedScan && "bg-critical text-background",
              !finished && "bg-muted text-foreground",
            )}
          >
            {verified && <CheckIcon className="size-4.5" strokeWidth={3} aria-hidden />}
            {(stillFailing || failedScan) && <XIcon className="size-4.5" strokeWidth={3} aria-hidden />}
            {!finished && <Spinner />}
          </span>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-foreground">
              {verified && "Verified fixed"}
              {stillFailing && "Still failing"}
              {failedScan && "The scan could not finish"}
              {!finished && "Checking your fix"}
            </p>
            <p className="mt-0.5 text-sm leading-relaxed text-muted-foreground">
              {verified &&
                `A scan on ${formatDateTime(scan.data?.completed_at ?? null)} looked again and the problem is gone. The finding is closed.`}
              {stillFailing &&
                `The scan finished and the rule still fails${resourceName ? ` on ${resourceName}` : ""}. Check the change was applied to this resource, give it a minute to propagate, and verify again.`}
              {failedScan &&
                (scan.data?.error_message ??
                  "It stopped before it could look at this resource, so it proves nothing either way.")}
              {!finished &&
                "CloudGuard is re-reading the subscription this resource lives in. You can leave this page — the finding closes on its own if the fix took."}
            </p>
          </div>
        </div>
        {finished && (
          <Button variant="ghost" size="icon-sm" aria-label="Dismiss" onClick={onClose}>
            <XIcon aria-hidden />
          </Button>
        )}
      </div>

      <ol className="mt-4 grid grid-cols-4 gap-2" aria-label="Verification progress">
        {PHASES.map((label, index) => {
          const done = index < phase || (index === phase && finished);
          const active = index === phase && !finished;
          return (
            <li key={label} className="flex flex-col gap-1.5">
              <span className="h-1 overflow-hidden rounded-full bg-foreground/10">
                <motion.span
                  className={cn(
                    "block h-full rounded-full",
                    verified ? "bg-ok" : stillFailing ? "bg-high" : failedScan ? "bg-critical" : "bg-foreground",
                  )}
                  initial={false}
                  animate={{ width: done ? "100%" : active ? "50%" : "0%" }}
                  transition={{ duration: DURATION.page / 1000, ease: EASE_OUT }}
                />
              </span>
              <span
                className={cn(
                  "text-[11px]",
                  active || done ? "text-foreground" : "text-muted-foreground",
                )}
              >
                {label}
              </span>
            </li>
          );
        })}
      </ol>

      {(stillFailing || failedScan) && (
        <div className="mt-4">
          <Button size="sm" onClick={onRetry} disabled={retrying}>
            <RotateCcwIcon data-icon="inline-start" aria-hidden />
            Verify again
          </Button>
        </div>
      )}
    </motion.section>
  );
}
