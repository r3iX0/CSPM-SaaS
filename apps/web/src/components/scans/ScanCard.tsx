import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { Scan, ScanDetail, WorkerStatus } from "@/lib/types";
import { useT } from "@/i18n";
import { StatusPill } from "@/components/security/StatusPill";
import { ScanProgress } from "@/components/scans/ScanProgress";
import { ScanDetailPanel } from "@/components/scans/ScanDetailPanel";
import { DeleteScanConfirm } from "@/components/scans/DeleteScanConfirm";
import { Button } from "@/components/ui/button";
import { IN_FLIGHT } from "@/components/scans/status";
import { useIsDemo } from "@/lib/useDemo";
import { cn, formatDateTime, formatRelative, label } from "@/lib/format";
import { ChevronDownIcon, RotateCcwIcon, Trash2Icon } from "lucide-react";

/**
 * The statuses that guarantee a stored snapshot to re-evaluate.
 *
 * Snapshots are written when collection succeeds, so these two are the runs
 * that have one. A FAILED scan may have collected before it fell over and may
 * not have, and offering a button that usually answers "that scan has no
 * stored snapshot" would read as data loss rather than as the ordinary thing
 * it is.
 */
const REPLAYABLE = ["COMPLETED", "PARTIAL"];

/** One run: what it found, what it could not read, and what can be done to it. */
export function ScanCard({ scan }: { scan: Scan }) {
  const t = useT();
  const queryClient = useQueryClient();
  const running = IN_FLIGHT.includes(scan.status);

  const [open, setOpen] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [replayError, setReplayError] = useState<string | null>(null);

  const cancel = useMutation({
    mutationFn: () => api.post<Scan>(`/api/v1/scans/${scan.id}/cancel`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scans"] }),
  });

  const replay = useMutation({
    mutationFn: () => api.post<Scan>(`/api/v1/scans/${scan.id}/replay`),
    onSuccess: () => {
      setReplayError(null);
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    // Surfaced on the card rather than swallowed: the common refusal is that a
    // scan is already running for this connection, which is a thing to wait
    // out and not a fault.
    onError: (err) =>
      setReplayError(
        err instanceof Error ? err.message : "Could not queue the re-evaluation",
      ),
  });

  const remove = useMutation({
    mutationFn: (purge: boolean) => api.del(`/api/v1/scans/${scan.id}?purge_findings=${purge}`),
    onSuccess: () => {
      setConfirmingDelete(false);
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      // Purging changes the findings and the score, so those go too.
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });

  // Nothing in the demo is re-run or removed: it is a recording others share.
  const isDemo = useIsDemo();
  const replayable = !running && REPLAYABLE.includes(scan.status) && !isDemo;
  const helpId = `scan-replay-help-${scan.id}`;

  return (
    <div className="px-4 py-3.5 sm:px-5">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <div className="flex min-w-0 flex-1 items-center gap-3">
          <StatusPill status={scan.status} />
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-foreground">
              {formatDateTime(scan.completed_at ?? scan.started_at ?? scan.created_at)}
            </p>
            <p className="text-xs text-muted-foreground">
              {formatRelative(scan.completed_at ?? scan.started_at ?? scan.created_at)}
              {scan.trigger === "SCHEDULED" && ` · ${t.scans.scheduled}`}
              {scan.trigger === "MANUAL" && ` · ${t.scans.manualUnknownUser}`}
            </p>
          </div>
          {/* A replay read the database, not the cloud. Left unlabelled it
              sits in the list looking like a scan that went and checked,
              which is the one thing it did not do. */}
          {scan.replay_of_scan_id && (
            <span className="inline-flex shrink-0 items-center rounded-full border border-border bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">
              {t.scans.replayOfLabel}
            </span>
          )}
        </div>

        <dl className="flex flex-wrap gap-x-6 gap-y-2 text-sm">
          {scan.duration_seconds != null && (
            <Stat label={t.scans.duration} value={formatDuration(scan.duration_seconds)} />
          )}
          <Stat label={t.scans.resources} value={scan.resource_count} />
          <Stat label={t.scans.rules} value={scan.rule_count} />
          <Stat
            label={scan.evaluation_only ? t.scans.wouldHaveFound : t.scans.findings}
            value={scan.finding_count}
          />
        </dl>

        {/* Actions sit at the end of the row, quiet until wanted. The long
            explanation of what re-evaluating does is the button's description
            -- read by assistive tech and shown on hover -- rather than a
            paragraph printed under every run in the history. */}
        <div className="flex items-center justify-end gap-1 sm:w-64">
          {running && (
            <Button
              variant="secondary"
              size="sm"
              onClick={() => cancel.mutate()}
              disabled={cancel.isPending}
            >
              {cancel.isPending ? t.scans.cancelling : t.scans.cancel}
            </Button>
          )}
          {/* Offered on any run that stored a capture, including a replay --
              the endpoint resolves that back to the scan that collected, so
              re-evaluating twice is the ordinary thing a reader expects and
              not an error. */}
          {replayable && (
            <>
              <Button
                variant="ghost"
                size="sm"
                title={t.scans.replayHelp}
                aria-describedby={helpId}
                onClick={() => replay.mutate()}
                disabled={replay.isPending}
              >
                <RotateCcwIcon data-icon="inline-start" aria-hidden />
                {replay.isPending ? t.scans.replayQueueing : t.scans.replay}
              </Button>
              <span id={helpId} className="sr-only">
                {t.scans.replayHelp}
              </span>
            </>
          )}
          <Button
            variant="ghost"
            size="sm"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? t.scans.hideDetails : t.scans.details}
            <ChevronDownIcon
              data-icon="inline-end"
              aria-hidden
              className={cn("transition-transform", open && "rotate-180")}
            />
          </Button>
          {!running && !isDemo && (
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label={t.scans.deleteScan}
              title={t.scans.deleteScan}
              className="text-muted-foreground hover:bg-critical-bg hover:text-critical"
              onClick={() => setConfirmingDelete(true)}
            >
              <Trash2Icon aria-hidden />
            </Button>
          )}
        </div>
      </div>

      {running && (
        <div className="mt-3">
          <LiveProgress scanId={scan.id} status={scan.status} />
        </div>
      )}

      {/* What a replay's numbers are allowed to mean. The two cases differ
          in the only way that matters -- whether any finding moved -- and a
          reader cannot tell them apart from the counters. */}
      {scan.replay_of_scan_id && !running && (
        <div
          className={
            scan.evaluation_only
              ? "mt-3 rounded-lg border border-medium-border bg-medium-bg px-3 py-2"
              : "mt-3 rounded-lg border border-ok-border bg-ok-bg px-3 py-2"
          }
        >
          <p
            className={
              scan.evaluation_only ? "text-xs font-medium text-medium" : "text-xs font-medium text-ok"
            }
          >
            {scan.evaluation_only ? t.scans.replayAdvisoryTitle : t.scans.replayCurrentTitle}
          </p>
          <p className="mt-1 text-xs leading-relaxed text-foreground">
            {scan.evaluation_only ? t.scans.replayAdvisoryDetail : t.scans.replayCurrentDetail}
          </p>
        </div>
      )}

      {/* Queued far longer than a worker takes to collect one. The progress
          bar above keeps implying imminent work, so the reason has to say
          otherwise -- this is almost always no worker running at all. */}
      {scan.stuck_in_queue && <StuckNote />}

      {/* Zero resources reads as a failure and is usually not one. The engine
          already knows which: a category that errored is recorded in
          collection_errors, so anything not listed there returned
          successfully and was simply empty. Saying so separates "nothing to
          assess" from "could not look", which the counters alone cannot. */}
      {!running && scan.status !== "FAILED" && scan.resource_count === 0 && (
        <div className="mt-3 rounded-lg border bg-muted/40 px-3 py-2">
          <p className="text-xs font-medium text-foreground">{t.scans.nothingFound}</p>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            {Object.keys(scan.collection_errors).length > 0
              ? t.scans.nothingFoundPartial
              : t.scans.nothingFoundHelp}
          </p>
        </div>
      )}

      {replayError && (
        <p className="mt-3 rounded-lg border border-high-border bg-high-bg px-3 py-2 text-xs text-high">
          {replayError}
        </p>
      )}

      {/* Mounted only while it is being asked, so the count of purgeable
          findings is fetched for the one scan under the pointer rather than
          for every run on the page. */}
      {confirmingDelete && (
        <DeleteScanConfirm
          scanId={scan.id}
          open={confirmingDelete}
          busy={remove.isPending}
          onCancel={() => setConfirmingDelete(false)}
          onConfirm={(purge) => remove.mutate(purge)}
        />
      )}

      {scan.error_message && (
        <p className="mt-3 rounded-lg border border-critical-border bg-critical-bg px-3 py-2 text-sm text-critical">
          {scan.error_message}
        </p>
      )}

      {/* A summary, not the full text of every failure. The reasons are
          sentences long and there is one per subscription per category, which
          on a tenant-wide scan turns the row into a wall nobody reads. The
          structured breakdown lives in Details. */}
      {Object.keys(scan.collection_errors).length > 0 && (
        <div className="mt-3 rounded-lg border border-medium-border bg-medium-bg px-3 py-2">
          <p className="text-xs font-medium text-medium">{t.scans.partial}</p>
          <ul className="mt-1.5 flex flex-col gap-0.5">
            {Object.entries(scan.collection_errors)
              .slice(0, 3)
              .map(([scope, reason]) => (
                <li key={scope} className="text-xs text-foreground">
                  <strong>{scope}</strong>
                  <span className="text-muted-foreground"> — {firstSentence(reason)}</span>
                </li>
              ))}
          </ul>
          {Object.keys(scan.collection_errors).length > 3 && (
            <p className="mt-1 text-xs text-muted-foreground">
              and {Object.keys(scan.collection_errors).length - 3} more
            </p>
          )}
        </div>
      )}

      {open && (
        <div className="mt-3">
          <ScanDetailPanel scanId={scan.id} />
        </div>
      )}
    </div>
  );
}

/**
 * Progress, read from the steps the scan is actually made of.
 *
 * Polled separately from the scan list and only while something is running. The
 * list refetches every two seconds to keep a status current; this reads a
 * second endpoint per open scan, and doing that for a page of finished scans
 * would be a request per card per tick for information that cannot change.
 */
function LiveProgress({ scanId, status }: { scanId: string; status: string }) {
  const detail = useQuery({
    queryKey: ["scan-detail", scanId],
    queryFn: () => api.get<ScanDetail>(`/api/v1/scans/${scanId}/detail`).then((r) => r.data),
    refetchInterval: 3000,
  });

  const stages = detail.data?.stages ?? [];

  return (
    <div className="rounded-lg border bg-muted/30 p-3">
      {stages.length > 0 ? (
        <ScanProgress stages={stages} />
      ) : (
        // Before PLAN has claimed anything there are no steps to show, and the
        // status is the only honest thing to say.
        <p className="text-xs text-muted-foreground">{label(status)}</p>
      )}
    </div>
  );
}

/**
 * Why a scan is not moving, checked rather than guessed.
 *
 * `stuck_in_queue` is inferred from elapsed time, which is only ever a
 * suspicion. This asks the broker how many workers answer, which turns it into
 * a fact -- and the fact matters, because the failure looks like success from
 * every other angle: the worker service reports Online, passes health checks,
 * and is simply running the wrong process.
 *
 * Queried only once a scan already looks stuck. A broker round trip on every
 * poll would be a cost paid by every healthy deployment.
 */
function StuckNote() {
  const t = useT();
  const status = useQuery({
    queryKey: ["worker-status"],
    queryFn: () => api.get<WorkerStatus>("/api/v1/scans/worker-status").then((r) => r.data),
    staleTime: 30_000,
  });

  return (
    <div className="mt-3 rounded-lg border border-high-border bg-high-bg px-3 py-2">
      <p className="text-xs font-medium text-high">{t.scans.stuckTitle}</p>
      <p className="mt-1 text-xs leading-relaxed text-foreground">
        {status.data ? status.data.detail : t.scans.stuckDetail}
      </p>
      {status.data && status.data.workers === 0 && (
        <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
          {t.scans.stuckDetail}
        </p>
      )}
    </div>
  );
}

function Stat({ label: text, value }: { label: string; value: number | string }) {
  return (
    <div className="min-w-14">
      <dt className="text-[11px] text-muted-foreground">{text}</dt>
      <dd className="font-medium tabular-nums text-foreground">{value}</dd>
    </div>
  );
}

/** Human duration. Minutes and seconds, because scans are minutes-long. */
function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return `${minutes}m ${String(rest).padStart(2, "0")}s`;
}

/** The first sentence of a multi-sentence remedy, for the summary line. */
function firstSentence(text: string): string {
  const cut = text.indexOf(". ");
  return cut === -1 ? text : `${text.slice(0, cut)}.`;
}
