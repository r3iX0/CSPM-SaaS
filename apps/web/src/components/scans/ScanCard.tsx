import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { Scan, WorkerStatus } from "@/lib/types";
import { useT } from "@/i18n";
import { StatusPill } from "@/components/security/StatusPill";
import { useScanWizard } from "@/components/scans/ScanWizardProvider";
import { DeleteScanConfirm } from "@/components/scans/DeleteScanConfirm";
import { Button } from "@/components/ui/button";
import { IN_FLIGHT } from "@/components/scans/status";
import { useIsDemo } from "@/lib/useDemo";
import { formatDateTime, formatRelative, formatSeconds } from "@/lib/format";
import { RotateCcwIcon, Trash2Icon } from "lucide-react";

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

/**
 * One run: what it found, what it could not read, and what can be done to it.
 *
 * Watching a run, stopping it and reading its steps are the scan wizard's: the
 * row opens it on this scan. The row once carried its own smaller live view,
 * polled on its own clock, and the two drew the same scan differently
 * (DECISIONS.md §154).
 */
export function ScanCard({ scan }: { scan: Scan }) {
  const t = useT();
  const queryClient = useQueryClient();
  const wizard = useScanWizard();
  const running = IN_FLIGHT.includes(scan.status);

  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [replayError, setReplayError] = useState<string | null>(null);

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
    <div className="px-5 py-3">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <div className="flex min-w-0 flex-1 items-center gap-3">
          <StatusPill status={scan.status} />
          <div className="min-w-0">
            <p className="truncate text-[13.5px] font-medium text-foreground tabular-nums">
              {formatDateTime(scan.completed_at ?? scan.started_at ?? scan.created_at)}
            </p>
            <p className="text-[11.5px] text-muted-foreground">
              {formatRelative(scan.completed_at ?? scan.started_at ?? scan.created_at)}
              {scan.trigger === "SCHEDULED" && ` · ${t.scans.scheduled}`}
              {scan.trigger === "MANUAL" && ` · ${t.scans.manualUnknownUser}`}
            </p>
          </div>
          {/* A replay read the database, not the cloud. Left unlabelled it
              sits in the list looking like a scan that went and checked,
              which is the one thing it did not do. */}
          {scan.replay_of_scan_id && (
            <span className="inline-flex shrink-0 items-center rounded-full border border-border bg-muted px-2 py-px text-[11px] font-medium text-muted-foreground">
              {t.scans.replayOfLabel}
            </span>
          )}
        </div>

        <dl className="flex flex-wrap gap-x-6 gap-y-2 text-sm">
          {scan.duration_seconds != null && (
            <Stat label={t.scans.duration} value={formatSeconds(scan.duration_seconds)} />
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
            variant={running ? "secondary" : "ghost"}
            size="sm"
            onClick={() => wizard.watch(scan.id)}
          >
            {running ? t.scans.watch : t.scans.open}
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

      {/* Queued far longer than a worker takes to collect one. A status of
          "Queued" keeps implying imminent work, so the reason has to say
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
          structured breakdown is the wizard's Details tab. */}
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
        <p className="mt-1 text-xs leading-relaxed text-foreground">
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

/** The first sentence of a multi-sentence remedy, for the summary line. */
function firstSentence(text: string): string {
  const cut = text.indexOf(". ");
  return cut === -1 ? text : `${text.slice(0, cut)}.`;
}
