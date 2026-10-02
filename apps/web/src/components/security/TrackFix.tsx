import { useMutation, useQueryClient } from "@tanstack/react-query";
import { CheckIcon, WrenchIcon } from "lucide-react";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import type { FindingStatus, RemediationTask } from "@/lib/types";
import { useT } from "@/i18n";
import { taskFor, useMarkDone, useRemediationQueue } from "@/lib/remediation";
import { useIsDemo } from "@/lib/useDemo";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { formatDate, formatEffort } from "@/lib/format";

/**
 * The work, at the foot of the fix: track it, then say it is done.
 *
 * `POST /remediation` existed from the start and nothing called it, so the
 * queue could only ever be empty (DECISIONS.md §41). It sits under the fix,
 * because tracking work is a statement about who is going to do what is
 * written above it -- and since the fix moved into the remediation page's sheet
 * (§202), marking that work done sits here too, the one place the fix is read
 * in full. Neither closes the finding: tracking moves it to IN_PROGRESS, done
 * starts the verification (§18), and only a scan observing the fix resolves it.
 * The caption says so where the button is.
 */
export function TrackFix({
  findingId,
  status,
  effortMinutes,
}: {
  findingId: string;
  status: FindingStatus;
  effortMinutes?: number;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const isDemo = useIsDemo();
  const tasks = useRemediationQueue();
  const task = taskFor(tasks.data, findingId);
  const markDone = useMarkDone();

  const track = useMutation({
    mutationFn: () =>
      api.post<RemediationTask>("/api/v1/remediation", {
        finding_id: findingId,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["remediation"] });
      void queryClient.invalidateQueries({ queryKey: ["finding", findingId] });
      void queryClient.invalidateQueries({ queryKey: ["findings"] });
      toast.success("Added to the remediation queue", {
        description:
          "Prioritised by impact against effort. The finding stays open until a scan observes the fix.",
      });
    },
    onError: (err) =>
      toast.error("Could not track this fix", {
        description: err instanceof ApiError ? err.message : "The API rejected the request.",
      }),
  });

  if (tasks.isLoading) return <Skeleton className="h-9 w-48" />;

  if (task) {
    const open = task.status === "TODO" || task.status === "IN_PROGRESS";
    return (
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="flex items-center gap-2 text-sm text-foreground">
            <WrenchIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
            {open
              ? t.remediation.trackedSince(formatDate(task.created_at))
              : t.remediation.doneOn(formatDate(task.completed_at))}
          </p>
          {open && !isDemo && (
            <Button
              variant="secondary"
              disabled={markDone.isPending}
              onClick={() => markDone.mutate(task.id)}
            >
              {markDone.isPending ? (
                <Spinner data-icon="inline-start" />
              ) : (
                <CheckIcon data-icon="inline-start" aria-hidden />
              )}
              Mark done
            </Button>
          )}
        </div>
        {open && <p className="text-xs text-muted-foreground">{t.remediation.doneNote}</p>}
      </div>
    );
  }

  // Nothing to schedule. A verified fix has no work left in it, and an accepted
  // risk is a decision not to do the work -- offering to queue either would ask
  // the reader to undo a conclusion the product has already recorded. The demo
  // refuses every write, so it is offered nothing to press.
  if (status === "RESOLVED" || status === "ACCEPTED_RISK" || isDemo) return null;

  return (
    <div className="flex flex-wrap items-center gap-3">
      <Button variant="secondary" disabled={track.isPending} onClick={() => track.mutate()}>
        {track.isPending ? (
          <Spinner data-icon="inline-start" />
        ) : (
          <WrenchIcon data-icon="inline-start" aria-hidden />
        )}
        Track this fix
      </Button>
      <p className="text-xs text-muted-foreground">
        Puts it in the remediation queue
        {effortMinutes ? ` as ${formatEffort(effortMinutes)} of work` : ""}, ranked against
        everything else open. It does not close the finding — a scan does.
      </p>
    </div>
  );
}
