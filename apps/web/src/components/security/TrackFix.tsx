import { CheckIcon, WrenchIcon } from "lucide-react";

import type { FindingStatus } from "@/lib/types";
import { useT } from "@/i18n";
import {
  isTrackable,
  taskFor,
  useMarkDone,
  useRemediationQueue,
  useTrack,
} from "@/lib/remediation";
import { useIsDemo } from "@/lib/useDemo";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { formatDate, formatEffort } from "@/lib/format";

/**
 * The work on a fix: track it, then say it is done.
 *
 * `POST /remediation` existed from the start and nothing called it, so the
 * queue could only ever be empty (DECISIONS.md §41). Since the fix moved into
 * the remediation page's sheet (§202), marking that work done sits here too.
 * It heads the sheet rather than ending it: at the foot of the steps, the CLI
 * and the Terraform it was a scroll nobody made, and a reader looking for the
 * way to queue a fix concluded there was none (§205). Neither closes the
 * finding: tracking moves it to IN_PROGRESS, done starts the verification
 * (§18), and only a scan observing the fix resolves it. The caption says so
 * where the button is.
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
  const isDemo = useIsDemo();
  const tasks = useRemediationQueue();
  const task = taskFor(tasks.data, findingId);
  const markDone = useMarkDone();
  const track = useTrack();

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

  // Nothing to schedule (`isTrackable`). The demo refuses every write, so it is
  // offered nothing to press.
  if (!isTrackable(status) || isDemo) return null;

  return (
    <div className="flex flex-wrap items-center gap-3">
      <Button
        variant="secondary"
        disabled={track.isPending}
        onClick={() => track.mutate(findingId)}
      >
        {track.isPending ? (
          <Spinner data-icon="inline-start" />
        ) : (
          <WrenchIcon data-icon="inline-start" aria-hidden />
        )}
        {t.remediation.trackThisFix}
      </Button>
      <p className="text-xs text-muted-foreground">
        Puts it in the remediation queue
        {effortMinutes ? ` as ${formatEffort(effortMinutes)} of work` : ""}, ranked against
        everything else open. It does not close the finding — a scan does.
      </p>
    </div>
  );
}
