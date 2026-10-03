import { CheckIcon, PlayIcon, RotateCcwIcon, WrenchIcon, XIcon } from "lucide-react";

import type { FindingStatus } from "@/lib/types";
import { useT } from "@/i18n";
import {
  isOpenTask,
  isTrackable,
  memberName,
  taskFor,
  useAssignees,
  useMarkDone,
  useRemediationQueue,
  useTrack,
  useUpdateTask,
  type TaskChange,
} from "@/lib/remediation";
import { useIsDemo } from "@/lib/useDemo";
import { SelectField } from "@/components/common/SelectField";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
 *
 * Tracked work is worked here too: started, handed to a member, given a due
 * date, reopened when it was marked done too soon, and dropped from the queue
 * when nobody will do it (§208). Each was a field the API always accepted and
 * nothing in the app could send.
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
  const update = useUpdateTask();
  const track = useTrack();
  const assignees = useAssignees();

  if (tasks.isLoading) return <Skeleton className="h-9 w-48" />;

  if (task) {
    const open = isOpenTask(task);
    const busy = markDone.isPending || update.isPending;
    const change = (next: TaskChange) => update.mutate({ id: task.id, change: next });
    return (
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="flex items-center gap-2 text-sm text-foreground">
            <WrenchIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
            {open
              ? t.remediation.trackedSince(formatDate(task.created_at))
              : t.remediation.doneOn(formatDate(task.completed_at))}
          </p>
          {!isDemo && (
            <div className="flex flex-wrap items-center gap-2">
              {task.status === "TODO" && (
                <Button
                  variant="outline"
                  disabled={busy}
                  onClick={() => change({ status: "IN_PROGRESS" })}
                >
                  <PlayIcon data-icon="inline-start" aria-hidden />
                  {t.remediation.start}
                </Button>
              )}
              {open ? (
                <Button
                  variant="secondary"
                  disabled={busy}
                  onClick={() => markDone.mutate(task.id)}
                >
                  {markDone.isPending ? (
                    <Spinner data-icon="inline-start" />
                  ) : (
                    <CheckIcon data-icon="inline-start" aria-hidden />
                  )}
                  Mark done
                </Button>
              ) : (
                <Button
                  variant="outline"
                  disabled={busy}
                  onClick={() => change({ status: "TODO" })}
                >
                  <RotateCcwIcon data-icon="inline-start" aria-hidden />
                  {t.remediation.reopen}
                </Button>
              )}
            </div>
          )}
        </div>
        {open && (
          <div className="flex flex-wrap items-end gap-x-4 gap-y-3">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor={`owner-${task.id}`} className="text-caption text-muted-foreground">
                {t.remediation.owner}
              </Label>
              <SelectField
                id={`owner-${task.id}`}
                value={task.assigned_to ?? ""}
                disabled={isDemo || busy}
                onValueChange={(value) => change({ assigned_to: value === "" ? null : value })}
                ariaLabel={t.remediation.owner}
                size="default"
                className="w-56"
                fallbackLabel={() => memberName(undefined)}
                options={[
                  { value: "", label: t.remediation.unassigned },
                  ...(assignees.data ?? []).map((member) => ({
                    value: member.user_id,
                    label: memberName(member),
                  })),
                ]}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor={`due-${task.id}`} className="text-caption text-muted-foreground">
                {t.remediation.due}
              </Label>
              <Input
                id={`due-${task.id}`}
                type="date"
                className="h-8 w-fit"
                disabled={isDemo || busy}
                value={task.due_date ?? ""}
                onChange={(event) => change({ due_date: event.target.value || null })}
              />
            </div>
            {!isDemo && (
              <Button
                variant="ghost"
                size="sm"
                className="text-muted-foreground"
                disabled={busy}
                onClick={() => change({ status: "CANCELLED" })}
              >
                <XIcon data-icon="inline-start" aria-hidden />
                {t.remediation.stopTracking}
              </Button>
            )}
          </div>
        )}
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
