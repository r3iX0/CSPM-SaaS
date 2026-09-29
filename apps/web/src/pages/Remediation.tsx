import {
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { CheckIcon, WrenchIcon } from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { FindingDetail, RemediationTask } from "@/lib/types";
import { useT } from "@/i18n";
import { StatusPill } from "@/components/security/StatusPill";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import { Button, buttonVariants } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { StatStrip } from "@/components/common/StatStrip";
import { useIsDemo } from "@/lib/useDemo";
import { Spinner } from "@/components/ui/spinner";
import { cn, formatDay, formatEffort, resourceTypeLabel } from "@/lib/format";

/**
 * The work queue.
 *
 * "Mark done" records that somebody did the work; it does not resolve the
 * finding, and the page says so where the button is rather than only in the
 * introduction. Only a scan observing the fixed state closes a finding
 * (RULE_ENGINE.md section 3), and a queue that let a person tick a security
 * problem closed would be the one place in this product where saying so made
 * it true.
 */
export function RemediationPage() {
  const t = useT();
  const queryClient = useQueryClient();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["remediation"],
    queryFn: () =>
      api.get<RemediationTask[]>("/api/v1/remediation").then((r) => r.data),
  });

  /**
   * What each task is actually about.
   *
   * `GET /remediation` returns the task and nothing of the finding behind it --
   * no title, no asset, no rule -- so this queue could say only "View finding",
   * and a reader deciding what to work on next had to open every card to learn
   * what the work was. That is an API limitation rather than a UI one, and it
   * is worked around here rather than by widening the endpoint: the finding is
   * read per task under the same cache key its own page uses, so opening one
   * from this list costs no request at all.
   */
  const findings = useQueries({
    queries: (data ?? []).map((task) => ({
      queryKey: ["finding", task.finding_id],
      queryFn: () =>
        api
          .get<FindingDetail>(`/api/v1/findings/${task.finding_id}`)
          .then((r) => r.data),
      staleTime: 60_000,
      retry: false,
    })),
  });

  const update = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      api.patch<RemediationTask & { note?: string | null }>(
        `/api/v1/remediation/${id}`,
        { status },
      ),
    // The API answers a completed task with what happens next -- CloudGuard
    // will look again, and only an observation closes the finding. That
    // sentence used to be discarded, so marking work done gave no feedback at
    // all and quietly implied the finding was now closed.
    onSuccess: ({ data: task }) => {
      queryClient.invalidateQueries({ queryKey: ["remediation"] });
      queryClient.invalidateQueries({ queryKey: ["finding", task.finding_id] });
      toast.success("Marked done", {
        description:
          task.note ??
          "Cleave will check the environment and close the finding once the change appears.",
      });
    },
    onError: (err) =>
      toast.error("Could not update this task", {
        description:
          err instanceof Error ? err.message : "The API rejected the change.",
      }),
  });

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t.remediation.title}
        description={t.remediation.description}
      />

      {isLoading && <CardsSkeleton />}

      {error && (
        <ErrorState
          title="Could not load the remediation queue"
          detail="Cleave could not reach its own API."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      {data && data.length === 0 && (
        <EmptyState
          icon={WrenchIcon}
          title={t.remediation.empty}
          detail="Assign a finding from its detail page to start tracking the work."
          action={
            <Link
              to="/findings"
              className={buttonVariants({ variant: "outline" })}
            >
              Go to findings
            </Link>
          }
        />
      )}

      {data && data.length > 0 && <QueueSummary tasks={data} />}

      {/* One queue, one container. Divided rows read as a list to work down;
          a stack of separate cards read as a pile of separate problems. */}
      {data && data.length > 0 && (
        <div className="divide-y divide-border overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10">
          {data.map((task) => (
            <TaskCard
              key={task.id}
              task={task}
              finding={findings.find((q) => q.data?.id === task.finding_id)?.data}
              marking={update.isPending && update.variables?.id === task.id}
              onDone={() => update.mutate({ id: task.id, status: "DONE" })}
            />
          ))}
          {/* Said where the button is, every time: the one thing a reader
              might assume about "done" is the one thing it does not do. */}
          <p className="bg-muted/60 px-5 py-3 text-xs leading-relaxed text-muted-foreground">
            {t.remediation.doneNote}
          </p>
        </div>
      )}
    </div>
  );
}

/**
 * One job, said as a job.
 *
 * The card this replaces led with two badges and a link reading "View finding",
 * which named the queue's own vocabulary and none of the reader's. What decides
 * whether a task is worked next is what is wrong, on what, and how long it
 * takes -- so the title of the finding is the card, and the badges qualify it.
 */
function TaskCard({
  task,
  finding,
  marking,
  onDone,
}: {
  task: RemediationTask;
  finding: FindingDetail | undefined;
  marking: boolean;
  onDone: () => void;
}) {
  const t = useT();
  const done = task.status === "DONE" || task.status === "CANCELLED";
  const isDemo = useIsDemo();
  const overdue = !done && task.due_date !== null && new Date(task.due_date) < new Date();

  return (
    <div
      className={cn(
        "flex flex-wrap items-center gap-x-6 gap-y-3 px-5 py-3 transition-colors hover:bg-muted/60",
        done && "opacity-70",
      )}
    >
      <div className="flex min-w-0 flex-1 items-center gap-3">
        {/* A fixed column, so titles line up whatever the badge says. */}
        <span className="w-[4.5rem] shrink-0">
          <SeverityBadge level={task.priority} />
        </span>
        <div className="min-w-0">
          {finding ? (
            <Link
              to={`/findings/${task.finding_id}`}
              className={cn(
                "block truncate text-[13.5px] font-medium hover:underline",
                done ? "text-muted-foreground line-through decoration-muted-foreground/50" : "text-foreground",
              )}
            >
              {finding.title}
            </Link>
          ) : (
            // The row keeps its height while the finding arrives, so a queue
            // does not reflow under the reader's cursor.
            <Skeleton className="h-4 w-72 max-w-full" />
          )}
          <p className="mt-0.5 truncate text-[11.5px] text-muted-foreground">
            {finding?.resource
              ? `${finding.resource.name} · ${resourceTypeLabel(finding.resource.resource_type)}`
              : finding
                ? "Tenant-wide — no single asset carries this"
                : " "}
            {/* Why it sits above an equally urgent task: the asset is on a
                route. Counted by the API, and only said when it is true. */}
            {finding && (task.on_routes ?? 0) > 0 && (
              <span className="font-medium text-foreground">
                {" · "}
                {t.remediation.onRoutes(task.on_routes ?? 0)}
              </span>
            )}
          </p>
          {task.notes && (
            <p className="mt-1 text-xs text-muted-foreground">{task.notes}</p>
          )}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-muted-foreground">
        {/* Only a state a person put it in is a pill here; to do is the
            queue itself. Done is work claimed, and says what it waits on:
            the finding closes when a scan sees the fix, or not at all. */}
        {task.status === "IN_PROGRESS" && <StatusPill status={task.status} />}
        {done &&
          (finding?.status === "RESOLVED" ? (
            <StatusPill status="RESOLVED" />
          ) : (
            <span className="inline-flex rounded-full border border-border bg-muted px-2 py-px text-[11px] font-medium">
              {t.remediation.waitingOnScan}
            </span>
          ))}
        <span className="w-14 tabular-nums">{formatEffort(task.estimated_effort_minutes)}</span>
        <span className={cn("w-[130px] tabular-nums", overdue && "font-medium text-critical")}>
          {done && task.completed_at
            ? t.remediation.doneOn(formatDay(task.completed_at))
            : task.due_date
              ? `${overdue ? "Overdue · " : "Due "}${formatDay(task.due_date)}`
              : null}
        </span>
        <span className="flex w-24 justify-end">
          {!done && !isDemo && (
            <Button variant="outline" size="sm" disabled={marking} onClick={onDone}>
              {marking ? (
                <Spinner data-icon="inline-start" />
              ) : (
                <CheckIcon data-icon="inline-start" aria-hidden />
              )}
              Mark done
            </Button>
          )}
        </span>
      </div>
    </div>
  );
}

/**
 * The queue in four numbers, above the queue.
 *
 * What is left, what is moving, what it will cost, and what is late -- the
 * questions somebody opening this page on a Monday is actually asking, which a
 * list of rows answers only if they are all counted by eye.
 */
function QueueSummary({ tasks }: { tasks: RemediationTask[] }) {
  const open = tasks.filter((task) => task.status === "TODO" || task.status === "IN_PROGRESS");
  const moving = tasks.filter((task) => task.status === "IN_PROGRESS").length;
  const minutes = open.reduce((sum, task) => sum + task.estimated_effort_minutes, 0);
  const late = open.filter(
    (task) => task.due_date !== null && new Date(task.due_date) < new Date(),
  ).length;

  return (
    <StatStrip
      stats={[
        { label: "Open", value: open.length },
        { label: "In progress", value: moving },
        { label: "Effort left", value: formatEffort(minutes) },
        { label: "Overdue", value: late, alert: late > 0 },
      ]}
    />
  );
}
