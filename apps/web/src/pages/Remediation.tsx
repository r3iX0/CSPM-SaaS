import {
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { WrenchIcon } from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { Dashboard, FindingDetail, RemediationTask } from "@/lib/types";
import { useT } from "@/i18n";
import { HelpPopover } from "@/components/common/HelpPopover";
import { AgeingStrip } from "@/components/remediation/AgeingStrip";
import { RemediationBoard, type Lane } from "@/components/remediation/Board";
import { RemediationTiles } from "@/components/remediation/StatTiles";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import { buttonVariants } from "@/components/ui/button";

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
      api.patch<RemediationTask & { note?: string }>(
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
          "CloudGuard will check the environment and close the finding once the change appears.",
      });
    },
    onError: (err) =>
      toast.error("Could not update this task", {
        description:
          err instanceof Error ? err.message : "The API rejected the change.",
      }),
  });

  /**
   * The estate's own numbers, for the two tiles that are not about this board.
   *
   * Under the key the overview already uses, so a reader arriving from it pays
   * nothing: a queue reporting only on its own cards can sit empty and serene
   * over an environment with eleven open risks in it.
   */
  const posture = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api.get<Dashboard>("/api/v1/dashboard").then((r) => r.data),
    staleTime: 30_000,
    retry: false,
  });

  const tasks = data ?? [];
  const findingOf = (task: RemediationTask) =>
    findings.find((q) => q.data?.id === task.finding_id)?.data;

  /**
   * Which column each task is in.
   *
   * `DONE` is not "fixed": it is a claim that the work was deployed, and it
   * waits in "Awaiting a scan" until a scan stops finding the problem. Only
   * the finding's own status can move a card into "Verified fixed", which is
   * what makes that column impossible to reach by hand.
   */
  const lanes: Record<Lane, RemediationTask[]> = {
    TO_FIX: [],
    IN_PROGRESS: [],
    AWAITING_SCAN: [],
    VERIFIED: [],
  };
  for (const task of tasks) {
    if (task.status === "CANCELLED") continue;
    const finding = findingOf(task);
    if (finding?.status === "RESOLVED") lanes.VERIFIED.push(task);
    else if (task.status === "DONE") lanes.AWAITING_SCAN.push(task);
    else if (task.status === "IN_PROGRESS") lanes.IN_PROGRESS.push(task);
    else lanes.TO_FIX.push(task);
  }

  const onBoard = lanes.TO_FIX.length + lanes.IN_PROGRESS.length;
  const openRisks = posture.data?.open_finding_count ?? null;
  const cameBack =
    posture.data?.remediation_activity?.reduce(
      (total, week) => total + week.reopened,
      0,
    ) ?? null;

  /** Measured from the problem, not from the paperwork. */
  const raisedAt = [...lanes.TO_FIX, ...lanes.IN_PROGRESS, ...lanes.AWAITING_SCAN].map(
    (task) => {
      const at = findingOf(task)?.first_detected_at;
      return at ? new Date(at).getTime() : null;
    },
  );

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={
          <>
            {t.remediation.title}
            <HelpPopover label="What closes a finding">
              The queue is ordered by impact against effort. Marking work done
              records that somebody did it — only a later scan that stops
              finding the problem closes the finding.
            </HelpPopover>
          </>
        }
        description={
          data ? (
            <>
              <span className="font-mono">{onBoard}</span> of{" "}
              <span className="font-mono">{openRisks ?? "—"}</span> open risk
              {openRisks === 1 ? "" : "s"} are on the board
            </>
          ) : undefined
        }
      />

      {isLoading && <CardsSkeleton />}

      {error && (
        <ErrorState
          title="Could not load the remediation queue"
          detail="CloudGuard could not reach its own API."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      {data && tasks.length === 0 && (
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

      {data && (
        <RemediationTiles
          verified={posture.data?.verified_resolved_last_30_days ?? null}
          open={openRisks}
          inProgress={lanes.IN_PROGRESS.length}
          cameBack={cameBack}
        />
      )}

      {data && tasks.length > 0 && (
        <>
          <RemediationBoard
            lanes={lanes}
            findingOf={findingOf}
            busyId={update.isPending ? update.variables?.id : undefined}
            onMove={(task, status) => update.mutate({ id: task.id, status })}
          />

          <AgeingStrip raisedAt={raisedAt} />
        </>
      )}
    </div>
  );
}
