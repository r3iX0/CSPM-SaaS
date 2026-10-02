import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { FindingDetail, RemediationTask } from "@/lib/types";

/** The URL parameter that holds a fix open on the remediation page (DECISIONS.md §202). */
export const FIX_PARAM = "fix";

/** The URL parameter that holds one rule's fix open over every asset it is on (§203). */
export const RULE_PARAM = "rule";

/** Where a finding's fix is read: the remediation page, with its sheet open on it. */
export function fixPath(findingId: string): string {
  return `/remediation?${FIX_PARAM}=${encodeURIComponent(findingId)}`;
}

/**
 * The remediation queue, under the one key every reader of it shares.
 *
 * The finding detail response carries no task, and widening it to say whether
 * a finding is tracked would put a join on the hot path of the page the product
 * is really about (DECISIONS.md §41). Sharing the key means the queue page, the
 * fix sheet and a finding's fix card cost one request between them.
 */
export function useRemediationQueue() {
  return useQuery({
    queryKey: ["remediation"],
    queryFn: () => api.get<RemediationTask[]>("/api/v1/remediation").then((r) => r.data),
    staleTime: 30_000,
    retry: false,
  });
}

/**
 * The task tracking a finding's fix, if one is.
 *
 * A cancelled task is not tracking: the work was called off, and the finding
 * can be picked up again.
 */
export function taskFor(
  tasks: RemediationTask[] | undefined,
  findingId: string,
): RemediationTask | undefined {
  return (Array.isArray(tasks) ? tasks : []).find(
    (row) => row.finding_id === findingId && row.status !== "CANCELLED",
  );
}

/**
 * Marking work done.
 *
 * The API answers a completed task with what happens next -- Cleave will look
 * again, and only an observation closes the finding -- and the toast carries
 * that sentence, because marking work done must never quietly imply the
 * finding is now closed.
 */
export function useMarkDone() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.patch<RemediationTask & { note?: string | null }>(`/api/v1/remediation/${id}`, {
        status: "DONE",
      }),
    onSuccess: ({ data: task }) => {
      void queryClient.invalidateQueries({ queryKey: ["remediation"] });
      void queryClient.invalidateQueries({ queryKey: ["finding", task.finding_id] });
      toast.success("Marked done", {
        description:
          task.note ??
          "Cleave will check the environment and close the finding once the change appears.",
      });
    },
    onError: (err) =>
      toast.error("Could not update this task", {
        description: err instanceof Error ? err.message : "The API rejected the change.",
      }),
  });
}

/** One line of the queue: a task on its own, or every task one rule's fix closes. */
export type QueueItem =
  | { kind: "task"; task: RemediationTask }
  | { kind: "group"; ruleId: string; tasks: RemediationTask[] };

/**
 * The queue, with the tasks one fix closes drawn as one piece of work.
 *
 * Two tasks of one rule are one fix applied twice: the same steps, the same
 * commands with a different name in them. Listed apart they read as two
 * problems, and whoever works the queue does the same reading twice
 * (DECISIONS.md §203). A group takes the place of its highest-ranked task, so
 * the server's order -- open first, by impact against effort (§127) -- still
 * decides where the work sits. A task whose finding has not arrived stays on
 * its own: what rule it is under is not known yet.
 */
export function groupByRule(
  tasks: RemediationTask[],
  findings: ReadonlyMap<string, FindingDetail>,
): QueueItem[] {
  const byRule = new Map<string, RemediationTask[]>();
  for (const task of tasks) {
    const ruleId = findings.get(task.finding_id)?.rule_id;
    if (ruleId === undefined) continue;
    byRule.set(ruleId, [...(byRule.get(ruleId) ?? []), task]);
  }

  const items: QueueItem[] = [];
  const placed = new Set<string>();
  for (const task of tasks) {
    const ruleId = findings.get(task.finding_id)?.rule_id;
    const members = ruleId === undefined ? undefined : byRule.get(ruleId);
    if (ruleId === undefined || members === undefined || members.length < 2) {
      items.push({ kind: "task", task });
    } else if (!placed.has(ruleId)) {
      placed.add(ruleId);
      items.push({ kind: "group", ruleId, tasks: members });
    }
  }
  return items;
}

/** Whether a task is work still to do, as opposed to work claimed or called off. */
export function isOpenTask(task: RemediationTask): boolean {
  return task.status === "TODO" || task.status === "IN_PROGRESS";
}

/**
 * Marking every open task of one fix done.
 *
 * One request per task, sent together: the queue is bounded by work a person
 * created, and a batch endpoint would be a second way to write the same row
 * (§203). Each claim starts its own verification, and the worker scans each
 * subscription once for all of them (§18). A partial failure says how many
 * did not go through rather than hiding them behind the ones that did.
 */
export function useMarkAllDone() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (ids: string[]) =>
      Promise.allSettled(
        ids.map((id) =>
          api.patch<RemediationTask>(`/api/v1/remediation/${id}`, { status: "DONE" }),
        ),
      ),
    onSuccess: (results) => {
      void queryClient.invalidateQueries({ queryKey: ["remediation"] });
      void queryClient.invalidateQueries({ queryKey: ["finding"] });
      const failed = results.filter((result) => result.status === "rejected").length;
      const done = results.length - failed;
      if (failed > 0) {
        toast.error(`Marked ${done} of ${results.length} done`, {
          description: `${failed} could not be updated. They are still open in the queue.`,
        });
        return;
      }
      toast.success(`Marked ${done} done`, {
        description:
          "Cleave will check each subscription shortly, and close every finding whose change appears.",
      });
    },
  });
}

/**
 * Tracking every open finding of one rule that nobody has tracked yet.
 *
 * The same `POST /remediation` a single fix sends, once per finding, for the
 * reason `useMarkAllDone` gives.
 */
export function useTrackAll() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (findingIds: string[]) =>
      Promise.allSettled(
        findingIds.map((id) =>
          api.post<RemediationTask>("/api/v1/remediation", { finding_id: id }),
        ),
      ),
    onSuccess: (results) => {
      void queryClient.invalidateQueries({ queryKey: ["remediation"] });
      void queryClient.invalidateQueries({ queryKey: ["findings"] });
      void queryClient.invalidateQueries({ queryKey: ["finding"] });
      const failed = results.filter((result) => result.status === "rejected").length;
      const tracked = results.length - failed;
      if (failed > 0) {
        toast.error(`Tracked ${tracked} of ${results.length}`, {
          description: `${failed} could not be added to the queue.`,
        });
        return;
      }
      toast.success(`Added ${tracked} to the remediation queue`, {
        description: "Each finding stays open until a scan observes its fix.",
      });
    },
  });
}
