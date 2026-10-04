import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import type {
  Finding,
  FindingDetail,
  FindingStatus,
  Member,
  RemediationTask,
  Severity,
} from "@/lib/types";

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
 * Whether a finding's fix can still be put in the queue.
 *
 * A verified fix has no work left in it, and an accepted risk or a false
 * positive is a decision not to do the work -- offering to queue any of them
 * would ask the reader to undo a conclusion the product has already recorded.
 */
export function isTrackable(status: FindingStatus): boolean {
  return status === "OPEN" || status === "IN_PROGRESS";
}

/**
 * Putting a finding's fix in the queue.
 *
 * One mutation for every place that offers it -- the finding's fix card, the
 * fix sheet's header, and the queue's list of findings nobody has tracked
 * (DECISIONS.md §205) -- so each says the same thing about what tracking does
 * and does not do. `variables` names the finding being tracked, for a list
 * that spins one row's button only.
 */
export function useTrack() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (findingId: string) =>
      api.post<RemediationTask>("/api/v1/remediation", { finding_id: findingId }),
    onSuccess: (_result, findingId) => {
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
  const reopen = useUpdateTask();
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
        // A press in the wrong row is put right in place, and the claim it
        // opened is withdrawn with it (DECISIONS.md §212).
        action: {
          label: "Undo",
          onClick: () => reopen.mutate({ id: task.id, change: { status: "TODO" } }),
        },
      });
    },
    onError: (err) =>
      toast.error("Could not update this task", {
        description: err instanceof Error ? err.message : "The API rejected the change.",
      }),
  });
}

/** What a task can be changed to: a field sent as `null` is cleared (§212). */
export interface TaskChange {
  status?: "TODO" | "IN_PROGRESS" | "CANCELLED";
  assigned_to?: string | null;
  due_date?: string | null;
}

/** What each change is said as, once it has gone through. */
function changeSaid(change: TaskChange): { title: string; description?: string } {
  if (change.status === "IN_PROGRESS") return { title: "Started" };
  if (change.status === "TODO") {
    return { title: "Reopened", description: "Cleave stopped checking for the fix." };
  }
  if (change.status === "CANCELLED") {
    return {
      title: "No longer tracked",
      description: "The finding is open again, and offered with the work nobody tracked.",
    };
  }
  if ("assigned_to" in change) {
    return { title: change.assigned_to === null ? "Owner removed" : "Owner set" };
  }
  return { title: change.due_date === null ? "Due date removed" : "Due date set" };
}

/**
 * Everything but marking done: starting the work, handing it to somebody,
 * giving it a date, reopening it, and calling it off (DECISIONS.md §212).
 *
 * `PATCH /remediation/{id}` took all of these from the start, and nothing in
 * the app sent any of them, so "In progress" and "Overdue" above the queue
 * could only ever read 0, and a task marked done by mistake stayed done.
 */
export function useUpdateTask() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, change }: { id: string; change: TaskChange }) =>
      api.patch<RemediationTask>(`/api/v1/remediation/${id}`, change),
    onSuccess: ({ data: task }, { change }) => {
      void queryClient.invalidateQueries({ queryKey: ["remediation"] });
      void queryClient.invalidateQueries({ queryKey: ["finding", task.finding_id] });
      if (change.status === "CANCELLED") {
        void queryClient.invalidateQueries({ queryKey: ["findings"] });
      }
      const said = changeSaid(change);
      toast.success(said.title, said.description ? { description: said.description } : {});
    },
    onError: (err) =>
      toast.error("Could not update this task", {
        description: err instanceof Error ? err.message : "The API rejected the change.",
      }),
  });
}

/** The organization's members, who work can be handed to (§212). */
export function useAssignees() {
  return useQuery({
    queryKey: ["members", "assignees"],
    queryFn: () => api.get<Member[]>("/api/v1/members").then((r) => r.data),
    staleTime: 5 * 60_000,
    retry: false,
  });
}

/** How a member is named on a task: their address, or a stand-in until they sign in. */
export function memberName(member: Member | undefined): string {
  if (!member) return "A former member";
  if (member.is_you) return "You";
  return member.email ?? "A member yet to sign in";
}

/**
 * Where a tracked fix has got to, said one way wherever the task is shown.
 *
 * The queue drew the task's own status and the fix sheet drew the finding's,
 * so one task read "Waiting on a scan" in its row and "In progress" in its
 * sheet -- and a task marked done read "In progress" beside "Done 3 Oct"
 * (DECISIONS.md §212). Once work is claimed, what matters is what the checks
 * found, so the verification decides: a check that has looked and not seen the
 * fix is "not fixed yet", never a spinner saying "checking".
 */
export type WorkState =
  | "todo"
  | "in_progress"
  | "checking"
  | "not_yet"
  | "still_failing"
  | "unverified"
  | "fixed"
  | "stopped";

export function workState(task: RemediationTask, finding?: FindingDetail): WorkState {
  if (finding?.status === "RESOLVED") return "fixed";
  if (task.status === "TODO") return "todo";
  if (task.status === "IN_PROGRESS") return "in_progress";
  if (task.status === "CANCELLED") return "stopped";
  const verification = finding?.verification;
  switch (verification?.status) {
    case "VERIFIED":
      return "fixed";
    case "STILL_FAILING":
      return "still_failing";
    case "INSUFFICIENT_EVIDENCE":
    case "ABANDONED":
      return "unverified";
    case "PENDING":
      return verification.attempts > 0 && verification.last_state === "FAIL"
        ? "not_yet"
        : "checking";
    case undefined:
      return "checking";
  }
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

const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

/**
 * The worst of several findings' severities, for a row standing for all of them.
 *
 * A row's badge is the severity of what is wrong, as on every other finding.
 * The queue drew the task's priority in the same badge -- impact against
 * effort, so a High finding on three attack paths read Critical in its row and
 * High in its own sheet (DECISIONS.md §212). Priority still orders the queue.
 */
export function worstSeverity(severities: readonly Severity[]): Severity {
  return severities.reduce<Severity>(
    (worst, next) => (SEVERITY_RANK[next] < SEVERITY_RANK[worst] ? next : worst),
    "LOW",
  );
}

/**
 * What one rule finds, said without the asset: a finding's title with its
 * asset's name taken off the end.
 *
 * The findings list carries no rule name, and a title is the rule's statement
 * followed by " — " and the asset ("Identity can grant itself any role — User
 * 70f01f3e"). A title in any other shape is kept whole rather than guessed at.
 */
export function ruleTitle(finding: Pick<Finding, "title" | "resource">): string {
  const suffix = finding.resource ? ` — ${finding.resource.name}` : null;
  return suffix && finding.title.endsWith(suffix)
    ? finding.title.slice(0, -suffix.length)
    : finding.title;
}

/** One line of the findings nobody tracked: one finding, or several of one rule. */
export interface UntrackedItem {
  ruleId: string;
  findings: Finding[];
}

/**
 * The untracked findings, the ones of one rule drawn as one line.
 *
 * Four rows of "Identity can grant itself any role" filled the list under the
 * queue, which groups the same work as one row (§203, §212). The list's order
 * -- worst risk first -- decides where each line sits, as in the queue.
 */
export function groupUntracked(findings: readonly Finding[]): UntrackedItem[] {
  const items: UntrackedItem[] = [];
  const byRule = new Map<string, UntrackedItem>();
  for (const finding of findings) {
    const existing = byRule.get(finding.rule_id);
    if (existing) {
      existing.findings.push(finding);
      continue;
    }
    const item: UntrackedItem = { ruleId: finding.rule_id, findings: [finding] };
    byRule.set(finding.rule_id, item);
    items.push(item);
  }
  return items;
}
