import { useState } from "react";
import { useQueries, useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { CheckIcon, ChevronDownIcon, WrenchIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { Finding, FindingDetail, Member, RemediationTask } from "@/lib/types";
import {
  FIX_PARAM,
  RULE_PARAM,
  groupByRule,
  groupUntracked,
  isOpenTask,
  memberName,
  ruleTitle,
  taskFor,
  useAssignees,
  useMarkAllDone,
  useMarkDone,
  useRemediationQueue,
  useTrack,
  useTrackAll,
  workState,
  worstSeverity,
  type UntrackedItem,
} from "@/lib/remediation";
import { useT } from "@/i18n";
import { WorkPill } from "@/components/security/WorkPill";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { FixSheet } from "@/components/security/FixSheet";
import { RuleFixSheet, type RuleFixMember } from "@/components/security/RuleFixSheet";
import { CardsSkeleton, EmptyState, ErrorState, PageHeader } from "@/components/common/states";
import { Button, buttonVariants } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { StatStrip } from "@/components/common/StatStrip";
import { useIsDemo } from "@/lib/useDemo";
import { Spinner } from "@/components/ui/spinner";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
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
  const [params, setParams] = useSearchParams();
  const { data, isLoading, error, refetch } = useRemediationQueue();
  const markDone = useMarkDone();

  const markAllDone = useMarkAllDone();
  const assignees = useAssignees();
  const owners = new Map((assignees.data ?? []).map((member) => [member.user_id, member]));

  /**
   * The fix the sheet is open on, in the URL: one finding's (`?fix=`,
   * DECISIONS.md §202) or one rule's over every asset it is on (`?rule=`,
   * §203), never both. A finding's "Open fix" lands here with it set, and a
   * row sets it; the history entry is replaced rather than pushed, so Back
   * leaves the page rather than walking through every fix that was looked at.
   */
  const fixId = params.get(FIX_PARAM);
  const ruleId = fixId === null ? params.get(RULE_PARAM) : null;
  const openSheet = (param: typeof FIX_PARAM | typeof RULE_PARAM, value: string | null) =>
    setParams(
      (previous) => {
        const next = new URLSearchParams(previous);
        next.delete(FIX_PARAM);
        next.delete(RULE_PARAM);
        if (value) next.set(param, value);
        return next;
      },
      { replace: true },
    );
  const openFix = (findingId: string | null) => openSheet(FIX_PARAM, findingId);
  const openRule = (rule: string | null) => openSheet(RULE_PARAM, rule);

  /**
   * What each task is actually about.
   *
   * `GET /remediation` returns the task and nothing of the finding behind it --
   * no title, no asset, no rule -- so this queue could say only "View finding",
   * and a reader deciding what to work on next had to open every card to learn
   * what the work was. That is an API limitation rather than a UI one, and it
   * is worked around here rather than by widening the endpoint: the finding is
   * read per task under the same cache key its own page uses, so opening its
   * fix from this list costs no request at all.
   */
  const findings = useQueries({
    queries: (data ?? []).map((task) => ({
      queryKey: ["finding", task.finding_id],
      queryFn: () =>
        api.get<FindingDetail>(`/api/v1/findings/${task.finding_id}`).then((r) => r.data),
      staleTime: 60_000,
      retry: false,
    })),
  });
  const byFinding = new Map<string, FindingDetail>();
  for (const query of findings) if (query.data) byFinding.set(query.data.id, query.data);

  // Grouped once every finding has arrived (or failed), so rows regroup once
  // rather than each time another title lands (§203).
  const settled = findings.every((query) => !query.isLoading);
  const items = groupByRule(data ?? [], settled ? byFinding : new Map());
  const ruleMembers: RuleFixMember[] =
    ruleId === null
      ? []
      : (data ?? []).flatMap((task) => {
          const finding = byFinding.get(task.finding_id);
          return finding?.rule_id === ruleId ? [{ task, finding }] : [];
        });

  return (
    <div className="flex flex-col gap-4">
      <PageHeader title={t.remediation.title} description={t.remediation.description} />

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
        <>
          <EmptyState
            icon={WrenchIcon}
            title={t.remediation.empty}
            detail="Track a fix from a finding, or start with the worst open ones below."
            action={
              <Link to="/findings" className={buttonVariants({ variant: "outline" })}>
                Go to findings
              </Link>
            }
          />
          <WhereToStart tasks={data} onOpen={openFix} />
        </>
      )}

      {data && data.length > 0 && <QueueSummary tasks={data} />}

      {/* One queue, one container. Divided rows read as a list to work down;
          a stack of separate cards read as a pile of separate problems. */}
      {data && data.length > 0 && (
        <div className="divide-y divide-border overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10">
          {items.map((item) =>
            item.kind === "task" ? (
              <TaskCard
                key={item.task.id}
                task={item.task}
                finding={byFinding.get(item.task.finding_id)}
                owners={owners}
                marking={markDone.isPending && markDone.variables === item.task.id}
                onDone={() => markDone.mutate(item.task.id)}
                onOpen={() => openFix(item.task.finding_id)}
              />
            ) : (
              <TaskGroup
                key={item.ruleId}
                tasks={item.tasks}
                findings={byFinding}
                marking={
                  markAllDone.isPending &&
                  item.tasks.some((task) => markAllDone.variables?.includes(task.id))
                }
                onDoneAll={() =>
                  markAllDone.mutate(item.tasks.filter(isOpenTask).map((task) => task.id))
                }
                onOpen={() => openRule(item.ruleId)}
                renderTask={(task) => (
                  <TaskCard
                    key={task.id}
                    task={task}
                    finding={byFinding.get(task.finding_id)}
                    owners={owners}
                    marking={markDone.isPending && markDone.variables === task.id}
                    onDone={() => markDone.mutate(task.id)}
                    onOpen={() => openFix(task.finding_id)}
                    nested
                  />
                )}
              />
            ),
          )}
          {/* Said where the button is, every time: the one thing a reader
              might assume about "done" is the one thing it does not do. */}
          <p className="bg-muted/60 px-5 py-3 text-xs leading-relaxed text-muted-foreground">
            {t.remediation.doneNote}
          </p>
        </div>
      )}

      {/* A queue with work in it still says what is not in it (§205). */}
      {data && data.length > 0 && <WhereToStart tasks={data} onOpen={openFix} />}

      <FixSheet findingId={fixId} onClose={() => openFix(null)} />
      <RuleFixSheet
        ruleId={ruleId}
        members={ruleMembers}
        onClose={() => openRule(null)}
        onOpenFinding={openFix}
      />
    </div>
  );
}

/**
 * A row's figures and its action. On a phone they take a line of their own
 * under the title, with the action at its end; the fixed widths that line the
 * figures up in columns apply only beside the title, where there are columns
 * to line up -- on their own line they centred the button (§223).
 */
const ROW_FIGURES =
  "flex w-full flex-wrap items-center gap-x-5 gap-y-2 text-xs text-muted-foreground sm:w-auto";
const ROW_ACTION = "ml-auto flex justify-end sm:ml-0 sm:w-24";

/**
 * One job, said as a job.
 *
 * The card this replaces led with two badges and a link reading "View finding",
 * which named the queue's own vocabulary and none of the reader's. What decides
 * whether a task is worked next is what is wrong, on what, and how long it
 * takes -- so the title of the finding is the card, and the badges qualify it.
 * The title opens the fix, which is what somebody working down a queue wants
 * next; the finding itself is a link inside it (DECISIONS.md §202).
 */
function TaskCard({
  task,
  finding,
  owners,
  marking,
  onDone,
  onOpen,
  nested = false,
}: {
  task: RemediationTask;
  finding: FindingDetail | undefined;
  /** The organization's members by user id, to name who has the work (§212). */
  owners: ReadonlyMap<string, Member>;
  marking: boolean;
  onDone: () => void;
  onOpen: () => void;
  /** Drawn inside its rule's group, indented under it (§203). */
  nested?: boolean;
}) {
  const t = useT();
  const done = task.status === "DONE" || task.status === "CANCELLED";
  const isDemo = useIsDemo();
  const overdue = !done && task.due_date !== null && new Date(task.due_date) < new Date();
  const state = workState(task, finding);

  return (
    <div
      className={cn(
        "flex flex-wrap items-center gap-x-6 gap-y-3 px-5 py-3 transition-colors hover:bg-muted/60",
        nested && "bg-muted/30 pl-10",
        done && "opacity-70",
      )}
    >
      {/* A basis, not `flex-1`: at zero basis the title gave its width to
          the figures beside it on a phone and was drawn 0px wide, where with
          one it wraps them onto their own line (DECISIONS.md §212). */}
      <div className="flex min-w-0 flex-[1_1_16rem] items-center gap-3">
        {/* A fixed column, so titles line up whatever the badge says. The
            finding's severity, as everywhere else; priority orders the queue
            and was drawn here as a second, disagreeing severity (§212). */}
        <span className="w-[4.5rem] shrink-0">
          {finding ? <SeverityBadge level={finding.severity} /> : <Skeleton className="h-5 w-16" />}
        </span>
        <div className="min-w-0">
          {finding ? (
            <button
              type="button"
              aria-haspopup="dialog"
              onClick={onOpen}
              className={cn(
                "block max-w-full truncate rounded-sm text-left text-body font-medium outline-none hover:underline focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring",
                done
                  ? "text-muted-foreground line-through decoration-muted-foreground/50"
                  : "text-foreground",
              )}
            >
              {finding.title}
            </button>
          ) : (
            // The row keeps its height while the finding arrives, so a queue
            // does not reflow under the reader's cursor.
            <Skeleton className="h-4 w-72 max-w-full" />
          )}
          {/* Only the asset's name gives way when the line is short: on a
              phone the route count was the part cut off (§223). */}
          <p className="mt-0.5 flex flex-wrap gap-x-1 text-caption text-muted-foreground">
            <span className="max-w-full min-w-0 truncate">
              {finding?.resource
                ? `${finding.resource.name} · ${resourceTypeLabel(finding.resource.resource_type)}`
                : finding
                  ? t.remediation.tenantWide
                  : " "}
            </span>
            {/* Why it sits above an equally urgent task: the asset is on a
                route. Counted by the API, and only said when it is true. */}
            {finding && (task.on_routes ?? 0) > 0 && (
              <span className="font-medium text-foreground">
                · {t.remediation.onRoutes(task.on_routes ?? 0)}
              </span>
            )}
            {finding && task.assigned_to && (
              <span>· {t.remediation.ownedBy(memberName(owners.get(task.assigned_to)))}</span>
            )}
          </p>
          {task.notes && <p className="mt-1 text-xs text-muted-foreground">{task.notes}</p>}
        </div>
      </div>

      <div className={ROW_FIGURES}>
        {/* To do is the queue itself and needs no pill. Anything further
            says where the work has got to, as its sheet does: started, or
            claimed and what the checks have found since (§212). */}
        {state !== "todo" && <WorkPill state={state} />}
        <span className="tabular-nums sm:w-14">{formatEffort(task.estimated_effort_minutes)}</span>
        <span className={cn("tabular-nums sm:w-[130px]", overdue && "font-medium text-critical")}>
          {done && task.completed_at
            ? t.remediation.doneOn(formatDay(task.completed_at))
            : task.due_date
              ? `${overdue ? "Overdue · " : "Due "}${formatDay(task.due_date)}`
              : null}
        </span>
        <span className={ROW_ACTION}>
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
 * Every task one rule's fix closes, as one piece of work (DECISIONS.md §203).
 *
 * Its title opens the rule's fix over all of its assets, which is the reason
 * to group at all: one set of steps, one script. The assets are named in the
 * line under it, and each still opens as its own row beneath, for the reader
 * who wants one asset's fix or to mark one done. "Mark all done" is the row's
 * action, as "Mark done" is a single task's.
 */
function TaskGroup({
  tasks,
  findings,
  marking,
  onDoneAll,
  onOpen,
  renderTask,
}: {
  tasks: RemediationTask[];
  findings: ReadonlyMap<string, FindingDetail>;
  marking: boolean;
  onDoneAll: () => void;
  onOpen: () => void;
  renderTask: (task: RemediationTask) => React.ReactNode;
}) {
  const t = useT();
  const isDemo = useIsDemo();
  const [expanded, setExpanded] = useState(false);
  const open = tasks.filter(isOpenTask);
  const lead = findings.get((open[0] ?? tasks[0])?.finding_id ?? "");
  const names = tasks.map(
    (task) => findings.get(task.finding_id)?.resource?.name ?? t.remediation.tenantWide,
  );
  const onRoutes = tasks.filter((task) => (task.on_routes ?? 0) > 0).length;
  const effort = open.reduce((sum, task) => sum + task.estimated_effort_minutes, 0);
  const due = open
    .map((task) => task.due_date)
    .filter((date): date is string => date !== null)
    .sort()[0];
  const overdue = due !== undefined && new Date(due) < new Date();
  const severity = worstSeverity(
    tasks.flatMap((task) => {
      const finding = findings.get(task.finding_id);
      return finding ? [finding.severity] : [];
    }),
  );

  return (
    <Collapsible open={expanded} onOpenChange={setExpanded}>
      <div
        className={cn(
          "flex flex-wrap items-center gap-x-6 gap-y-3 px-5 py-3 transition-colors hover:bg-muted/60",
          open.length === 0 && "opacity-70",
        )}
      >
        <div className="flex min-w-0 flex-[1_1_16rem] items-center gap-3">
          <span className="w-[4.5rem] shrink-0">
            <SeverityBadge level={severity} />
          </span>
          <div className="min-w-0">
            <button
              type="button"
              aria-haspopup="dialog"
              onClick={onOpen}
              className="block max-w-full truncate rounded-sm text-left text-body font-medium text-foreground outline-none hover:underline focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring"
            >
              {lead?.rule_name ?? lead?.title}
            </button>
            <p className="mt-0.5 flex flex-wrap gap-x-1 text-caption text-muted-foreground">
              <span className="max-w-full min-w-0 truncate">
                {t.remediation.groupLine(tasks.length, names)}
              </span>
              {onRoutes > 0 && (
                <span className="font-medium text-foreground">
                  · {t.remediation.groupOnRoutes(onRoutes)}
                </span>
              )}
            </p>
          </div>
        </div>

        <div className={ROW_FIGURES}>
          <CollapsibleTrigger
            className="inline-flex items-center gap-1 rounded-sm outline-none hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring"
            aria-label={expanded ? t.remediation.groupHide : t.remediation.groupShow(tasks.length)}
          >
            <ChevronDownIcon
              className={cn("size-4 transition-transform", expanded && "rotate-180")}
              aria-hidden
            />
          </CollapsibleTrigger>
          <span className="tabular-nums sm:w-14">{effort > 0 ? formatEffort(effort) : null}</span>
          <span className={cn("tabular-nums sm:w-[130px]", overdue && "font-medium text-critical")}>
            {due ? `${overdue ? "Overdue · " : "Due "}${formatDay(due)}` : null}
          </span>
          <span className={ROW_ACTION}>
            {open.length > 0 && !isDemo && (
              <Button variant="outline" size="sm" disabled={marking} onClick={onDoneAll}>
                {marking ? (
                  <Spinner data-icon="inline-start" />
                ) : (
                  <CheckIcon data-icon="inline-start" aria-hidden />
                )}
                {t.remediation.markAllDoneShort}
              </Button>
            )}
          </span>
        </div>
      </div>
      <CollapsibleContent className="divide-y divide-border border-t">
        {tasks.map(renderTask)}
      </CollapsibleContent>
    </Collapsible>
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

/** How many lines of untracked work the queue offers. */
const STARTERS = 5;

/** How many open findings are read to fill them: one rule's findings share a line. */
const STARTER_PAGE = 25;

/**
 * The worst open findings nobody has tracked, each a press away from the queue.
 *
 * An empty queue said "track a finding from its detail page" to somebody with
 * fifty-eight open ones, which is a page away from the answer. The findings
 * list's own first page -- worst risk first -- is the answer, and each row
 * queues its fix in place, the same `POST /remediation` the fix sheet sends
 * (DECISIONS.md §187); its title opens that sheet, to read the fix before
 * tracking it (§202).
 *
 * It stays under a queue that has work in it, headed "Not in the queue yet":
 * offered only while the queue was empty, it vanished with the first task
 * tracked, and the page that ranks the work had no way left to add any
 * (§205). Tracking moves a finding out of OPEN, so the list refills from the
 * next worst; a finding with a task is left out even so, as a cancelled task
 * leaves its finding where it was. Not in the demo, where the API refuses it.
 *
 * Findings of one rule share a line and are tracked together, as the queue
 * groups them, and the header says how many open findings the five lines are
 * drawn from -- it showed five of a hundred and fifty-six and said neither
 * (§212).
 */
function WhereToStart({
  tasks,
  onOpen,
}: {
  tasks: RemediationTask[];
  onOpen: (findingId: string) => void;
}) {
  const t = useT();
  const isDemo = useIsDemo();
  const open = useQuery({
    queryKey: ["findings", "starters"],
    queryFn: () =>
      api.get<Finding[]>(`/api/v1/findings?status=OPEN&sort=risk&limit=${STARTER_PAGE}&offset=0`),
    retry: false,
  });
  const track = useTrack();
  const trackAll = useTrackAll();

  const page = open.data;
  const untracked = (Array.isArray(page?.data) ? page.data : []).filter(
    (finding) => taskFor(tasks, finding.id) === undefined,
  );
  const items = groupUntracked(untracked).slice(0, STARTERS);
  if (isDemo || items.length === 0) return null;

  const shown = items.reduce((sum, item) => sum + item.findings.length, 0);
  const total = typeof page?.meta.total === "number" ? page.meta.total : undefined;
  const busy = track.isPending || trackAll.isPending;
  const heading = tasks.length === 0 ? t.remediation.whereToStart : t.remediation.notTracked;
  return (
    <section
      aria-labelledby="where-to-start"
      className="overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1 px-5 pt-4 pb-3">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h2 id="where-to-start" className="text-body font-semibold">
            {heading}
          </h2>
          {total !== undefined && total > shown && (
            <span className="text-caption text-muted-foreground">
              {t.remediation.shownOf(shown, total)}
            </span>
          )}
        </div>
        <Link
          to="/findings"
          className="rounded-sm text-xs text-muted-foreground underline underline-offset-2 outline-none hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring"
        >
          {t.remediation.allOpenFindings}
        </Link>
      </div>
      <ul className="divide-y border-t">
        {items.map((item) => (
          <UntrackedRow
            key={item.ruleId}
            item={item}
            busy={busy}
            spinning={
              (track.isPending &&
                item.findings.some((finding) => finding.id === track.variables)) ||
              (trackAll.isPending &&
                item.findings.some((finding) => trackAll.variables?.includes(finding.id)))
            }
            onOpen={onOpen}
            onTrack={() =>
              item.findings.length === 1
                ? track.mutate(item.findings[0]?.id ?? "")
                : trackAll.mutate(item.findings.map((finding) => finding.id))
            }
          />
        ))}
      </ul>
    </section>
  );
}

/** One line of untracked work: a finding, or every listed finding of one rule. */
function UntrackedRow({
  item,
  busy,
  spinning,
  onOpen,
  onTrack,
}: {
  item: UntrackedItem;
  busy: boolean;
  spinning: boolean;
  onOpen: (findingId: string) => void;
  onTrack: () => void;
}) {
  const t = useT();
  const lead = item.findings[0];
  if (!lead) return null;
  const count = item.findings.length;
  const title = count === 1 ? lead.title : ruleTitle(lead);
  const names = item.findings.map((finding) => finding.resource?.name ?? t.remediation.tenantWide);

  return (
    <li className="flex items-center gap-3 px-5 py-2.5">
      <SeverityBadge level={worstSeverity(item.findings.map((finding) => finding.severity))} />
      <div className="min-w-0 flex-1">
        <button
          type="button"
          aria-haspopup="dialog"
          onClick={() => onOpen(lead.id)}
          className="block max-w-full truncate rounded-sm text-left text-body outline-none hover:underline focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring"
        >
          {title}
        </button>
        {count > 1 && (
          <p className="truncate text-caption text-muted-foreground">
            {t.remediation.untrackedLine(count, names)}
          </p>
        )}
      </div>
      <Button
        size="sm"
        variant="outline"
        disabled={busy}
        onClick={onTrack}
        aria-label={
          count === 1 ? t.remediation.trackFor(title) : t.remediation.trackGroupFor(title, count)
        }
      >
        {spinning ? (
          <Spinner data-icon="inline-start" />
        ) : (
          <WrenchIcon data-icon="inline-start" aria-hidden />
        )}
        {count === 1 ? t.remediation.track : t.remediation.trackGroup(count)}
      </Button>
    </li>
  );
}
