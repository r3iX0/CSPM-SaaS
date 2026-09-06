import { Link } from "react-router-dom";
import { LockIcon } from "lucide-react";

import type { FindingDetail, RemediationTask } from "@/lib/types";
import { useT } from "@/i18n";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { cn, formatEffort, resourceTypeLabel } from "@/lib/format";

/** Which column a task belongs in, and why. */
export type Lane = "TO_FIX" | "IN_PROGRESS" | "AWAITING_SCAN" | "VERIFIED";

/**
 * The queue as a board, with one column nobody can put a card in.
 *
 * The subtitle this replaces read "Fixes a later scan observed — never work
 * somebody marked done", which is a sentence asking to be believed. The board
 * says it structurally instead: "Verified fixed" carries a padlock, has no
 * action that reaches it, and a card arrives there only when a scan stopped
 * finding the problem (docs/UI_REDESIGN.md §4.6).
 *
 * "Awaiting a scan" is the column that column implies: a fix somebody has
 * deployed and CloudGuard has not yet confirmed. Before it existed, marking
 * work done moved a card to a status that read like completion, and the fact
 * that nothing had been verified lived only in a sentence.
 */
export function RemediationBoard({
  lanes,
  findingOf,
  busyId,
  onMove,
}: {
  lanes: Record<Lane, RemediationTask[]>;
  findingOf: (task: RemediationTask) => FindingDetail | undefined;
  busyId?: string;
  onMove: (task: RemediationTask, status: RemediationTask["status"]) => void;
}) {
  const t = useT();

  return (
    <div className="grid gap-3 lg:grid-cols-4">
      <Column
        title={t.remediation.laneToFix}
        tone="var(--sev-critical)"
        tasks={lanes.TO_FIX}
        findingOf={findingOf}
        busyId={busyId}
        action={{ label: t.remediation.start, status: "IN_PROGRESS" }}
        onMove={onMove}
      />
      <Column
        title={t.remediation.laneInProgress}
        tone="var(--sev-medium)"
        tasks={lanes.IN_PROGRESS}
        findingOf={findingOf}
        busyId={busyId}
        action={{ label: t.remediation.deployed, status: "DONE" }}
        onMove={onMove}
      />
      <Column
        title={t.remediation.laneAwaiting}
        tone="var(--sev-ok)"
        tasks={lanes.AWAITING_SCAN}
        findingOf={findingOf}
        busyId={busyId}
        note={t.remediation.awaitingNote}
        onMove={onMove}
      />
      <Column
        title={t.remediation.laneVerified}
        tone="var(--sev-ok)"
        tasks={lanes.VERIFIED}
        findingOf={findingOf}
        busyId={busyId}
        locked
        note={t.remediation.verifiedNote}
        onMove={onMove}
      />
    </div>
  );
}

function Column({
  title,
  tone,
  tasks,
  findingOf,
  busyId,
  action,
  note,
  locked = false,
  onMove,
}: {
  title: string;
  tone: string;
  tasks: RemediationTask[];
  findingOf: (task: RemediationTask) => FindingDetail | undefined;
  busyId?: string;
  action?: { label: string; status: RemediationTask["status"] };
  /** The one sentence a column needs to explain itself. Two on the page, total. */
  note?: string;
  locked?: boolean;
  onMove: (task: RemediationTask, status: RemediationTask["status"]) => void;
}) {
  const t = useT();

  return (
    <section aria-label={title} className="flex min-w-0 flex-col gap-2">
      <header className="flex items-center gap-2 px-1">
        <span
          className="size-2 shrink-0 rounded-full"
          style={{ background: tone }}
          aria-hidden
        />
        <h2 className="text-[13px] font-semibold text-foreground">{title}</h2>
        <span className="font-mono text-[11px] text-meta-foreground">
          {tasks.length}
        </span>
        {locked && (
          <LockIcon
            className="ml-auto size-3.5 text-meta-foreground"
            aria-label={t.remediation.lockedLabel}
          />
        )}
      </header>

      <div className="flex flex-col gap-2">
        {tasks.map((task) => (
          <TaskCard
            key={task.id}
            task={task}
            finding={findingOf(task)}
            busy={busyId === task.id}
            action={action}
            onMove={onMove}
          />
        ))}

        {note && (
          <p className="rounded-lg border border-dashed p-2.5 text-xs leading-relaxed text-muted-foreground">
            {note}
          </p>
        )}

        {tasks.length === 0 && !note && (
          <p className="rounded-lg border border-dashed p-2.5 text-xs text-meta-foreground">
            {t.remediation.laneEmpty}
          </p>
        )}
      </div>
    </section>
  );
}

/**
 * One job, as a card in a column.
 *
 * What decides whether a task is worked next is what is wrong, on what, and how
 * long it takes — so the finding's title is the card, and everything else
 * qualifies it.
 */
function TaskCard({
  task,
  finding,
  busy,
  action,
  onMove,
}: {
  task: RemediationTask;
  finding: FindingDetail | undefined;
  busy: boolean;
  action?: { label: string; status: RemediationTask["status"] };
  onMove: (task: RemediationTask, status: RemediationTask["status"]) => void;
}) {
  return (
    <article
      className={cn(
        "rounded-lg border bg-card p-2.5",
        // The severity rail, in the colour the badge would have used. A column
        // of cards is scanned down its left edge.
        "border-l-2",
      )}
      style={{ borderLeftColor: `var(--sev-${task.priority.toLowerCase()})` }}
    >
      {finding ? (
        <Link
          to={`/findings/${task.finding_id}`}
          className="block text-[13px] font-medium leading-snug text-foreground hover:underline"
        >
          {finding.title}
        </Link>
      ) : (
        // The card keeps its height while the finding arrives, so a board does
        // not reflow under the reader's cursor.
        <Skeleton className="h-4 w-full" />
      )}

      <p className="mt-1 truncate text-[11px] text-meta-foreground">
        {finding?.resource ? (
          <span className="font-mono">{finding.resource.name}</span>
        ) : finding ? (
          "Tenant-wide"
        ) : (
          " "
        )}
        {finding?.resource && (
          <> · {resourceTypeLabel(finding.resource.resource_type)}</>
        )}
      </p>

      <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
        <span className="flex items-center gap-2">
          <SeverityBadge level={task.priority} size="sm" />
          <span className="font-mono text-[11px] text-meta-foreground">
            {formatEffort(task.estimated_effort_minutes)}
          </span>
        </span>

        {action && (
          <Button
            variant="secondary"
            size="sm"
            disabled={busy}
            onClick={() => onMove(task, action.status)}
          >
            {busy && <Spinner data-icon="inline-start" />}
            {action.label}
          </Button>
        )}
      </div>
    </article>
  );
}
