import { useState } from "react";
import { Link } from "react-router-dom";
import { useQueries, useQuery } from "@tanstack/react-query";
import { motion } from "motion/react";
import { CheckIcon, XIcon } from "lucide-react";

import { api, auth } from "@/lib/api";
import type {
  CloudAccount,
  CloudConnection,
  ContextDeclaration,
  Dashboard,
} from "@/lib/types";
import { useT } from "@/i18n";
import { setupPath } from "@/lib/connectionStage";
import { DEMO_ICON } from "@/lib/icons";
import { useIsDemo, useJoinDemo } from "@/lib/useDemo";
import { DURATION, EASE_OUT } from "@/lib/motion";
import { cn } from "@/lib/format";
import { useScanWizard } from "@/components/scans/ScanWizardProvider";
import { Button, buttonVariants } from "@/components/ui/button";

/** Declarations are read per subscription; past this many, the first answers. */
const CONTEXT_PROBE_LIMIT = 20;

type Step = {
  key: string;
  title: string;
  detail: string;
  done: boolean;
  /** Which earlier step has to be done first; nothing to do here until it is. */
  requires?: string;
  /** Drawn as a button for the next step and as a quiet link for the rest. */
  action: (primary: boolean) => React.ReactNode;
};

/** The quiet form of a later step's action: reachable, not competing. */
const QUIET_ACTION =
  "inline-flex items-center gap-1 text-xs font-medium text-muted-foreground underline-offset-4 hover:text-foreground hover:underline";

function actionClass(primary: boolean): string {
  return primary ? buttonVariants({ size: "sm" }) : QUIET_ACTION;
}

/**
 * The five things between signing up and trusting the product.
 *
 * Every step is read off state the server already holds -- a connection that
 * can scan, a completed scan, a verified fix, a schedule, a declaration -- and
 * nothing is recorded by the checklist itself. That is the point: it is right
 * on a second device, for a teammate who never saw it, and after the customer
 * does a step somewhere else entirely. A checklist that remembered clicks would
 * tick "fix a finding" for somebody who opened one and closed it again.
 *
 * The one thing held in the browser is the dismissal, per organization. It is a
 * preference about this screen, not a fact about the estate, and losing it in a
 * private window costs a reader one click.
 *
 * Only the next undone step carries a primary button. Five equal calls to
 * action is a menu; one is a direction.
 */
export function GettingStarted({
  dashboard,
  accounts,
  variant,
}: {
  dashboard: Dashboard;
  accounts: CloudAccount[];
  /** `full` before the first scan, when this is the whole page; `compact` after. */
  variant: "full" | "compact";
}) {
  const t = useT();
  const copy = t.gettingStarted;
  const scanWizard = useScanWizard();
  const isDemo = useIsDemo();
  const joinDemo = useJoinDemo();
  const dismissKey = `cloudguard.getting-started.dismissed.${auth.organizationId ?? "default"}`;
  const [dismissed, setDismissed] = useState(() => readFlag(dismissKey));

  const connections = useQuery({
    queryKey: ["cloud-connections"],
    queryFn: () =>
      api.get<CloudConnection[]>("/api/v1/cloud-connections").then((r) => r.data),
    retry: false,
  });

  // The same cache key the settings form reads, so declaring there ticks the
  // step here without a request of its own.
  const contexts = useQueries({
    queries: accounts.slice(0, CONTEXT_PROBE_LIMIT).map((account) => ({
      queryKey: ["account-context", account.id],
      queryFn: () =>
        api
          .get<ContextDeclaration | null>(`/api/v1/cloud-accounts/${account.id}/context`)
          .then((r) => r.data),
      retry: false,
      staleTime: 60_000,
    })),
  });

  const rows = Array.isArray(connections.data) ? connections.data : [];
  const ready = rows.find((connection) => connection.is_ready_to_scan);
  const pending = rows.find((connection) => !connection.is_ready_to_scan);
  const scanned = dashboard.last_scan !== null;
  const fixed =
    (dashboard.findings_by_status?.RESOLVED ?? 0) > 0 ||
    dashboard.verified_resolved_last_30_days > 0;
  const scheduled = rows.some((connection) => connection.scan_interval_hours !== null);
  const declared = contexts.some((query) => query.data != null && typeof query.data === "object");
  const topRisk = dashboard.top_risks?.[0];

  const steps: Step[] = [
    {
      key: "connect",
      title: copy.connectTitle,
      detail: copy.connectDetail,
      done: Boolean(ready),
      action: (primary) =>
        pending ? (
          <Link to={setupPath(pending.id)} className={actionClass(primary)}>
            {copy.continueAction}
          </Link>
        ) : (
          <Link to="/connections/new" className={actionClass(primary)}>
            {copy.connectAction}
          </Link>
        ),
    },
    {
      key: "scan",
      title: copy.scanTitle,
      detail: copy.scanDetail,
      done: scanned,
      requires: "connect",
      action: (primary) =>
        primary ? (
          <Button size="sm" onClick={() => scanWizard.start(ready?.id)}>
            {copy.scanAction}
          </Button>
        ) : (
          <button type="button" className={QUIET_ACTION} onClick={() => scanWizard.start(ready?.id)}>
            {copy.scanAction}
          </button>
        ),
    },
    {
      key: "fix",
      title: copy.fixTitle,
      detail: copy.fixDetail,
      done: fixed,
      requires: "scan",
      action: (primary) => (
        <Link
          to={topRisk ? `/risks/${topRisk.id}` : "/findings"}
          className={actionClass(primary)}
        >
          {topRisk ? copy.fixAction : copy.fixActionFallback}
        </Link>
      ),
    },
    {
      key: "schedule",
      title: copy.scheduleTitle,
      detail: copy.scheduleDetail,
      done: scheduled,
      requires: "connect",
      action: (primary) => (
        <Link to="/scans" className={actionClass(primary)}>
          {copy.scheduleAction}
        </Link>
      ),
    },
    {
      key: "context",
      title: copy.contextTitle,
      detail: copy.contextDetail,
      done: declared,
      // Subscriptions are only known once a scan has discovered them.
      requires: "scan",
      action: (primary) => (
        <Link to="/settings" className={actionClass(primary)}>
          {copy.contextAction}
        </Link>
      ),
    },
  ];

  const doneCount = steps.filter((step) => step.done).length;
  const next = steps.findIndex((step) => !step.done);

  // Finished, or put away after the first scan. Before the first scan this is
  // the whole page, so it cannot be dismissed into a blank one. Never in the
  // demo: its setup is not the reader's to do.
  if (isDemo) return null;
  if (next === -1) return null;
  if (variant === "compact" && dismissed) return null;

  return (
    <section
      aria-labelledby="getting-started"
      className="overflow-hidden rounded-xl border border-border bg-card"
    >
      <header className="flex flex-wrap items-start justify-between gap-4 px-5 pt-5">
        <div className="min-w-0">
          <h2 id="getting-started" className="text-base font-semibold tracking-tight">
            {copy.title}
          </h2>
          <p className="mt-0.5 text-sm text-muted-foreground">{copy.intro}</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="w-36">
            <p className="text-right text-xs tabular-nums text-muted-foreground">
              {copy.progress
                .replace("{done}", String(doneCount))
                .replace("{total}", String(steps.length))}
            </p>
            <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-muted" aria-hidden>
              <motion.div
                className="h-full rounded-full bg-ok"
                initial={false}
                animate={{ width: `${(doneCount / steps.length) * 100}%` }}
                transition={{ duration: DURATION.page / 1000, ease: EASE_OUT }}
              />
            </div>
          </div>
          {variant === "compact" && (
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label={copy.dismiss}
              title={copy.dismiss}
              onClick={() => {
                setDismissed(true);
                writeFlag(dismissKey);
              }}
            >
              <XIcon aria-hidden />
            </Button>
          )}
        </div>
      </header>

      <ol
        className={cn(
          "mt-4 grid border-t border-border",
          variant === "compact"
            ? "divide-y divide-border lg:grid-cols-5 lg:divide-x lg:divide-y-0"
            : "divide-y divide-border",
        )}
      >
        {steps.map((step, index) => {
          const current = index === next;
          const blocked =
            !step.done &&
            step.requires !== undefined &&
            !steps.find((other) => other.key === step.requires)?.done;
          return (
            <li
              key={step.key}
              aria-current={current ? "step" : undefined}
              className={cn(
                "relative flex gap-3 px-5 py-4",
                variant === "compact" && "lg:flex-col lg:gap-2.5",
                current && "bg-muted/30",
              )}
            >
              {current && (
                <span
                  className={cn(
                    "absolute bg-foreground",
                    variant === "compact"
                      ? "inset-y-0 left-0 w-0.5 lg:inset-x-0 lg:top-0 lg:bottom-auto lg:h-0.5 lg:w-auto"
                      : "inset-y-0 left-0 w-0.5",
                  )}
                  aria-hidden
                />
              )}
              <span
                className={cn(
                  "flex size-6 shrink-0 items-center justify-center rounded-full text-[11px] font-semibold tabular-nums",
                  step.done && "bg-ok text-background",
                  current && "bg-foreground text-background",
                  !step.done && !current && "border border-border text-muted-foreground",
                )}
              >
                {step.done ? <CheckIcon className="size-3.5" strokeWidth={3} aria-hidden /> : index + 1}
              </span>
              <div className="flex min-w-0 flex-1 flex-col gap-2 sm:flex-row sm:items-center sm:justify-between lg:flex-col lg:items-start">
                <div className="min-w-0">
                  <p
                    className={cn(
                      "text-sm font-medium",
                      step.done ? "text-muted-foreground line-through decoration-muted-foreground/40" : "text-foreground",
                    )}
                  >
                    {step.title}
                  </p>
                  {!step.done && (
                    <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
                      {step.detail}
                    </p>
                  )}
                </div>
                {current && <div className="shrink-0">{step.action(true)}</div>}
                {!current && !step.done && !blocked && (
                  <div className="shrink-0">{step.action(false)}</div>
                )}
                {blocked && (
                  <span className="text-xs text-muted-foreground">{copy.waitingOnPrevious}</span>
                )}
              </div>
            </li>
          );
        })}
      </ol>

      {/* Before anything is connected, the way to see the product without
          connecting anything. */}
      {variant === "full" && !steps[0].done && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border bg-muted/30 px-5 py-3.5">
          <p className="text-sm text-muted-foreground">{t.demo.exploreDetail}</p>
          <Button
            variant="outline"
            size="sm"
            onClick={() => joinDemo.mutate()}
            disabled={joinDemo.isPending}
          >
            <DEMO_ICON data-icon="inline-start" aria-hidden />
            {joinDemo.isPending ? t.demo.opening : t.demo.explore}
          </Button>
        </div>
      )}
    </section>
  );
}

function readFlag(key: string): boolean {
  try {
    return localStorage.getItem(key) === "1";
  } catch {
    return false;
  }
}

function writeFlag(key: string): void {
  try {
    localStorage.setItem(key, "1");
  } catch {
    // A private window or blocked storage: the checklist simply comes back
    // on the next visit, which is the harmless way to fail.
  }
}
