import { useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "motion/react";
import { CheckIcon, MinusIcon, XIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { Scan, ScanDetail, ScanStage } from "@/lib/types";
import { cn, formatSeconds, label } from "@/lib/format";
import { DURATION, EASE_OUT, fadeUp, useCountUp } from "@/lib/motion";
import { IN_FLIGHT } from "@/components/scans/status";
import { useScanEvents } from "@/lib/scanEvents";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";

type Phase = ScanStage["stage"];
type PhaseState = "pending" | "active" | "done" | "partial" | "failed" | "skipped";

const PHASES: { id: Phase; label: string; blurb: string }[] = [
  { id: "PLAN", label: "Plan", blurb: "Work out what this scan covers" },
  { id: "COLLECT", label: "Collect", blurb: "Read each scope and store what came back" },
  { id: "ANALYZE", label: "Analyze", blurb: "Normalize, evaluate every rule, score" },
];

/** Running and failed rise to the top: they are what a reader is watching for. */
const LANE_ORDER: Record<ScanStage["status"], number> = {
  RUNNING: 0,
  FAILED: 1,
  PENDING: 2,
  SUCCEEDED: 3,
  SKIPPED: 4,
};

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

/**
 * A scan, as it runs and as it ended.
 *
 * Everything that moves here moves because the API said something changed.
 * There is no percentage invented from elapsed time and no sub-phase the
 * backend does not report. ANALYZE is one durable step, and what is drawn inside
 * it -- normalize, evaluate, score -- is the `phase` that step writes as it
 * passes each seam, plus the resource and rule counts committed at those same
 * seams. A progress bar that advances on a timer is a claim about work nobody
 * measured.
 *
 * Pushed over `GET /scans/{id}/events` while that stream is live, and polled
 * whenever it is not -- the two write the same query, so which one delivered a
 * state is invisible on screen. Neither runs once the scan has finished. The result replaces the
 * pipeline in place, and the lists that a finished scan changes -- findings,
 * the dashboard -- are invalidated once, when it finishes.
 */
export function ScanPipeline({
  scanId,
  onRunAnother,
  onMinimize,
}: {
  scanId: string;
  onRunAnother: () => void;
  onMinimize: () => void;
}) {
  const queryClient = useQueryClient();
  const live = useScanEvents(scanId);
  const detail = useQuery({
    queryKey: ["scan-detail", scanId],
    queryFn: () => api.get<ScanDetail>(`/api/v1/scans/${scanId}/detail`).then((r) => r.data),
    refetchInterval: (query) => {
      if (live) return false;
      const status = (query.state.data as ScanDetail | undefined)?.status;
      return !status || IN_FLIGHT.includes(status) ? 2500 : false;
    },
  });

  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.get<Scan[]>("/api/v1/scans").then((r) => r.data),
  });

  const cancel = useMutation({
    mutationFn: () => api.post<Scan>(`/api/v1/scans/${scanId}/cancel`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scan-detail", scanId] }),
  });

  const data = detail.data;
  const running = !data || IN_FLIGHT.includes(data.status);

  // Once, on the transition to finished: a scan that ends changes findings,
  // the score and the scan list, and none of those poll on their own.
  const settled = useRef(false);
  useEffect(() => {
    if (!data || running || settled.current) return;
    settled.current = true;
    for (const key of ["scans", "findings", "risks", "dashboard"]) {
      queryClient.invalidateQueries({ queryKey: [key] });
    }
  }, [data, running, queryClient]);

  if (detail.isLoading || !data) {
    return (
      <div className="flex flex-col gap-3 py-4">
        <Skeleton className="h-14 w-full" />
        <Skeleton className="h-24 w-full" />
      </div>
    );
  }

  const stages = data.stages ?? [];
  const previous = (scans.data ?? [])
    .filter(
      (s) =>
        s.id !== data.id &&
        s.connection_id != null &&
        s.connection_id === data.connection_id &&
        (s.status === "COMPLETED" || s.status === "PARTIAL") &&
        s.created_at < data.created_at,
    )
    .sort((a, b) => b.created_at.localeCompare(a.created_at))[0];

  return (
    <div className="flex flex-col gap-5 py-4">
      <PhaseTrack stages={stages} status={data.status} />

      <AnalyzeDetail step={stages.find((s) => s.stage === "ANALYZE")} scan={data} />

      {running && stages.length === 0 && (
        <p className="text-sm text-muted-foreground">
          {data.stuck_in_queue
            ? "Nothing has picked this scan up yet. That usually means no worker is running."
            : "Queued. A worker picks a scan up within seconds."}
        </p>
      )}

      <CollectLanes stages={stages.filter((s) => s.stage === "COLLECT")} />

      {stages
        .filter((s) => s.stage !== "COLLECT" && s.status === "FAILED" && s.error)
        .map((s) => (
          <Alert key={s.stage} variant="destructive">
            <AlertTitle>{PHASES.find((p) => p.id === s.stage)?.label} failed</AlertTitle>
            <AlertDescription>{s.error}</AlertDescription>
          </Alert>
        ))}

      {running ? (
        <div className="flex items-center justify-between gap-2">
          <Button
            variant="secondary"
            size="sm"
            disabled={cancel.isPending}
            onClick={() => cancel.mutate()}
          >
            {cancel.isPending ? "Cancelling…" : "Cancel scan"}
          </Button>
          <Button variant="ghost" size="sm" onClick={onMinimize}>
            Minimize
          </Button>
        </div>
      ) : (
        <ScanResult scan={data} previous={previous} onRunAnother={onRunAnother} />
      )}
    </div>
  );
}

const ANALYZE_PHASES: { id: NonNullable<ScanStage["phase"]>; label: string }[] = [
  { id: "NORMALIZE", label: "Normalize" },
  { id: "EVALUATE", label: "Evaluate rules" },
  { id: "SCORE", label: "Score risk" },
];

/**
 * Inside the one ANALYZE step, while it runs.
 *
 * The phase is what the step reported reaching, not a guess from elapsed time,
 * and before its first report the honest thing to say is that it is reading
 * back what collection stored. The counts appear as the pipeline commits them:
 * resources once normalizing has persisted them, rules once evaluation has run.
 * Findings are not counted live -- they are reconciled as one change, and a
 * number climbing through reopen-and-resolve would be a count of nothing.
 */
function AnalyzeDetail({ step, scan }: { step: ScanStage | undefined; scan: ScanDetail }) {
  if (!step || step.status !== "RUNNING") return null;
  const reached = ANALYZE_PHASES.findIndex((phase) => phase.id === step.phase);

  return (
    <motion.div
      initial={fadeUp.initial}
      animate={fadeUp.animate}
      className="flex flex-col gap-2.5 rounded-lg border px-3 py-2.5"
    >
      <ol className="flex flex-wrap items-center gap-x-4 gap-y-1" aria-label="Analysis">
        {ANALYZE_PHASES.map((phase, i) => {
          const done = reached > i;
          const current = reached === i;
          return (
            <li
              key={phase.id}
              aria-current={current ? "step" : undefined}
              className={cn(
                "flex items-center gap-1.5 text-xs",
                current ? "font-medium text-foreground" : "text-muted-foreground",
              )}
            >
              {done ? (
                <CheckIcon className="size-3 text-ok" aria-hidden />
              ) : current ? (
                <Spinner className="size-3" />
              ) : (
                <span className="size-1.5 rounded-full bg-muted-foreground/40" aria-hidden />
              )}
              {phase.label}
            </li>
          );
        })}
      </ol>
      {reached === -1 && (
        <p className="text-xs text-muted-foreground">Reading back what collection stored.</p>
      )}
      {(scan.resource_count > 0 || scan.rule_count > 0) && (
        <div className="flex gap-6">
          {scan.resource_count > 0 && <LiveCount label="Resources" value={scan.resource_count} />}
          {scan.rule_count > 0 && <LiveCount label="Rules run" value={scan.rule_count} />}
        </div>
      )}
    </motion.div>
  );
}

function LiveCount({ label: text, value }: { label: string; value: number }) {
  const shown = useCountUp(value);
  return (
    <span className="flex items-baseline gap-1.5 text-xs text-muted-foreground">
      {text}
      <span className="text-sm font-semibold tabular-nums text-foreground">
        {Math.round(shown)}
      </span>
    </span>
  );
}

function phaseState(steps: ScanStage[], scanRunning: boolean): PhaseState {
  if (steps.length === 0) return "pending";
  if (steps.some((s) => s.status === "RUNNING")) return "active";
  if (steps.every((s) => s.status === "SUCCEEDED")) return "done";
  if (steps.every((s) => s.status === "SKIPPED")) return "skipped";
  const unfinished = steps.some((s) => s.status === "PENDING");
  if (unfinished) {
    return steps.some((s) => s.status !== "PENDING") && scanRunning ? "active" : "pending";
  }
  if (steps.some((s) => s.status === "FAILED")) {
    return steps.some((s) => s.status === "SUCCEEDED") ? "partial" : "failed";
  }
  return "done";
}

/**
 * Plan, Collect, Analyze, as one line.
 *
 * The connector after a phase fills when that phase has finished -- however it
 * finished, since a partial collection still hands over to analysis. The
 * current phase breathes; under reduced motion `MotionConfig` holds it still.
 */
function PhaseTrack({ stages, status }: { stages: ScanStage[]; status: string }) {
  const scanRunning = IN_FLIGHT.includes(status);
  const states = PHASES.map((phase) =>
    phaseState(
      stages.filter((s) => s.stage === phase.id),
      scanRunning,
    ),
  );

  return (
    <ol className="flex items-start" aria-label="Scan pipeline">
      {PHASES.map((phase, i) => {
        const state = states[i];
        const finished = state !== "pending" && state !== "active";
        return (
          <li key={phase.id} className="flex flex-1 flex-col gap-2 last:flex-none">
            <div className="flex items-center">
              <PhaseNode state={state} />
              {i < PHASES.length - 1 && (
                <span className="relative mx-2 h-0.5 flex-1 overflow-hidden rounded-full bg-border" aria-hidden>
                  <motion.span
                    className="absolute inset-0 origin-left bg-primary"
                    initial={false}
                    animate={{ scaleX: finished ? 1 : 0 }}
                    transition={{ duration: DURATION.chart / 1000, ease: EASE_OUT }}
                  />
                </span>
              )}
            </div>
            <div className="pr-3">
              <p className="text-xs font-medium">{phase.label}</p>
              <p className="text-[11px] leading-snug text-muted-foreground">{phase.blurb}</p>
              <p className="sr-only">{state}</p>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

function PhaseNode({ state }: { state: PhaseState }) {
  return (
    <span className="relative flex size-8 shrink-0 items-center justify-center">
      {state === "active" && (
        <motion.span
          className="absolute inset-0 rounded-full bg-primary/20"
          animate={{ scale: [1, 1.35, 1], opacity: [0.6, 0, 0.6] }}
          transition={{ duration: 1.6, repeat: Infinity, ease: "easeInOut" }}
          aria-hidden
        />
      )}
      <motion.span
        layout
        className={cn(
          "relative flex size-8 items-center justify-center rounded-full border transition-colors",
          state === "done" && "border-ok-border bg-ok-bg text-ok",
          state === "partial" && "border-medium-border bg-medium-bg text-medium",
          state === "failed" && "border-critical-border bg-critical-bg text-critical",
          state === "skipped" && "border-dashed border-unknown-border bg-unknown-bg text-unknown",
          state === "active" && "border-primary bg-background text-foreground",
          state === "pending" && "bg-background text-muted-foreground",
        )}
      >
        {state === "active" && <Spinner className="size-4" />}
        {(state === "done" || state === "partial") && <CheckIcon className="size-4" aria-hidden />}
        {state === "failed" && <XIcon className="size-4" aria-hidden />}
        {state === "skipped" && <MinusIcon className="size-4" aria-hidden />}
        {state === "pending" && <span className="size-1.5 rounded-full bg-muted-foreground/50" />}
      </motion.span>
    </span>
  );
}

/**
 * One lane per scope read.
 *
 * The segmented bar is the count made visible -- one segment per scope, not a
 * single percentage -- so one red segment in twelve reads as a gap in the
 * report rather than as a broken scan. Lanes re-sort as they change state and
 * glide to their new place, which keeps a running or failed scope in view on
 * a tenant with forty subscriptions.
 */
function CollectLanes({ stages }: { stages: ScanStage[] }) {
  if (stages.length === 0) return null;

  const done = stages.filter((s) => s.status === "SUCCEEDED").length;
  const failed = stages.filter((s) => s.status === "FAILED").length;
  const lanes = [...stages].sort((a, b) => LANE_ORDER[a.status] - LANE_ORDER[b.status]);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-col gap-1.5">
        <p className="text-xs tabular-nums text-muted-foreground">
          {done} of {stages.length} scopes read
          {failed > 0 && <span className="text-critical"> · {failed} failed</span>}
        </p>
        <div className="flex h-1.5 gap-0.5" aria-hidden>
          {stages.map((stage, i) => (
            <motion.span
              key={`${stage.scope ?? "scope"}-${i}`}
              className={cn(
                "flex-1 rounded-full transition-colors",
                stage.status === "SUCCEEDED" && "bg-ok",
                stage.status === "FAILED" && "bg-critical",
                stage.status === "RUNNING" && "bg-primary",
                stage.status === "SKIPPED" && "bg-unknown/40",
                stage.status === "PENDING" && "bg-muted",
              )}
              animate={stage.status === "RUNNING" ? { opacity: [0.35, 1, 0.35] } : { opacity: 1 }}
              transition={
                stage.status === "RUNNING"
                  ? { duration: 1.4, repeat: Infinity, ease: "easeInOut" }
                  : { duration: DURATION.quick / 1000 }
              }
            />
          ))}
        </div>
      </div>

      <ul className="flex flex-col gap-1.5">
        {lanes.map((stage, i) => (
          <motion.li
            key={stage.scope ?? `scope-${i}`}
            layout
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: DURATION.quick / 1000, ease: EASE_OUT }}
            className={cn(
              "flex flex-col gap-1 rounded-lg border px-3 py-2",
              stage.status === "FAILED" && "border-critical-border bg-critical-bg",
              stage.status === "RUNNING" && "border-primary/40",
            )}
          >
            <div className="flex items-center gap-2.5">
              <LaneMark status={stage.status} />
              <span className="min-w-0 flex-1 truncate text-sm">{stage.scope ?? "Scope"}</span>
              {stage.attempt > 1 && (
                <span className="shrink-0 text-xs text-muted-foreground">attempt {stage.attempt}</span>
              )}
              <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
                {stage.duration_seconds != null && stage.status !== "PENDING"
                  ? formatSeconds(stage.duration_seconds)
                  : label(stage.status)}
              </span>
            </div>
            {stage.status === "FAILED" && stage.error && (
              <p className="pl-6 text-xs leading-relaxed text-critical">{stage.error}</p>
            )}
          </motion.li>
        ))}
      </ul>
    </div>
  );
}

function LaneMark({ status }: { status: ScanStage["status"] }) {
  if (status === "RUNNING") return <Spinner className="size-3.5 shrink-0" />;
  if (status === "SUCCEEDED") return <CheckIcon className="size-3.5 shrink-0 text-ok" aria-hidden />;
  if (status === "FAILED") return <XIcon className="size-3.5 shrink-0 text-critical" aria-hidden />;
  if (status === "SKIPPED")
    return <MinusIcon className="size-3.5 shrink-0 text-unknown" aria-hidden />;
  return <span className="mx-1 size-1.5 shrink-0 rounded-full bg-muted-foreground/40" aria-hidden />;
}

const OUTCOME: Record<string, { title: string; tone: string; description: string }> = {
  COMPLETED: {
    title: "Scan complete",
    tone: "border-ok-border",
    description: "Every scope was read and every rule evaluated.",
  },
  PARTIAL: {
    title: "Completed with gaps",
    tone: "border-medium-border",
    description: "Some scopes or categories could not be read. Checks that depend on them are UNKNOWN, not passed.",
  },
  FAILED: {
    title: "Scan failed",
    tone: "border-critical-border",
    description: "This run did not produce results. Findings from earlier scans are unchanged.",
  },
  CANCELLED: {
    title: "Scan cancelled",
    tone: "border-border",
    description: "Stopped before it finished. Findings from earlier scans are unchanged.",
  },
};

/**
 * How the scan ended, and what changed because of it.
 *
 * A partial scan ends amber, never green: data came back, and it still cannot
 * support a pass for what it did not read. The comparison is with the last
 * finished scan of the same connection, and is left out rather than guessed
 * when there is none.
 */
function ScanResult({
  scan,
  previous,
  onRunAnother,
}: {
  scan: ScanDetail;
  previous: Scan | undefined;
  onRunAnother: () => void;
}) {
  const outcome = OUTCOME[scan.status] ?? {
    title: label(scan.status),
    tone: "border-border",
    description: "",
  };
  const errors = Object.entries(scan.collection_errors ?? {});
  const severities = SEVERITY_ORDER.filter((level) => (scan.findings_by_severity[level] ?? 0) > 0);
  const delta = previous ? scan.finding_count - previous.finding_count : null;

  return (
    <motion.div initial={fadeUp.initial} animate={fadeUp.animate}>
      <Card className={cn("border", outcome.tone)}>
        <CardHeader>
          <CardTitle>{outcome.title}</CardTitle>
          <CardDescription>{outcome.description}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {scan.error_message && (
            <Alert variant="destructive">
              <AlertDescription>{scan.error_message}</AlertDescription>
            </Alert>
          )}

          <div className="grid grid-cols-3 gap-3">
            <Counter label="Resources" value={scan.resource_count} />
            <Counter label="Rules run" value={scan.rule_count} />
            <Counter label="Findings" value={scan.finding_count} />
          </div>

          {delta !== null && (
            <p className="text-xs text-muted-foreground">
              {delta === 0 ? (
                "Same number of findings as the last scan."
              ) : (
                <>
                  <span className={cn("font-medium", delta > 0 ? "text-critical" : "text-ok")}>
                    {delta > 0 ? `+${delta}` : delta}
                  </span>{" "}
                  findings since the last scan.
                </>
              )}
            </p>
          )}

          {severities.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {severities.map((level) => (
                <SeverityBadge key={level} level={level}>
                  {label(level)} {scan.findings_by_severity[level]}
                </SeverityBadge>
              ))}
            </div>
          )}

          {errors.length > 0 && (
            <ul className="flex flex-col gap-1 rounded-lg border border-medium-border bg-medium-bg px-3 py-2">
              {errors.slice(0, 3).map(([scope, reason]) => (
                <li key={scope} className="text-xs">
                  <strong>{scope}</strong>
                  <span className="text-muted-foreground"> — {reason}</span>
                </li>
              ))}
              {errors.length > 3 && (
                <li className="text-xs text-muted-foreground">and {errors.length - 3} more</li>
              )}
            </ul>
          )}
        </CardContent>
        <CardFooter className="flex flex-wrap gap-2">
          <Link to="/findings" className={buttonVariants({ size: "sm" })}>
            View findings
          </Link>
          <Link to="/scans" className={buttonVariants({ variant: "outline", size: "sm" })}>
            Scan history
          </Link>
          <Button variant="ghost" size="sm" className="ml-auto" onClick={onRunAnother}>
            Run another
          </Button>
        </CardFooter>
      </Card>
    </motion.div>
  );
}

function Counter({ label: text, value }: { label: string; value: number }) {
  const shown = useCountUp(value);
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-muted-foreground">{text}</span>
      <span className="text-xl font-semibold tabular-nums">{Math.round(shown)}</span>
    </div>
  );
}
