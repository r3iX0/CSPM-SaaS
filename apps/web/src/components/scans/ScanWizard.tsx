import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, m } from "motion/react";
import { CheckIcon, CloudIcon, PlayIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import type { CloudConnection, Scan } from "@/lib/types";
import { collectionCategoryLabel, cn, formatSeconds } from "@/lib/format";
import { DURATION, EASE_IN, EASE_OUT } from "@/lib/motion";
import { useIsDemo } from "@/lib/useDemo";
import { words } from "@/lib/vocabulary";
import { IN_FLIGHT } from "@/components/scans/status";
import { ScanPipeline, ScanResult } from "@/components/scans/ScanPipeline";
import { ScanDetailPanel } from "@/components/scans/ScanDetailPanel";
import { useLiveScan } from "@/components/scans/useLiveScan";
import { ProviderMark } from "@/components/security/ProviderMark";
import { EmptyState } from "@/components/common/states";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Field,
  FieldDescription,
  FieldLabel,
  FieldLegend,
  FieldSet,
} from "@/components/ui/field";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

type Step = "scope" | "review" | "run" | "result";

const STEPS: { id: Step; label: string }[] = [
  { id: "scope", label: "Environment" },
  { id: "review", label: "Review" },
  { id: "run", label: "Scan" },
  { id: "result", label: "Result" },
];

/**
 * Starting a scan, watching it run, and reading how it ended, as one dialog.
 *
 * Four steps, and the second is the reason this is a wizard rather than a
 * button: before Cleave reads anybody's cloud it says what it is about to
 * read, roughly how long that took last time, and which checks will come back
 * inconclusive because the deployed role cannot serve them. A scan started
 * without that is a scan whose UNKNOWNs arrive as a surprise. The fourth is
 * its own step so that a scan finishing is something the step bar says, not
 * only something the body swaps into.
 *
 * It is also the one view of any scan, finished or not: a row in the scan
 * history opens it on that scan, so there is no second, smaller live view on
 * the scans page drifting out of step with this one (DECISIONS.md §154).
 *
 * A scan is scoped to a whole connection -- the worker resolves the
 * subscriptions beneath it -- so the first step chooses an environment, not a
 * subscription, and is skipped when only one environment can be scanned.
 * Which subscriptions are in scope is a property of the connection, changed on
 * the connections page, and review links there rather than offering a choice
 * the API would ignore.
 *
 * Closing is minimising. The scan goes on; the header's indicator reopens it.
 */
export function ScanWizard({
  open,
  onClose,
  scanId,
  initialConnectionId,
  onScanStarted,
  onRunAnother,
}: {
  open: boolean;
  onClose: () => void;
  scanId: string | null;
  initialConnectionId: string | null;
  onScanStarted: (scanId: string) => void;
  onRunAnother: () => void;
}) {
  return (
    <Dialog open={open} onOpenChange={(next) => !next && onClose()}>
      {/* A dialog on a desk, the whole screen on a phone: the lanes of a
          forty-subscription tenant do not fit a narrow card. */}
      <DialogContent
        // Opened on a scan, the dialog itself takes focus, announced by its
        // title. Left to the default, focus landed on the first control in
        // the footer -- "Run another" on a finished scan -- so Enter started
        // a new scan (DECISIONS.md §187). Setup keeps the default: its first
        // control is the choice the reader came to make.
        initialFocus={
          scanId
            ? () => document.querySelector<HTMLElement>('[data-slot="dialog-content"]')
            : true
        }
        className={cn(
          "flex max-h-[calc(100dvh-4rem)] flex-col gap-0 p-0 sm:max-w-2xl",
          "max-sm:inset-0 max-sm:max-h-none max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:rounded-none",
        )}
      >
        {scanId ? (
          <ScanSession
            key={scanId}
            scanId={scanId}
            onRunAnother={onRunAnother}
            onMinimize={onClose}
          />
        ) : (
          <SetupFlow
            initialConnectionId={initialConnectionId}
            onStarted={onScanStarted}
            onLeave={onClose}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

/** Header, a body that scrolls, and a footer that does not: every step's shape. */
function Frame({
  step,
  title,
  description,
  children,
  footer,
}: {
  step: Step;
  title: string;
  description: string;
  children: ReactNode;
  footer: ReactNode;
}) {
  return (
    <>
      <DialogHeader className="gap-3 border-b px-4 pt-4 pb-3">
        <div className="flex flex-col gap-1.5 pr-8">
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </div>
        <Stepper current={step} />
      </DialogHeader>

      <div className="min-h-0 flex-1 overflow-y-auto px-4">
        <AnimatePresence mode="wait" initial={false}>
          <m.div
            key={step}
            initial={{ opacity: 0, x: 12 }}
            animate={{
              opacity: 1,
              x: 0,
              transition: { duration: DURATION.page / 1000, ease: EASE_OUT },
            }}
            exit={{
              opacity: 0,
              x: -8,
              transition: { duration: DURATION.instant / 1000, ease: EASE_IN },
            }}
            className="py-4"
          >
            {children}
          </m.div>
        </AnimatePresence>
      </div>

      <DialogFooter className="mx-0 mb-0 items-center sm:justify-between max-sm:rounded-none">
        {footer}
      </DialogFooter>
    </>
  );
}

/**
 * Where the reader is in the four steps.
 *
 * The connector between two steps fills when the first is done, so moving on
 * reads as progress along one line rather than as a panel being swapped.
 */
function Stepper({ current }: { current: Step }) {
  const index = STEPS.findIndex((s) => s.id === current);

  return (
    <ol className="flex items-center gap-2" aria-label="Scan steps">
      {STEPS.map((step, i) => {
        const done = i < index;
        const active = i === index;
        return (
          <li key={step.id} className="flex flex-1 items-center gap-2 last:flex-none">
            <span
              aria-current={active ? "step" : undefined}
              className={cn(
                "flex size-6 shrink-0 items-center justify-center rounded-full border text-xs font-medium transition-colors",
                done && "border-primary bg-primary text-primary-foreground",
                active && "border-primary text-foreground",
                !done && !active && "text-muted-foreground",
              )}
            >
              {done ? <CheckIcon className="size-3.5" aria-hidden /> : i + 1}
            </span>
            {/* On a phone only the current step is named; the rest are its
                numbers, and a screen reader still hears every name. */}
            <span
              className={cn(
                "text-xs whitespace-nowrap",
                active ? "font-medium text-foreground" : "text-muted-foreground max-sm:sr-only",
              )}
            >
              {step.label}
            </span>
            {i < STEPS.length - 1 && (
              <span className="relative h-px flex-1 overflow-hidden bg-border" aria-hidden>
                <m.span
                  className="absolute inset-0 origin-left bg-primary"
                  initial={false}
                  animate={{ scaleX: done ? 1 : 0 }}
                  transition={{ duration: DURATION.page / 1000, ease: EASE_OUT }}
                />
              </span>
            )}
          </li>
        );
      })}
    </ol>
  );
}

/** Environment and Review: everything before a scan exists. */
function SetupFlow({
  initialConnectionId,
  onStarted,
  onLeave,
}: {
  initialConnectionId: string | null;
  onStarted: (scanId: string) => void;
  onLeave: () => void;
}) {
  const queryClient = useQueryClient();
  // Null until the reader moves: the first step is then chosen from what the
  // connections are, once they have loaded.
  const [step, setStep] = useState<"scope" | "review" | null>(
    initialConnectionId ? "review" : null,
  );
  const [chosen, setChosen] = useState(initialConnectionId ?? "");
  const [error, setError] = useState<string | null>(null);

  const connections = useQuery({
    queryKey: ["cloud-connections"],
    queryFn: () =>
      api.get<CloudConnection[]>("/api/v1/cloud-connections").then((r) => r.data),
  });

  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.get<Scan[]>("/api/v1/scans").then((r) => r.data),
  });

  const rows = connections.data ?? [];
  const ready = rows.filter((c) => c.is_ready_to_scan);
  const selectedId = chosen || ready[0]?.id || "";
  const selected = rows.find((c) => c.id === selectedId);
  const loaded = connections.data !== undefined;

  // One environment that can be scanned leaves nothing to choose, so the
  // wizard opens on review; Back still reaches the list.
  const wanted = step ?? (loaded && ready.length === 1 ? "review" : "scope");
  const current = wanted === "review" && loaded && !selected ? "scope" : wanted;

  const inScope = selected?.subscriptions.filter((s) => s.in_scope) ?? [];
  const target =
    inScope.find((s) => s.is_scannable) ??
    selected?.subscriptions.find((s) => s.is_scannable);

  const start = useMutation({
    mutationFn: () =>
      api
        .post<Scan>("/api/v1/scans", { cloud_account_id: target?.id })
        .then((r) => r.data),
    onSuccess: (scan) => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      if (scan) onStarted(scan.id);
    },
    onError: async (err) => {
      // Refused because one is already running: follow that one instead of
      // reporting a conflict the reader can do nothing about.
      if (err instanceof ApiError && err.status === 409) {
        const fresh = await api.get<Scan[]>("/api/v1/scans").then((r) => r.data);
        const running = fresh?.find(
          (s) => s.connection_id === selected?.id && IN_FLIGHT.includes(s.status),
        );
        if (running) {
          onStarted(running.id);
          return;
        }
      }
      setError(err instanceof ApiError ? err.message : "Could not start the scan");
    },
  });

  return (
    <Frame
      step={current}
      title="Run a scan"
      description="Cleave reads your environment with the role you deployed. Nothing is changed."
      footer={
        current === "scope" ? (
          <Button
            className="sm:ml-auto"
            disabled={!selected?.is_ready_to_scan}
            onClick={() => setStep("review")}
          >
            Continue
          </Button>
        ) : (
          <>
            <Button variant="ghost" onClick={() => setStep("scope")}>
              Back
            </Button>
            <Button disabled={!target || start.isPending} onClick={() => start.mutate()}>
              {start.isPending ? (
                <Spinner data-icon="inline-start" />
              ) : (
                <PlayIcon data-icon="inline-start" />
              )}
              Start scan
            </Button>
          </>
        )
      }
    >
      {!loaded ? (
        <div className="flex flex-col gap-2">
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-16 w-full" />
        </div>
      ) : current === "scope" ? (
        <ScopeStep
          connections={rows}
          scans={scans.data ?? []}
          value={selectedId}
          onChange={setChosen}
          onWatch={onStarted}
          onLeave={onLeave}
        />
      ) : (
        selected && (
          <ReviewStep
            connection={selected}
            scans={scans.data ?? []}
            error={error}
            onLeave={onLeave}
          />
        )
      )}
    </Frame>
  );
}

function ScopeStep({
  connections,
  scans,
  value,
  onChange,
  onWatch,
  onLeave,
}: {
  connections: CloudConnection[];
  scans: Scan[];
  value: string;
  onChange: (id: string) => void;
  onWatch: (scanId: string) => void;
  onLeave: () => void;
}) {
  if (connections.length === 0) {
    return (
      <EmptyState
        icon={CloudIcon}
        title="No cloud connected"
        detail="Connect an environment first. A scan reads through the role that connection deploys."
        action={
          <Link to="/connections/new" className={buttonVariants()} onClick={onLeave}>
            Connect a cloud
          </Link>
        }
      />
    );
  }

  return (
    <FieldSet>
      <FieldLegend variant="label">Which environment?</FieldLegend>
      <RadioGroup value={value} onValueChange={(next) => onChange(String(next))}>
        {connections.map((connection) => {
          const vocabulary = words(connection.provider);
          const inScope = connection.subscriptions.filter((s) => s.in_scope).length;
          const running = scans.find(
            (s) => s.connection_id === connection.id && IN_FLIGHT.includes(s.status),
          );
          return (
            <FieldLabel
              key={connection.id}
              htmlFor={`scan-connection-${connection.id}`}
              className={cn(
                "flex cursor-pointer items-start gap-3 rounded-lg border px-4 py-3 transition-colors",
                value === connection.id ? "border-foreground bg-muted/40" : "hover:border-input",
                !connection.is_ready_to_scan && "cursor-not-allowed opacity-60",
              )}
            >
              <RadioGroupItem
                id={`scan-connection-${connection.id}`}
                value={connection.id}
                disabled={!connection.is_ready_to_scan}
                className="mt-1"
              />
              <span className="flex min-w-0 flex-1 flex-col gap-0.5">
                <span className="flex items-center gap-2 text-sm font-medium text-foreground">
                  <ProviderMark provider={connection.provider} />
                  <span className="truncate">{connection.name}</span>
                </span>
                <span className="text-xs text-muted-foreground">
                  {connection.is_ready_to_scan
                    ? `${inScope} ${vocabulary.Account.toLowerCase()}${inScope === 1 ? "" : "s"} in scope`
                    : "Finish setting up this connection before scanning it"}
                </span>
              </span>
              {/* A second scan of the same connection is refused, so the
                  honest offer is to follow the one already running. */}
              {running && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={(event) => {
                    event.preventDefault();
                    onWatch(running.id);
                  }}
                >
                  Scan running · watch
                </Button>
              )}
            </FieldLabel>
          );
        })}
      </RadioGroup>
    </FieldSet>
  );
}

function ReviewStep({
  connection,
  scans,
  error,
  onLeave,
}: {
  connection: CloudConnection;
  scans: Scan[];
  error: string | null;
  onLeave: () => void;
}) {
  const vocabulary = words(connection.provider);
  const inScope = connection.subscriptions.filter((s) => s.in_scope);

  // The last run that finished, as the only honest basis for an estimate.
  const last = [...scans]
    .filter(
      (s) =>
        s.connection_id === connection.id &&
        s.duration_seconds != null &&
        (s.status === "COMPLETED" || s.status === "PARTIAL"),
    )
    .sort((a, b) => b.created_at.localeCompare(a.created_at))[0];

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center gap-3">
        <span className="flex size-9 items-center justify-center rounded-lg border bg-muted/50 text-muted-foreground">
          <ProviderMark provider={connection.provider} />
        </span>
        <div className="min-w-0">
          <p className="truncate text-sm font-medium">{connection.name}</p>
          <p className="text-xs text-muted-foreground">
            {last
              ? `About ${formatSeconds(last.duration_seconds ?? 0)}, based on the last run`
              : "No finished run yet to estimate from"}
          </p>
        </div>
      </div>

      <Field>
        <FieldLabel>What will be read</FieldLabel>
        <FieldDescription>
          Each {vocabulary.Account.toLowerCase()} in scope, plus the directory.{" "}
          <Link
            to={`/connections?id=${connection.id}`}
            onClick={onLeave}
            className="underline underline-offset-2 hover:text-foreground"
          >
            Change scope
          </Link>
        </FieldDescription>
        <ul className="flex flex-col divide-y rounded-lg border">
          {inScope.length === 0 && (
            <li className="px-3 py-2 text-xs text-muted-foreground">
              Nothing is in scope yet.
            </li>
          )}
          {inScope.map((subscription) => (
            <li key={subscription.id} className="flex items-center justify-between gap-3 px-3 py-2">
              <span className="truncate text-sm">
                {subscription.display_name ?? subscription.subscription_id}
              </span>
              <span
                className={cn(
                  "shrink-0 text-xs",
                  subscription.is_scannable ? "text-muted-foreground" : "text-high",
                )}
              >
                {subscription.is_scannable ? "Readable" : "Not readable yet"}
              </span>
            </li>
          ))}
        </ul>
      </Field>

      {connection.degraded_categories.length > 0 && (
        <Alert>
          <AlertTitle>Some checks will come back inconclusive</AlertTitle>
          <AlertDescription>
            The deployed role cannot fully read:{" "}
            {connection.degraded_categories.map(collectionCategoryLabel).join(", ")}. Those
            checks report UNKNOWN, never a pass, until the role is redeployed.
          </AlertDescription>
        </Alert>
      )}

      {error && (
        <Alert variant="destructive">
          <AlertTitle>Could not start the scan</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
    </div>
  );
}

/**
 * Scan and Result: one scan, from the moment it exists.
 *
 * Cancelling asks once more, in place. A scan stopped by a stray click has to
 * be started again from the top and read the whole estate twice, so the
 * footer's main button is the one that leaves it running.
 */
function ScanSession({
  scanId,
  onRunAnother,
  onMinimize,
}: {
  scanId: string;
  onRunAnother: () => void;
  onMinimize: () => void;
}) {
  const queryClient = useQueryClient();
  const isDemo = useIsDemo();
  const { data, running, previous } = useLiveScan(scanId);
  const [confirming, setConfirming] = useState(false);

  const cancel = useMutation({
    mutationFn: () => api.post<Scan>(`/api/v1/scans/${scanId}/cancel`),
    onSuccess: () => {
      setConfirming(false);
      queryClient.invalidateQueries({ queryKey: ["scan-detail", scanId] });
    },
  });

  const step: Step = data && !running ? "result" : "run";

  return (
    <Frame
      step={step}
      title={step === "result" ? "Scan finished" : "Scan running"}
      description={
        step === "result"
          ? "How this run ended, and what it changed."
          : "Closing this does not stop the scan. The header keeps its progress."
      }
      footer={
        step === "run" ? (
          <>
            {/* Nothing in the demo is stopped or re-run: it is a recording
                others share. The empty span keeps the main button right. */}
            {isDemo ? (
              <span />
            ) : confirming ? (
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">Stop this scan?</span>
                <Button variant="ghost" size="sm" onClick={() => setConfirming(false)}>
                  Keep running
                </Button>
                <Button
                  variant="destructive"
                  size="sm"
                  disabled={cancel.isPending}
                  onClick={() => cancel.mutate()}
                >
                  {cancel.isPending ? "Cancelling…" : "Stop scan"}
                </Button>
              </div>
            ) : (
              <Button variant="ghost" disabled={!data} onClick={() => setConfirming(true)}>
                Cancel scan
              </Button>
            )}
            <Button onClick={onMinimize}>Run in background</Button>
          </>
        ) : (
          <>
            {isDemo ? (
              <span />
            ) : (
              <Button variant="ghost" onClick={onRunAnother}>
                Run another
              </Button>
            )}
            {/* Links rather than buttons, and no close handler: the scan is
                in the URL, so leaving the page is what closes the dialog. */}
            <div className="flex flex-col-reverse gap-2 sm:flex-row">
              <Link to="/scans" className={buttonVariants({ variant: "outline" })}>
                Scan history
              </Link>
              <Link to="/findings" className={buttonVariants()}>
                View findings
              </Link>
            </div>
          </>
        )
      }
    >
      {!data ? (
        <div className="flex flex-col gap-3">
          <Skeleton className="h-14 w-full" />
          <Skeleton className="h-24 w-full" />
        </div>
      ) : step === "run" ? (
        <ScanPipeline scan={data} />
      ) : (
        <Tabs defaultValue="result" className="flex flex-col gap-4">
          <TabsList>
            <TabsTrigger value="result">Result</TabsTrigger>
            <TabsTrigger value="details">Details</TabsTrigger>
          </TabsList>
          <TabsContent value="result">
            <ScanResult scan={data} previous={previous} />
          </TabsContent>
          <TabsContent value="details">
            <ScanDetailPanel scanId={scanId} />
          </TabsContent>
        </Tabs>
      )}
    </Frame>
  );
}
