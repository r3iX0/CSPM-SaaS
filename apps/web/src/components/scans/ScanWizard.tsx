import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion } from "motion/react";
import { CheckIcon, CloudIcon, PlayIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import type { CloudConnection, Scan } from "@/lib/types";
import { collectionCategoryLabel, cn, formatSeconds } from "@/lib/format";
import { DURATION, EASE_IN, EASE_OUT } from "@/lib/motion";
import { words } from "@/lib/vocabulary";
import { IN_FLIGHT } from "@/components/scans/status";
import { ScanPipeline } from "@/components/scans/ScanPipeline";
import { ProviderMark } from "@/components/security/ProviderMark";
import { EmptyState } from "@/components/common/states";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import {
  Field,
  FieldDescription,
  FieldLabel,
  FieldLegend,
  FieldSet,
} from "@/components/ui/field";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";

type Step = "scope" | "review" | "run";

const STEPS: { id: Step; label: string }[] = [
  { id: "scope", label: "Environment" },
  { id: "review", label: "Review" },
  { id: "run", label: "Scan" },
];

/**
 * Starting a scan, and watching it run, as one guided panel.
 *
 * Three steps, and the second is the reason this is a wizard rather than a
 * button: before CloudGuard reads anybody's cloud it says what it is about to
 * read, roughly how long that took last time, and which checks will come back
 * inconclusive because the deployed role cannot serve them. A scan started
 * without that is a scan whose UNKNOWNs arrive as a surprise.
 *
 * A scan is scoped to a whole connection -- the worker resolves the
 * subscriptions beneath it -- so the first step chooses an environment, not a
 * subscription. Which subscriptions are in scope is a property of the
 * connection, changed on the connections page, and review links there rather
 * than offering a choice the API would ignore.
 */
export function ScanWizard({
  open,
  onOpenChange,
  scanId,
  initialConnectionId,
  onScanStarted,
  onRunAnother,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  scanId: string | null;
  initialConnectionId: string | null;
  onScanStarted: (scanId: string) => void;
  onRunAnother: () => void;
}) {
  const [step, setStep] = useState<Exclude<Step, "run">>(
    initialConnectionId ? "review" : "scope",
  );
  const [chosen, setChosen] = useState(initialConnectionId ?? "");
  const current: Step = scanId ? "run" : step;

  const connections = useQuery({
    queryKey: ["cloud-connections"],
    queryFn: () =>
      api.get<CloudConnection[]>("/api/v1/cloud-connections").then((r) => r.data),
    enabled: open,
  });

  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.get<Scan[]>("/api/v1/scans").then((r) => r.data),
    enabled: open,
  });

  const rows = connections.data ?? [];
  const ready = rows.filter((c) => c.is_ready_to_scan);
  const selectedId = chosen || ready[0]?.id || "";
  const selected = rows.find((c) => c.id === selectedId);

  return (
    <Sheet open={open} onOpenChange={(next) => onOpenChange(next)}>
      <SheetContent className="w-full data-[side=right]:sm:max-w-xl">
        <SheetHeader className="gap-3 border-b">
          <div>
            <SheetTitle>{current === "run" ? "Scan" : "Run a scan"}</SheetTitle>
            <SheetDescription>
              {current === "run"
                ? "Closing this panel does not stop the scan. The header keeps its progress."
                : "CloudGuard reads your environment with the role you deployed. Nothing is changed."}
            </SheetDescription>
          </div>
          <Stepper current={current} />
        </SheetHeader>

        <div className="flex-1 overflow-y-auto px-4">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={current}
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
            >
              {current === "scope" && (
                <ScopeStep
                  loading={connections.isLoading}
                  connections={rows}
                  scans={scans.data ?? []}
                  value={selectedId}
                  onChange={setChosen}
                  onWatch={onScanStarted}
                />
              )}
              {current === "review" && selected && (
                <ReviewStep
                  connection={selected}
                  scans={scans.data ?? []}
                  onBack={() => setStep("scope")}
                  onStarted={onScanStarted}
                />
              )}
              {current === "run" && scanId && (
                <ScanPipeline
                  scanId={scanId}
                  onRunAnother={onRunAnother}
                  onMinimize={() => onOpenChange(false)}
                />
              )}
            </motion.div>
          </AnimatePresence>
        </div>

        {current === "scope" && (
          <SheetFooter className="border-t">
            <Button disabled={!selected?.is_ready_to_scan} onClick={() => setStep("review")}>
              Continue
            </Button>
          </SheetFooter>
        )}
      </SheetContent>
    </Sheet>
  );
}

/**
 * Where the reader is in the three steps.
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
            <span
              className={cn(
                "text-xs whitespace-nowrap",
                active ? "font-medium text-foreground" : "text-muted-foreground",
              )}
            >
              {step.label}
            </span>
            {i < STEPS.length - 1 && (
              <span className="relative h-px flex-1 overflow-hidden bg-border" aria-hidden>
                <motion.span
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

function ScopeStep({
  loading,
  connections,
  scans,
  value,
  onChange,
  onWatch,
}: {
  loading: boolean;
  connections: CloudConnection[];
  scans: Scan[];
  value: string;
  onChange: (id: string) => void;
  onWatch: (scanId: string) => void;
}) {
  if (loading) {
    return (
      <div className="flex flex-col gap-2 py-4">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-16 w-full" />
      </div>
    );
  }

  if (connections.length === 0) {
    return (
      <EmptyState
        className="my-4"
        icon={CloudIcon}
        title="No cloud connected"
        detail="Connect an environment first. A scan reads through the role that connection deploys."
        action={
          <Link to="/connections/new" className={buttonVariants()}>
            Connect a cloud
          </Link>
        }
      />
    );
  }

  return (
    <FieldSet className="py-4">
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
  onBack,
  onStarted,
}: {
  connection: CloudConnection;
  scans: Scan[];
  onBack: () => void;
  onStarted: (scanId: string) => void;
}) {
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const vocabulary = words(connection.provider);

  const inScope = connection.subscriptions.filter((s) => s.in_scope);
  const target =
    inScope.find((s) => s.is_scannable) ??
    connection.subscriptions.find((s) => s.is_scannable);

  // The last run that finished, as the only honest basis for an estimate.
  const last = [...scans]
    .filter(
      (s) =>
        s.connection_id === connection.id &&
        s.duration_seconds != null &&
        (s.status === "COMPLETED" || s.status === "PARTIAL"),
    )
    .sort((a, b) => b.created_at.localeCompare(a.created_at))[0];

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
          (s) => s.connection_id === connection.id && IN_FLIGHT.includes(s.status),
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
    <div className="flex flex-col gap-5 py-4">
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

      <div className="flex items-center justify-between gap-2">
        <Button variant="ghost" onClick={onBack}>
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
      </div>
    </div>
  );
}
