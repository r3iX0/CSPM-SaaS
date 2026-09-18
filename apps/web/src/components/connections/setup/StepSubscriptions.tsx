import { Link } from "react-router-dom";
import { motion } from "motion/react";
import { CheckIcon, PlayIcon } from "lucide-react";

import type { CloudConnection } from "@/lib/types";
import { useT } from "@/i18n";
import { words } from "@/lib/vocabulary";
import { DiscoveryRetry } from "@/components/connections/DiscoveryRetry";
import { SubscriptionScopeList } from "@/components/connections/SubscriptionScopeList";
import { StepHeader } from "@/components/connections/setup/StepHeader";
import { useScanWizard } from "@/components/scans/ScanWizardProvider";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/format";

/**
 * The last step: what CloudGuard found, and what it will read.
 *
 * Three states of one step rather than three steps. Discovery runs server-side
 * on every read of the connection, so between "verified" and "here is what is
 * beneath it" there is a gap of a few seconds -- occasionally of minutes, if
 * the grant landed at a narrower scope than the connection covers and the
 * answer is going to be nothing at all. The customer is in the same place
 * throughout; only what is on the page changes.
 *
 * Setup ends on a scan, not on a green tick -- and now on the scan itself
 * rather than on a link to the page where scans live. The button opens the
 * scan wizard on this connection's review step, so the moment setup finishes
 * the next click is the one that produces findings.
 */
export function StepSubscriptions({
  connection,
  onError,
}: {
  connection: CloudConnection;
  onError: (message: string) => void;
}) {
  const t = useT();
  const scanWizard = useScanWizard();
  const subscriptions = connection.subscriptions ?? [];
  const scoped = subscriptions.filter((s) => s.in_scope);
  const vocabulary = words(connection.provider);

  if (subscriptions.length === 0) {
    return <DiscoveryRetry connection={connection} onError={onError} />;
  }

  const noun = (subscriptions.length === 1 ? vocabulary.Account : vocabulary.Accounts)
    .toLowerCase();

  return (
    <>
      {connection.is_ready_to_scan ? (
        <div className="flex flex-col gap-5 rounded-xl border border-ok-border bg-ok-bg p-5 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-4">
            {/* The one flourish in the flow, and it is earned: this is the
                moment both grants have landed and something can be read. */}
            <motion.span
              initial={{ scale: 0.6, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ type: "spring", stiffness: 420, damping: 22 }}
              className="flex size-11 shrink-0 items-center justify-center rounded-full bg-ok text-background shadow-sm"
            >
              <CheckIcon className="size-5" strokeWidth={3} aria-hidden />
            </motion.span>
            <div className="min-w-0">
              <h2 className="text-base font-semibold tracking-tight text-foreground">
                {t.setup.doneHeadline.replace("{name}", connection.name)}
              </h2>
              <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
                {t.setup.doneSummary
                  .replace("{inScope}", String(scoped.length))
                  .replace("{total}", String(subscriptions.length))
                  .replace("{accounts}", noun)}
              </p>
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap gap-2">
            <Link
              to="/connections"
              className={cn(buttonVariants({ variant: "outline", size: "lg" }), "px-4")}
            >
              {t.setup.backToList}
            </Link>
            <Button size="lg" className="px-4" onClick={() => scanWizard.start(connection.id)}>
              <PlayIcon data-icon="inline-start" aria-hidden />
              {t.setup.runFirstScan}
            </Button>
          </div>
        </div>
      ) : (
        <StepHeader title={t.setup.reviewTitle} description={t.setup.reviewBody} />
      )}

      <div>
        {connection.is_ready_to_scan && (
          <p className="mb-3 text-sm font-medium text-foreground">{t.setup.reviewTitle}</p>
        )}
        <SubscriptionScopeList connection={connection} onError={onError} />
      </div>

      {/* Found something, but cannot scan it. Two different reasons, and the
          difference matters: everything ticked off is a choice the reader made
          and can undo in the list above, whereas rows that are in scope and
          still unscannable are a grant that did not reach them. */}
      {!connection.is_ready_to_scan && (
        <Alert className="border-high-border bg-high-bg text-high">
          <AlertTitle>
            {scoped.length === 0
              ? t.setup.nothingInScopeTitle
              : t.connection.noSubscriptionsYet}
          </AlertTitle>
          <AlertDescription className="text-foreground">
            {scoped.length === 0
              ? t.setup.nothingInScopeBody
              : t.connection.noSubscriptionsYetHelp}
          </AlertDescription>
        </Alert>
      )}
    </>
  );
}
