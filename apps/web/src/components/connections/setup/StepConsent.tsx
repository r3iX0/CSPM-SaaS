import { useState } from "react";
import { AnimatePresence, motion } from "motion/react";

import type { CloudConnection } from "@/lib/types";
import { useT } from "@/i18n";
import { SETUP_ICONS } from "@/lib/icons";
import { DURATION, EASE_OUT } from "@/lib/motion";
import { CopyButton } from "@/components/common/CopyButton";
import { ProviderMark } from "@/components/security/ProviderMark";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/format";
import { StepHeader } from "@/components/connections/setup/StepHeader";
import { WaitingNote } from "@/components/connections/setup/WaitingNote";

/**
 * Step two: admin consent.
 *
 * The step that most often cannot be finished by the person looking at it.
 * Admin consent needs a Global Administrator, and the customer evaluating
 * CloudGuard usually is not one -- so the handoff is a first-class branch here
 * rather than a sentence of advice. Sending the link is a way of completing the
 * step, not a way of giving up on it, which is why it sits beside the primary
 * action as a button of its own rather than beneath it as a link.
 *
 * Nothing is polled from this component: the wizard re-reads the connection
 * every few seconds and this step disappears when consent lands, whether it was
 * granted in this browser or in someone else's an hour from now.
 */
export function StepConsent({
  connection,
  consentError,
  onDismissError,
}: {
  connection: CloudConnection;
  consentError: string | null;
  onDismissError: () => void;
}) {
  const t = useT();
  const [handoff, setHandoff] = useState(false);
  const LeavesApp = SETUP_ICONS.leavesApp;
  const Handoff = SETUP_ICONS.handoff;
  const Expiry = SETUP_ICONS.expiry;

  // Consent cannot be started at all -- no signed link to offer. A dead end
  // with a reason, rather than a button that would 404 at Microsoft.
  if (!connection.consent_url) {
    return (
      <Alert className="border-high-border bg-high-bg text-high">
        <AlertTitle>{t.connection.cannotStartConsent}</AlertTitle>
        <AlertDescription className="text-foreground">
          {connection.status_detail}
        </AlertDescription>
      </Alert>
    );
  }

  const message = `${t.setup.handoffMessage}\n\n${connection.consent_url}`;

  return (
    <>
      <StepHeader
        mark={<ProviderMark provider={connection.provider} className="size-5" />}
        title={t.setup.consentTitle}
        description={t.setup.consentBody}
      />

      {/* Azure's own reason for the last attempt, carried back through the
          callback. Shown inside the step it belongs to: the retry is the button
          directly beneath it, which a page-level banner could not say. */}
      {consentError && (
        <Alert variant="destructive">
          <AlertTitle>{t.setup.consentFailed}</AlertTitle>
          <AlertDescription>
            <p>{consentError}</p>
            <Button variant="outline" size="sm" className="mt-2" onClick={onDismissError}>
              {t.setup.consentRetry}
            </Button>
          </AlertDescription>
        </Alert>
      )}

      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          {/* An anchor wearing the button's clothes, not a Button rendering an
              anchor: this leaves the application, and Base UI's Button expects
              a real <button> underneath it. */}
          <a
            href={connection.consent_url}
            target="_blank"
            rel="noopener noreferrer"
            className={cn(buttonVariants({ size: "lg" }), "px-4")}
          >
            {t.connection.openConsent}
            <LeavesApp data-icon="inline-end" aria-hidden />
          </a>
          {!handoff && (
            <Button
              type="button"
              variant="outline"
              size="lg"
              className="px-4"
              onClick={() => setHandoff(true)}
            >
              <Handoff data-icon="inline-start" aria-hidden />
              {t.setup.notAdmin}
            </Button>
          )}
        </div>
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Expiry className="size-3.5" aria-hidden />
          {t.connection.consentExpiry} {t.setup.opensInNewTab}.
        </p>
      </div>

      <AnimatePresence initial={false}>
        {handoff && (
          <motion.div
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: DURATION.quick / 1000, ease: EASE_OUT }}
            className="rounded-xl border border-border bg-muted/30 p-4 sm:p-5"
          >
            <div className="flex items-start gap-3">
              <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-background text-muted-foreground ring-1 ring-border">
                <Handoff className="size-4" aria-hidden />
              </span>
              <div className="min-w-0">
                <p className="text-sm font-medium text-foreground">{t.setup.handoffTitle}</p>
                <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
                  {t.setup.handoffBody}
                </p>
              </div>
            </div>
            {/* The link and a sentence explaining it, together, drawn as the
                message it will be. A bare URL pasted into a chat window asks a
                Global Administrator to approve something unexplained, which is
                the request they are right to refuse. */}
            <p className="mt-4 whitespace-pre-wrap break-words rounded-lg border border-border bg-background px-4 py-3 text-sm leading-relaxed text-foreground shadow-xs">
              {`${t.setup.handoffMessage}\n\n`}
              <span className="break-all font-mono text-xs text-muted-foreground">
                {connection.consent_url}
              </span>
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              <CopyButton text={message} label={t.setup.copyMessage} />
              <CopyButton
                text={connection.consent_url}
                label={t.connection.copyConsentLink}
                variant="ghost"
              />
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <WaitingNote text={t.connection.waitingForConsent} detail={t.setup.detectedAutomatically} />
    </>
  );
}
