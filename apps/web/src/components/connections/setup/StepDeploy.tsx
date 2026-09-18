import { useState } from "react";

import type { CloudConnection } from "@/lib/types";
import { useT } from "@/i18n";
import { SETUP_ICONS } from "@/lib/icons";
import { setupCopy } from "@/lib/setupCopy";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import { CopyButton } from "@/components/common/CopyButton";
import { ProviderMark } from "@/components/security/ProviderMark";
import { cn } from "@/lib/format";
import { StepHeader } from "@/components/connections/setup/StepHeader";
import { WaitingNote } from "@/components/connections/setup/WaitingNote";

/**
 * The grant that lets CloudGuard read anything.
 *
 * On Azure it is step three and follows consent, which proved only that
 * CloudGuard may ask the directory who exists. On AWS it is step two and it is
 * the whole grant -- there is nothing to consent to, so this panel is where a
 * connection either works or does not.
 *
 * It is the step that fails, in both clouds. The artefact is pre-filled and
 * cannot be typed wrong, so when nothing arrives the cause is always one of
 * scope, permission or propagation. Those three are named here rather than left
 * to a support conversation, in the order they are worth checking.
 *
 * The three things that happen after the button are shown before it, because
 * the button leaves the application: somebody about to be dropped into Azure
 * Portal or the AWS console should know what they are looking for there, and
 * that they do not have to come back and tell CloudGuard it is done.
 */
export function StepDeploy({
  connection,
  onRecheck,
  rechecking,
  onDiscard,
  discarding,
}: {
  connection: CloudConnection;
  onRecheck: () => void;
  rechecking: boolean;
  onDiscard: () => void;
  discarding: boolean;
}) {
  const t = useT();
  const copy = setupCopy(t, connection.provider);
  const [confirmingDiscard, setConfirmingDiscard] = useState(false);
  const externalId = connection.provider_ref?.external_id;
  const LeavesApp = SETUP_ICONS.leavesApp;
  const Stalled = SETUP_ICONS.stalled;

  // Consented, but CloudGuard cannot produce a template. Nothing the customer
  // does in Azure advances this, so it is shown as a problem and not as a wait.
  if (!connection.template_url) {
    return (
      <Alert className="border-high-border bg-high-bg text-high">
        <AlertTitle>{t.connection.cannotDeployYet}</AlertTitle>
        <AlertDescription className="text-foreground">
          {connection.status_detail}
        </AlertDescription>
      </Alert>
    );
  }

  // The wrong-scope cause is worded for the scope this connection actually
  // covers. "The deployment landed somewhere else" is only useful if the reader
  // is told where it was supposed to land.
  const wrongScope =
    connection.scope_type === "TENANT_ROOT"
      ? t.setup.stalledScopeTenant
      : connection.scope_type === "MANAGEMENT_GROUP"
        ? t.setup.stalledScopeGroup
        : connection.scope_type === "ORGANIZATION"
          ? t.setup.aws.stackScopeOrganization
          : connection.scope_type === "ACCOUNT"
            ? t.setup.aws.stackScopeAccount
            : t.setup.stalledScopeSubscription;

  const how = [
    { title: copy.deployHow1, detail: copy.deployHow1Detail },
    { title: copy.deployHow2, detail: copy.deployHow2Detail },
    { title: copy.deployHow3, detail: copy.deployHow3Detail },
  ];

  return (
    <>
      <StepHeader
        mark={<ProviderMark provider={connection.provider} className="size-5" />}
        title={copy.deployTitle}
        description={copy.deployBody}
      />

      {/* The external id, in front of the customer *before* they deploy.
          They are about to create a trust policy that requires it, and the one
          thing that makes this integration safe is that the policy demands a
          value only they and CloudGuard know. Somebody who cannot see it cannot
          check that the stack they ran actually asks for it. */}
      {externalId && (
        <div className="rounded-xl border border-border bg-muted/30 p-4">
          <p className="text-sm font-medium text-foreground">{t.setup.aws.externalIdTitle}</p>
          <div className="mt-2.5 flex items-center gap-2">
            <code className="min-w-0 flex-1 truncate rounded-lg border border-border bg-background px-3 py-2 font-mono text-[13px] text-foreground">
              {externalId}
            </code>
            <CopyButton text={externalId} label={t.setup.aws.externalIdTitle} />
          </div>
          <p className="mt-2.5 text-xs leading-relaxed text-muted-foreground">
            {t.setup.aws.externalIdBody}
          </p>
        </div>
      )}

      <div>
        <p className="mb-3 text-sm font-medium text-foreground">{copy.deployHowTitle}</p>
        <ol className="grid gap-3 sm:grid-cols-3">
          {how.map((item, index) => (
            <li key={item.title} className="rounded-xl border border-border p-4">
              <span className="flex size-6 items-center justify-center rounded-full bg-muted text-[11px] font-semibold tabular-nums text-muted-foreground">
                {index + 1}
              </span>
              <p className="mt-3 text-sm font-medium text-foreground">{item.title}</p>
              <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
                {item.detail}
              </p>
            </li>
          ))}
        </ol>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        {/* See the note in StepConsent: this one leaves for the provider's
            console, which is why it is an anchor rather than a button. */}
        <a
          href={connection.template_url}
          target="_blank"
          rel="noopener noreferrer"
          className={cn(buttonVariants({ size: "lg" }), "px-4")}
        >
          {connection.provider === "aws" ? t.setup.aws.launchStack : t.setup.deployToAzure}
          <LeavesApp data-icon="inline-end" aria-hidden />
        </a>
        <span className="text-xs text-muted-foreground">{t.setup.opensInNewTab}</span>
      </div>

      {connection.deploy_stalled ? (
        <div className="overflow-hidden rounded-xl border border-high-border">
          <div className="flex items-start gap-3 bg-high-bg px-4 py-3.5">
            <Stalled className="mt-0.5 size-4 shrink-0 text-high" aria-hidden />
            <div className="min-w-0">
              <p className="text-sm font-medium text-high">{t.setup.stalledTitle}</p>
              <p className="mt-0.5 text-xs leading-relaxed text-foreground">
                {connection.status_detail ?? t.setup.stalledBody}
              </p>
            </div>
          </div>
          <ol className="divide-y divide-border border-t border-high-border bg-card">
            {[t.setup.stalledPropagation, wrongScope, t.setup.stalledOwner].map(
              (cause, index) => (
                <li key={index} className="flex gap-3 px-4 py-3">
                  <span className="flex size-5 shrink-0 items-center justify-center rounded-full border border-border text-[10px] font-semibold tabular-nums text-muted-foreground">
                    {index + 1}
                  </span>
                  <span className="text-xs leading-relaxed text-foreground">{cause}</span>
                </li>
              ),
            )}
          </ol>
          <div className="flex flex-wrap gap-2 border-t border-border bg-card px-4 py-3">
            <Button variant="secondary" onClick={onRecheck} disabled={rechecking}>
              {rechecking ? t.setup.checking : t.setup.checkAgain}
            </Button>
            {!confirmingDiscard && (
              <Button variant="ghost" onClick={() => setConfirmingDiscard(true)}>
                {t.setup.changeScope}
              </Button>
            )}
          </div>

          {/* Changing scope is a new connection, not an edit: the scope is what
              the consent state and the role assignment were both bound to.
              Nothing has been scanned yet, which is what makes discarding the
              cheap answer -- and what the confirmation says. */}
          {confirmingDiscard && (
            <div className="border-t border-border bg-muted/30 px-4 py-3">
              <p className="text-xs font-medium text-foreground">{t.connection.discardTitle}</p>
              <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
                {t.connection.discardDetail}
              </p>
              <div className="mt-2 flex flex-wrap gap-2">
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={onDiscard}
                  disabled={discarding}
                >
                  {discarding ? t.connection.discarding : t.connection.discard}
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => setConfirmingDiscard(false)}
                >
                  {t.connection.keep}
                </Button>
              </div>
            </div>
          )}
        </div>
      ) : (
        <WaitingNote text={t.connection.waitingForAccess} detail={t.setup.detectedAutomatically} />
      )}
    </>
  );
}
