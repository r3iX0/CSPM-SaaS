import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { ArrowRightIcon, CheckIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { AzurePermissions } from "@/lib/types";
import { useT } from "@/i18n";
import { setupSteps } from "@/lib/connectionStage";
import { SETUP_ICONS } from "@/lib/icons";
import { setupCopy } from "@/lib/setupCopy";
import type { Provider } from "@/lib/types";
import { Button, buttonVariants } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ProviderMark } from "@/components/security/ProviderMark";
import { cn } from "@/lib/format";

/**
 * The first screen a customer sees on this page, and usually the first
 * meaningful screen in the product.
 *
 * It says what the next three minutes contain before asking for them. Setup
 * needs two grants and often two different people, so a lone "Connect Azure"
 * button hides the one fact that decides whether now is a good moment to start
 * -- and somebody who begins, discovers they are not a Global Administrator and
 * abandons it is a worse outcome than somebody who reads that first and comes
 * back with the right colleague.
 *
 * The steps are the wizard's own rail, from `setupSteps`, in the same words. A
 * preview that drifted from the flow it previews would be worse than no
 * preview.
 *
 * Shown for one cloud at a time. Somebody who has connected nothing is about to
 * connect *something*, and a preview that hedged across both would describe a
 * flow neither of them has.
 */
export function ConnectEmpty({ provider = "azure" }: { provider?: Provider }) {
  const t = useT();
  const copy = setupCopy(t, provider);
  const steps = setupSteps(provider);
  const last = steps.length - 1;
  const [showing, setShowing] = useState(false);
  const ReadOnly = SETUP_ICONS.readOnly;
  const meta = [
    { icon: SETUP_ICONS.duration, label: copy.metaDuration },
    { icon: SETUP_ICONS.readOnly, label: copy.metaReadOnly },
    { icon: SETUP_ICONS.permission, label: copy.metaNoCredentials },
  ];

  // Fetched rather than written into the page, and only when asked for. The
  // promise beneath this card is a claim about what CloudGuard requests; a
  // hardcoded list would be a second copy of that claim, free to drift from
  // the one the API and the consent screen actually use.
  const permissions = useQuery({
    queryKey: ["azure-permissions"],
    queryFn: () =>
      api
        .get<AzurePermissions>("/api/v1/cloud-accounts/azure/permissions")
        .then((r) => r.data),
    enabled: showing,
    staleTime: Infinity,
  });

  return (
    <div className="overflow-hidden rounded-xl border border-border bg-card shadow-xs">
      <div className="grid gap-10 p-6 sm:p-10 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)] lg:gap-14">
        <div>
          <span className="flex size-12 items-center justify-center rounded-xl border border-border bg-background shadow-xs">
            <ProviderMark provider={provider} className="size-6" />
          </span>
          <h2 className="mt-6 text-2xl font-semibold tracking-tight text-foreground">
            {t.connection.noConnections}
          </h2>
          <p className="mt-2 max-w-md text-sm leading-relaxed text-muted-foreground">
            {t.connection.noConnectionsHelp}
          </p>
          <ul className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
            {meta.map(({ icon: Icon, label }) => (
              <li key={label} className="flex items-center gap-1.5">
                <Icon className="size-3.5" aria-hidden />
                {label}
              </li>
            ))}
          </ul>
          <div className="mt-7 flex flex-wrap gap-2">
            <Link to="/connections/new" className={cn(buttonVariants({ size: "lg" }), "px-4")}>
              {t.connection.connectCloud}
              <ArrowRightIcon data-icon="inline-end" aria-hidden />
            </Link>
            <Button
              variant="ghost"
              size="lg"
              className="px-4 text-muted-foreground"
              onClick={() => setShowing((open) => !open)}
            >
              {showing ? t.connection.hideWhatItDoes : t.connection.readWhatItDoes}
            </Button>
          </div>

          {showing && (
            <div className="mt-5 rounded-lg border border-border bg-muted/40 px-4 py-3">
              <p className="text-xs font-medium text-muted-foreground">
                {t.connection.permissionsTitle}
              </p>

              {permissions.isLoading && (
                <div className="mt-3 space-y-2">
                  <Skeleton className="h-3 w-40" />
                  <Skeleton className="h-3 w-56" />
                </div>
              )}

              {permissions.isError && (
                <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                  {t.connection.permissionsUnavailable}
                </p>
              )}

              {permissions.data && (
                <dl className="mt-3 space-y-3 text-xs">
                  <div>
                    <dt className="font-medium text-foreground">
                      {t.connection.graphPermissions}
                    </dt>
                    <dd className="mt-1 flex flex-wrap gap-1.5">
                      {permissions.data.graph_application_permissions.map((name) => (
                        <code
                          key={name}
                          className="rounded border border-border bg-background px-1.5 py-0.5 text-[11px] text-muted-foreground"
                        >
                          {name}
                        </code>
                      ))}
                    </dd>
                  </div>
                  <div className="flex flex-wrap gap-x-8 gap-y-1">
                    <span>
                      <dt className="inline font-medium text-foreground">
                        {t.connection.rbacRole}:
                      </dt>{" "}
                      <dd className="inline text-muted-foreground">
                        {permissions.data.azure_rbac_role} ({permissions.data.access_type})
                      </dd>
                    </span>
                    <span>
                      <dt className="inline font-medium text-foreground">
                        {t.connection.writesPerformed}:
                      </dt>{" "}
                      <dd className="inline text-muted-foreground">
                        {permissions.data.writes_performed}
                      </dd>
                    </span>
                  </div>
                </dl>
              )}
            </div>
          )}
        </div>

        <div className="rounded-xl border border-border bg-muted/30 p-6">
          <p className="text-sm font-medium text-foreground">
            {copy.railTitle}
          </p>
          <ol className="mt-5">
            {steps.map((step, index) => {
              // The last row is not a step: it is what the customer gets for
              // the three above it, and it is ticked because CloudGuard does it
              // rather than asks for it.
              const payoff = index === last;
              return (
                <li key={step.stage} className="relative flex gap-3 pb-6 last:pb-0">
                  {!payoff && (
                    <span
                      className="absolute top-7 bottom-1 left-3 w-px -translate-x-1/2 bg-border"
                      aria-hidden
                    />
                  )}
                  <span
                    className={cn(
                      "relative flex size-6 shrink-0 items-center justify-center rounded-full text-[11px] font-semibold tabular-nums",
                      payoff
                        ? "bg-ok text-background"
                        : "border border-border bg-card text-muted-foreground",
                    )}
                  >
                    {payoff ? <CheckIcon className="size-3.5" strokeWidth={3} /> : index + 1}
                  </span>
                  <span className="min-w-0">
                    <span
                      className={cn(
                        "block text-sm font-medium",
                        payoff ? "text-ok" : "text-foreground",
                      )}
                    >
                      {copy[step.key]}
                    </span>
                    <span className="mt-0.5 block text-xs leading-relaxed text-muted-foreground">
                      {copy[`${step.key}Detail`]}
                    </span>
                  </span>
                </li>
              );
            })}
          </ol>
        </div>
      </div>

      {/* The claim the product is built on, on the screen where somebody is
          deciding whether to grant anything at all. */}
      <p className="flex items-start gap-2 border-t border-border bg-muted/30 px-6 py-4 sm:px-10 text-xs leading-relaxed text-muted-foreground">
        <ReadOnly className="mt-0.5 size-3.5 shrink-0" aria-hidden />
        {t.connection.readOnlyPromise}
      </p>
    </div>
  );
}
