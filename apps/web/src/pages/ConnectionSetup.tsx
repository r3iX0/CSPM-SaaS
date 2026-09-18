import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { AnimatePresence, motion } from "motion/react";
import { ArrowLeftIcon, PauseIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { CloudConnection, Provider } from "@/lib/types";
import { useT } from "@/i18n";
import { connectionStage, setupPath } from "@/lib/connectionStage";
import { SETUP_ICONS } from "@/lib/icons";
import { DURATION, EASE_IN, EASE_OUT } from "@/lib/motion";
import { setupCopy } from "@/lib/setupCopy";
import { SetupRail } from "@/components/connections/setup/SetupRail";
import { StepConsent } from "@/components/connections/setup/StepConsent";
import { StepDeploy } from "@/components/connections/setup/StepDeploy";
import { StepHeader } from "@/components/connections/setup/StepHeader";
import { StepScope } from "@/components/connections/setup/StepScope";
import { StepSubscriptions } from "@/components/connections/setup/StepSubscriptions";
import { CardsSkeleton } from "@/components/common/states";
import { ProviderMark } from "@/components/security/ProviderMark";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

/**
 * The connection wizard.
 *
 * Two routes, one component: `/connections/new` before anything exists, and
 * `/connections/:connectionId/setup` from the moment it does. The step shown is
 * derived from the connection rather than held in state, because setup leaves
 * this application twice -- to Microsoft for consent, to Azure Portal for the
 * role -- and returns through a full page load each time. The consent callback
 * redirects straight back to this URL, so coming back means arriving at the
 * next step rather than at a list with a card to find.
 *
 * The connection is re-read every five seconds until it can scan. That poll is
 * not only a status check: the backend re-probes both grants and runs discovery
 * inside the same request, so it is what actually advances the wizard while the
 * customer waits on somebody else.
 *
 * Laid out as a rail beside one panel, the shape of every serious onboarding
 * flow: where you are on the left, the one thing to do now on the right. The
 * panel swaps with a short slide when the stage changes -- which, because the
 * stage is the server's, happens when a grant lands rather than when a button
 * is pressed, and the motion is what tells the reader something arrived.
 */
export function ConnectionSetupPage() {
  const t = useT();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { connectionId } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  // Tracked separately from the query's own `isFetching`, which is true every
  // five seconds because of the poll -- a button reading "Checking…" on a timer
  // says the reader pressed something they did not.
  const [rechecking, setRechecking] = useState(false);

  const consentError = searchParams.get("consent_error");

  const detail = useQuery({
    queryKey: ["cloud-connection", connectionId],
    queryFn: () =>
      api
        .get<CloudConnection>(`/api/v1/cloud-connections/${connectionId}`)
        .then((r) => r.data),
    enabled: Boolean(connectionId),
    refetchInterval: (query) => (query.state.data?.is_ready_to_scan ? false : 5000),
    refetchIntervalInBackground: true,
  });

  const connection = detail.data ?? null;
  const stage = connectionStage(connection);
  // Which cloud the wizard is describing. Before a connection exists, the
  // picker in the first step decides; after it does, the connection itself is
  // the answer -- the provider is not editable, because the grant and the
  // artefact are both bound to it.
  const [chosen, setChosen] = useState<Provider>("azure");
  const provider = connection?.provider ?? chosen;
  const copy = setupCopy(t, provider);

  const setCancelled = useMutation({
    mutationFn: (value: boolean) =>
      api.post(
        `/api/v1/cloud-connections/${connectionId}/${value ? "cancel" : "resume"}`,
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cloud-connection", connectionId] });
      queryClient.invalidateQueries({ queryKey: ["cloud-connections"] });
    },
    onError: (err) =>
      setError(err instanceof Error ? err.message : "Could not update the connection"),
  });

  // Discarding and starting again is how the scope gets changed: the scope is
  // what consent and the role assignment were both bound to, so there is no
  // edit that would leave either of them meaning what they meant.
  const discard = useMutation({
    mutationFn: () => api.del(`/api/v1/cloud-connections/${connectionId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cloud-connections"] });
      navigate("/connections/new", { replace: true });
    },
    onError: (err) =>
      setError(err instanceof Error ? err.message : "Could not discard the connection"),
  });

  function dismissConsentError() {
    searchParams.delete("consent_error");
    setSearchParams(searchParams, { replace: true });
  }

  // Leaving is a first-class way out of every waiting step. Both grants are
  // somebody else's to give, and a wizard that can only be finished or
  // abandoned makes a customer sit on a spinner for a colleague who is in a
  // meeting. In the header rather than under the panel, so it is on screen
  // whichever step is showing and never competes with the step's own action.
  const waiting = connection !== null && ["consent", "deploy", "discover"].includes(stage);

  const meta = [
    { icon: SETUP_ICONS.duration, label: copy.metaDuration },
    { icon: SETUP_ICONS.readOnly, label: copy.metaReadOnly },
    { icon: SETUP_ICONS.permission, label: copy.metaNoCredentials },
  ];

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-8">
      <header className="flex flex-col gap-4">
        <Link
          to="/connections"
          className="inline-flex w-fit items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          <ArrowLeftIcon className="size-3.5" />
          {t.setup.backToConnections}
        </Link>

        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex min-w-0 items-center gap-4">
            <span className="flex size-12 shrink-0 items-center justify-center rounded-xl border border-border bg-card shadow-xs">
              <ProviderMark provider={provider} className="size-6" />
            </span>
            <div className="min-w-0">
              <h1 className="truncate text-2xl font-semibold tracking-tight text-foreground">
                {connection ? connection.name : copy.title}
              </h1>
              {/* What setup costs, which stops being worth saying once it is
                  paid: a connected environment is not "about 3 minutes". */}
              {!connection?.is_ready_to_scan && (
                <ul className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                  {meta.map(({ icon: Icon, label }) => (
                    <li key={label} className="flex items-center gap-1.5">
                      <Icon className="size-3.5" aria-hidden />
                      {label}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>

          {waiting && (
            <div className="flex shrink-0 items-center gap-2">
              <Button
                variant="ghost"
                onClick={() => setCancelled.mutate(true)}
                disabled={setCancelled.isPending}
                className="text-muted-foreground"
              >
                {t.connection.cancelSetupAction}
              </Button>
              <Button variant="outline" onClick={() => navigate("/connections")}>
                {t.setup.finishLater}
              </Button>
            </div>
          )}
        </div>
      </header>

      <div className="grid gap-8 lg:grid-cols-[15rem_minmax(0,1fr)] lg:items-start lg:gap-10">
        <aside className="rounded-xl border border-border bg-card p-5 lg:sticky lg:top-24 lg:border-0 lg:bg-transparent lg:p-0 lg:pt-2">
          <SetupRail stage={stage} provider={provider} />
        </aside>

        <div className="min-w-0 rounded-xl border border-border bg-card shadow-xs">
          {connectionId && detail.isLoading && (
            <div className="p-6 sm:p-8">
              <CardsSkeleton count={1} />
            </div>
          )}

          {connectionId && detail.isError && (
            <div className="p-6 sm:p-8">
              <Alert variant="destructive">
                <AlertTitle>This connection could not be loaded</AlertTitle>
                <AlertDescription>
                  <p>It may have been removed. The connections list is the way back.</p>
                  <Button
                    variant="outline"
                    size="sm"
                    className="mt-2"
                    onClick={() => navigate("/connections")}
                  >
                    {t.setup.backToConnections}
                  </Button>
                </AlertDescription>
              </Alert>
            </div>
          )}

          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              // One key for the three states of the last step, so ticking a
              // subscription out of scope does not replay the arrival.
              key={
                !connectionId
                  ? "scope"
                  : ["discover", "review", "done"].includes(stage)
                    ? "accounts"
                    : stage
              }
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
              {!connectionId && (
                <StepScope
                  provider={provider}
                  onProviderChange={setChosen}
                  onCreated={(id) => navigate(setupPath(id), { replace: true })}
                />
              )}

              {connection && stage !== "scope" && (
                <div className="flex flex-col gap-6 p-6 sm:p-8">
                  {stage === "paused" && (
                    <>
                      <StepHeader
                        mark={<PauseIcon className="size-5 text-muted-foreground" />}
                        title={t.setup.paused}
                        description={connection.status_detail ?? t.setup.pausedBody}
                      />
                      <div>
                        <Button
                          size="lg"
                          className="px-4"
                          onClick={() => setCancelled.mutate(false)}
                          disabled={setCancelled.isPending}
                        >
                          {t.connection.resumeSetup}
                        </Button>
                      </div>
                    </>
                  )}

                  {stage === "consent" && (
                    <StepConsent
                      connection={connection}
                      consentError={consentError}
                      onDismissError={dismissConsentError}
                    />
                  )}

                  {stage === "deploy" && (
                    <StepDeploy
                      connection={connection}
                      onRecheck={() => {
                        setRechecking(true);
                        void detail.refetch().finally(() => setRechecking(false));
                      }}
                      rechecking={rechecking}
                      onDiscard={() => discard.mutate()}
                      discarding={discard.isPending}
                    />
                  )}

                  {["discover", "review", "done"].includes(stage) && (
                    <StepSubscriptions connection={connection} onError={setError} />
                  )}

                  {error && (
                    <Alert variant="destructive">
                      <AlertDescription>{error}</AlertDescription>
                    </Alert>
                  )}
                </div>
              )}
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
