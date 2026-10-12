import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import type { GitHubInstallation, GitHubStatus } from "@/lib/types";
import { useT } from "@/i18n";
import { formatDay } from "@/lib/format";
import { SettingsSection } from "@/components/settings/SettingsSection";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";

const GITHUB = ["integrations", "github"];

/**
 * Cleave's GitHub App, linked to this organization (DECISIONS.md §231).
 *
 * Drawn only where the deployment offers GitHub. Installing happens on GitHub;
 * GitHub sends the person back to `GitHubCallback`, which links what they
 * installed. Unlinking leaves the App installed on GitHub, and says so.
 */
export function GitHubSection() {
  const t = useT();
  const queryClient = useQueryClient();
  const status = useQuery({
    queryKey: GITHUB,
    queryFn: () => api.get<GitHubStatus>("/api/v1/integrations/github").then((r) => r.data),
    retry: false,
  });
  const connect = useMutation({
    mutationFn: () =>
      api.post<{ install_url: string }>("/api/v1/integrations/github/connect").then((r) => r.data),
    onSuccess: ({ install_url }) => window.location.assign(install_url),
    onError: (err) =>
      toast.error(t.github.linkFailed, {
        description: err instanceof ApiError ? err.message : undefined,
      }),
  });
  const unlink = useMutation({
    mutationFn: (installation: GitHubInstallation) =>
      api.del(`/api/v1/integrations/github/installations/${installation.installation_id}`),
    onSuccess: () => {
      toast.success(t.github.unlinked, { description: t.github.unlinkNote });
      void queryClient.invalidateQueries({ queryKey: GITHUB });
    },
  });

  if (!status.data?.available) return null;
  const installations = status.data.installations;

  return (
    <SettingsSection id="github" title={t.github.title} description={t.github.help}>
      <div className="flex flex-col gap-4 rounded-xl bg-card p-5 ring-1 ring-foreground/10">
        {installations.length === 0 ? (
          <p className="text-body text-muted-foreground">{t.github.none}</p>
        ) : (
          <ul className="flex flex-col divide-y">
            {installations.map((installation) => (
              <li
                key={installation.installation_id}
                className="flex flex-wrap items-center justify-between gap-3 py-2"
              >
                <span className="text-body">
                  {t.github.linked(installation.account_login)}{" "}
                  <span className="text-muted-foreground">
                    {t.github.linkedOn(formatDay(installation.connected_at))}
                  </span>
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={unlink.isPending}
                  aria-label={t.github.unlinkFor(installation.account_login)}
                  onClick={() => unlink.mutate(installation)}
                >
                  {t.github.unlink}
                </Button>
              </li>
            ))}
          </ul>
        )}
        <div className="flex flex-wrap items-center gap-3">
          <Button disabled={connect.isPending} onClick={() => connect.mutate()}>
            {connect.isPending && <Spinner data-icon="inline-start" />}
            {t.github.connect}
          </Button>
          {installations.length > 0 && (
            <p className="text-caption text-muted-foreground">{t.github.indexHelp}</p>
          )}
        </div>
      </div>
    </SettingsSection>
  );
}

/**
 * Where GitHub sends a person after they install the App.
 *
 * GitHub adds `installation_id`, a one-time `code` and the `state` that went
 * out. All three go to the API under this person's session, which links the
 * installation only if GitHub lists it among theirs (§231). Posted once, even
 * under React's double effects in development, because the code is single-use.
 */
export function GitHubCallback() {
  const t = useT();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [params] = useSearchParams();
  const sent = useRef(false);
  const [error, setError] = useState<string | null>(null);

  const installationId = Number(params.get("installation_id"));
  const code = params.get("code");
  const state = params.get("state");
  const complete = Number.isInteger(installationId) && installationId > 0 && !!code && !!state;

  const link = useMutation({
    mutationFn: () =>
      api.post("/api/v1/integrations/github/installations", {
        installation_id: installationId,
        code,
        state,
      }),
    onSuccess: () => {
      toast.success(t.github.linkedToast);
      void queryClient.invalidateQueries({ queryKey: GITHUB });
      void navigate("/settings/integrations", { replace: true });
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : t.github.linkFailed),
  });

  useEffect(() => {
    if (!complete || sent.current) return;
    sent.current = true;
    link.mutate();
  }, [complete, link]);

  if (!complete || error) {
    return (
      <div className="flex flex-col items-start gap-3">
        <Alert variant="destructive">
          <AlertDescription>{error ?? t.github.linkMissing}</AlertDescription>
        </Alert>
        <Link to="/settings/integrations" className={buttonVariants({ variant: "outline" })}>
          {t.github.back}
        </Link>
      </div>
    );
  }
  return (
    <p className="flex items-center gap-2 text-body text-muted-foreground" role="status">
      <Spinner /> {t.github.linking}
    </p>
  );
}
