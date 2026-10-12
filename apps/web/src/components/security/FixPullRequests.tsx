import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { GitPullRequestIcon } from "lucide-react";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import type { FixPullRequest, GitHubStatus } from "@/lib/types";
import { useT } from "@/i18n";
import { useIsDemo } from "@/lib/useDemo";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";

const IN_FLIGHT: readonly FixPullRequest["state"][] = ["QUEUED", "OPENING"];

/**
 * A rule's fix as pull requests on the customer's own Terraform (DECISIONS.md §232).
 *
 * Offered where the deployment offers GitHub and the organization has linked an
 * installation. One request per repository the state indexes place the rule's
 * failing assets in; the worker opens each within a minute, so the list is
 * read again every few seconds while one is in flight. Each says how many of
 * its assets were edited, and links to the pull request once there is one.
 */
export function FixPullRequests({ ruleId }: { ruleId: string }) {
  const t = useT();
  const isDemo = useIsDemo();
  const queryClient = useQueryClient();
  const github = useQuery({
    queryKey: ["integrations", "github"],
    queryFn: () => api.get<GitHubStatus>("/api/v1/integrations/github").then((r) => r.data),
    retry: false,
  });
  const linked = github.data?.available === true && github.data.installations.length > 0;
  const key = ["pull-requests", ruleId];
  const pulls = useQuery({
    queryKey: key,
    queryFn: () =>
      api
        .get<FixPullRequest[]>(
          `/api/v1/remediation/pull-requests?rule_id=${encodeURIComponent(ruleId)}`,
        )
        .then((r) => r.data),
    enabled: linked,
    retry: false,
    refetchInterval: (query) =>
      query.state.data?.some((pull) => IN_FLIGHT.includes(pull.state)) ? 5_000 : false,
  });
  const ask = useMutation({
    mutationFn: () =>
      api
        .post<{ pull_requests: FixPullRequest[]; not_indexed: number }>(
          "/api/v1/remediation/pull-requests",
          { rule_id: ruleId },
        )
        .then((r) => r.data),
    onSuccess: ({ pull_requests, not_indexed }) => {
      toast.success(t.pullRequests.queued(pull_requests.length), {
        description: not_indexed > 0 ? t.pullRequests.notIndexed(not_indexed) : undefined,
      });
      void queryClient.invalidateQueries({ queryKey: key });
    },
    onError: (err) =>
      toast.error(t.pullRequests.failed, {
        description: err instanceof ApiError ? err.message : undefined,
      }),
  });

  if (!linked) return null;
  const rows = pulls.data ?? [];

  return (
    <section aria-labelledby="fix-pull-requests" className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 id="fix-pull-requests" className="text-body font-semibold">
          {t.pullRequests.title}
        </h3>
        {!isDemo && (
          <Button variant="outline" size="sm" disabled={ask.isPending} onClick={() => ask.mutate()}>
            {ask.isPending ? (
              <Spinner data-icon="inline-start" />
            ) : (
              <GitPullRequestIcon data-icon="inline-start" aria-hidden />
            )}
            {ask.isPending ? t.pullRequests.opening : t.pullRequests.open}
          </Button>
        )}
      </div>
      {rows.length > 0 && (
        <ul className="flex flex-col divide-y rounded-lg border">
          {rows.map((pull) => {
            const edited = pull.findings.filter((f) => f.outcome === "EDITED").length;
            return (
              <li key={pull.id} className="flex flex-col gap-0.5 px-3 py-2">
                <div className="flex flex-wrap items-center gap-x-2 text-body">
                  <span className="font-medium">{pull.repository}</span>
                  {pull.pr_url && pull.pr_number !== null && (
                    <a
                      href={pull.pr_url}
                      target="_blank"
                      rel="noreferrer"
                      className="rounded-sm underline underline-offset-2 outline-none focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring"
                    >
                      {t.pullRequests.number(pull.pr_number)}
                    </a>
                  )}
                  <span className="text-caption text-muted-foreground">
                    {t.pullRequests.state[pull.state]}
                  </span>
                </div>
                <p className="text-caption text-muted-foreground">
                  {IN_FLIGHT.includes(pull.state)
                    ? null
                    : (pull.detail ?? t.pullRequests.edited(edited, pull.findings.length))}
                </p>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
