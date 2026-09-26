import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { PlusIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { CloudConnection, ProviderOption } from "@/lib/types";
import { ProviderMark } from "@/components/security/ProviderMark";
import { useT } from "@/i18n";
import { ConnectEmpty } from "@/components/connections/ConnectEmpty";
import { ConnectionRow } from "@/components/connections/ConnectionRow";
import { CardsSkeleton, PageHeader } from "@/components/common/states";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/format";
import { useIsDemo } from "@/lib/useDemo";

/**
 * The connections page: one row per connection, opened for the detail.
 *
 * It answers a question about the estate rather than about any one connection
 * -- is every environment being read, and how recently -- so the shape is a
 * table of rows that can be compared at a glance, not a column of cards each
 * describing itself at length. A row's own detail, its subscriptions, cadence
 * and access, is one click away in `ConnectionRow`.
 *
 * Setup lives in the wizard at `/connections/new` and `/connections/:id/setup`.
 * This page holds no setup steps of its own, so there is one flow rather than
 * two that drifted.
 */
export function ConnectPage() {
  const t = useT();
  const [searchParams, setSearchParams] = useSearchParams();

  // Only reached when the consent callback could not tell which connection the
  // failure belonged to -- a tampered or expired state. With an id it redirects
  // into the wizard instead, where the retry sits next to the explanation.
  const consentError = searchParams.get("consent_error");
  const expandedId = searchParams.get("id");

  const connections = useQuery({
    queryKey: ["cloud-connections"],
    queryFn: () => api.get<CloudConnection[]>("/api/v1/cloud-connections").then((r) => r.data),
  });

  function dismissError() {
    searchParams.delete("consent_error");
    setSearchParams(searchParams);
  }

  const rows = connections.data ?? [];
  const isDemo = useIsDemo();

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t.connection.title}
        description={t.connection.intro}
        actions={
          rows.length > 0 && !isDemo ? (
            <Link to="/connections/new" className={cn(buttonVariants({ size: "sm" }))}>
              <PlusIcon data-icon="inline-start" aria-hidden />
              {t.connection.connectCloud}
            </Link>
          ) : undefined
        }
      />

      {consentError && (
        <Alert variant="destructive">
          <AlertTitle>Consent failed</AlertTitle>
          <AlertDescription>
            <p>{consentError}</p>
            <Button variant="outline" size="sm" className="mt-2" onClick={dismissError}>
              Dismiss
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {connections.isLoading && <CardsSkeleton count={2} />}

      {connections.isSuccess && rows.length === 0 && <ConnectEmpty />}

      {rows.length > 0 && (
        <div className="overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10">
          {/* Column labels, not a `<table>`: every row opens into a two-column
              panel, which a table cell cannot hold without either colspan
              gymnastics or a second nested grid. The labels are hidden on
              narrow screens, where each row stacks and carries its own. */}
          <div
            aria-hidden
            className="hidden px-5 py-2.5 text-[11.5px] text-muted-foreground md:grid md:grid-cols-[minmax(0,2.2fr)_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1.1fr)_auto] md:gap-4"
          >
            <span>{t.connection.columnConnection}</span>
            <span>{t.connection.columnStatus}</span>
            <span>{t.connection.columnSubscriptions}</span>
            <span>{t.connection.columnLastRead}</span>
            <span className="text-right">{t.connection.columnActions}</span>
          </div>

          {rows.map((connection) => (
            <ConnectionRow
              key={connection.id}
              connection={connection}
              defaultExpanded={connection.id === expandedId}
            />
          ))}
        </div>
      )}

      {connections.isSuccess && <ComingSoon />}
    </div>
  );
}

/** Platforms on the roadmap, named so a reader knows they were not overlooked. */
const PLANNED = ["gcp", "kubernetes", "docker", "github", "gitlab"] as const;
const PLANNED_NAMES: Record<string, string> = {
  aws: "AWS",
  gcp: "GCP",
  kubernetes: "Kubernetes",
  docker: "Docker",
  github: "GitHub",
  gitlab: "GitLab",
};

/**
 * What Cleave cannot read yet, at the foot of what it does.
 *
 * AWS is listed only while the API says it is not offered: its connector
 * exists and is gated until it has been run against a live account
 * (`AWS_ENABLED`, docs/AWS_INTEGRATION.md). The same answer the setup's first
 * step reads, so the two never disagree about whether AWS can be connected.
 */
function ComingSoon() {
  const t = useT();
  const providers = useQuery({
    queryKey: ["cloud-providers"],
    queryFn: () =>
      api.get<ProviderOption[]>("/api/v1/cloud-connections/providers").then((r) => r.data),
    retry: false,
  });
  if (!providers.isSuccess) return null;
  const awsOffered = (providers.data ?? []).some(
    (option) => option.id === "aws" && option.available,
  );
  const planned = [...(awsOffered ? [] : ["aws"]), ...PLANNED];

  return (
    <section aria-labelledby="coming-soon">
      <h2 id="coming-soon" className="mb-2.5 text-[12.5px] font-medium text-muted-foreground">
        {t.connection.comingSoon}
      </h2>
      <ul className="grid grid-cols-[repeat(auto-fill,minmax(130px,1fr))] gap-2.5">
        {planned.map((id) => (
          <li
            key={id}
            className="flex items-center gap-2.5 rounded-[10px] border border-border bg-card px-3.5 py-2.5 opacity-60"
          >
            <ProviderMark provider={id} tile className="text-muted-foreground" />
            <span className="text-[12.5px] font-medium text-muted-foreground">
              {PLANNED_NAMES[id]}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}
