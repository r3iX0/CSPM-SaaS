import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { ScanDetail } from "@/lib/types";
import { useT } from "@/i18n";
import { words } from "@/lib/vocabulary";
import { ProviderMark } from "@/components/security/ProviderMark";
import { ScanPipeline } from "@/components/scans/ScanPipeline";
import { CollectionPanel } from "@/components/scans/CollectionPanel";
import { Skeleton } from "@/components/ui/skeleton";

/**
 * What one scan covered, who it read as, and how each of its steps went.
 *
 * The Details tab of a finished scan in the scan wizard. The severity breakdown
 * is the Result tab's, so it is not repeated here; the steps are the same
 * `ScanPipeline` the scan was watched through while it ran, so a lane that
 * failed reads the same afterwards as it did live.
 */
export function ScanDetailPanel({ scanId }: { scanId: string }) {
  const t = useT();
  const detail = useQuery({
    queryKey: ["scan-detail", scanId],
    queryFn: () => api.get<ScanDetail>(`/api/v1/scans/${scanId}/detail`).then((r) => r.data),
  });

  if (detail.isLoading) return <Skeleton className="h-24 w-full" />;
  if (!detail.data) return null;

  const { scope } = detail.data;
  const vocabulary = words(scope.provider);
  const scanned = detail.data.progress_total ?? 0;

  return (
    <div className="grid gap-5 sm:grid-cols-2">
      <div>
        <SectionLabel>{t.scans.scope}</SectionLabel>
        <dl className="mt-1.5 flex flex-col gap-1 text-xs">
          <Row
            label={t.connection.connectionName}
            value={
              scope.connection_name ? (
                <span className="inline-flex items-center gap-1.5">
                  <ProviderMark provider={scope.provider} className="size-3.5" />
                  {scope.connection_name}
                </span>
              ) : null
            }
          />
          <Row
            label={vocabulary.Account}
            value={scope.subscription_name ?? scope.subscription_id}
          />
          <Row
            label={vocabulary.boundary === "tenant" ? "Tenant" : "Organization"}
            value={scope.tenant_id}
          />
          <Row label={t.scans.evaluated} value={scanned ? String(scanned) : null} />
        </dl>
      </div>

      <div>
        <SectionLabel>{t.scans.identity}</SectionLabel>
        <dl className="mt-1.5 flex flex-col gap-1 text-xs">
          {/* The object id the customer can look up in their own directory
              and revoke — not an internal reference. */}
          <Row label="Service principal" value={scope.service_principal_object_id} />
          <Row label="Role" value={scope.role_version ? `Scanner ${scope.role_version}` : null} />
          {/* Read from `trigger`, not inferred from a missing user. Before
              scans could start themselves, a NULL user meant "scheduled" by
              elimination; now it can equally mean a manual scan whose user
              record has gone, and labelling that one "Scheduled" is a plain
              untruth about who asked. */}
          <Row
            label={t.scans.initiator}
            value={
              detail.data.trigger === "SCHEDULED"
                ? t.scans.scheduled
                : (detail.data.triggered_by_user_id ?? t.scans.manualUnknownUser)
            }
          />
        </dl>
      </div>

      {(detail.data.stages?.length ?? 0) > 0 && (
        <div className="sm:col-span-2">
          <SectionLabel>Stages</SectionLabel>
          <div className="mt-2">
            <ScanPipeline scan={detail.data} />
          </div>
        </div>
      )}

      <div className="sm:col-span-2">
        <CollectionPanel scanId={scanId} />
      </div>
    </div>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p className="text-caption font-medium text-muted-foreground">
      {children}
    </p>
  );
}

function Row({ label: text, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-2">
      <dt className="shrink-0 text-muted-foreground">{text}</dt>
      <dd className="min-w-0 truncate font-mono text-caption text-foreground">
        {value ?? "—"}
      </dd>
    </div>
  );
}
