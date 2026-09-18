import { createElement } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { Level } from "@/lib/types";
import { useT } from "@/i18n";
import { StatusPill } from "@/components/security/StatusPill";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { ScoreTile } from "@/components/security/ScoreTile";
import { formatDateTime } from "@/lib/format";
import { FACT_ICONS, FACTOR_ICONS, resourceTypeIcon } from "@/lib/icons";
import { IconLabel, ResourceTypeLabel } from "@/components/security/IconLabel";
import { ChevronRightIcon, type LucideIcon } from "lucide-react";
import { Breadcrumbs, DetailSkeleton, ErrorState } from "@/components/common/states";
import { CodeBlock } from "@/components/common/CodeBlock";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  ContextRow,
  type ContextFact,
} from "@/components/security/ContextProvenance";
import { AssetNeighborhood } from "@/components/graph/AssetNeighborhood";
import { BlastRadius } from "@/components/graph/BlastRadius";

interface AssetDetail {
  id: string;
  name: string;
  resource_type: string;
  provider: string;
  provider_resource_id: string;
  region: string | null;
  environment: string | null;
  criticality: Level;
  data_sensitivity: Level;
  public_exposure: Level;
  metadata: Record<string, unknown>;
  /**
   * The same three values again, each with where it came from. Kept beside the
   * flat fields rather than replacing them: those are what every list view and
   * filter reads.
   */
  context?: {
    criticality: ContextFact;
    data_sensitivity: ContextFact;
    environment: ContextFact;
  };
  first_seen_at: string;
  last_seen_at: string;
  findings: {
    id: string;
    rule_id: string;
    title: string;
    severity: string;
    status: string;
    risk_score: number | null;
  }[];
}

export function AssetDetailPage() {
  const t = useT();
  const { assetId } = useParams();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["asset", assetId],
    queryFn: () =>
      api.get<AssetDetail>(`/api/v1/assets/${assetId}`).then((r) => r.data),
  });

  if (isLoading) return <DetailSkeleton />;
  if (error)
    return (
      <ErrorState
        title="Could not load this page"
        detail="CloudGuard could not reach its own API."
        impact="Nothing about your environment has changed — this is a problem displaying it."
        onRetry={() => refetch()}
      />
    );
  if (!data) return null;

  return (
    <div className="flex flex-col gap-6">
      <Breadcrumbs
        trail={[{ label: t.assets.title, to: "/assets" }, { label: data.name }]}
      />

      <div className="flex items-start gap-4">
        {/* The asset's kind, as a mark: the same glyph its row carries in the
            inventory, so the page and the row that opened it are visibly the
            same thing. */}
        <span className="flex size-12 shrink-0 items-center justify-center rounded-xl border border-border bg-card text-muted-foreground shadow-xs">
          {createElement(resourceTypeIcon(data.resource_type), {
            className: "size-5",
            "aria-hidden": true,
          })}
        </span>
        <div className="min-w-0">
        <h1 className="truncate text-2xl font-semibold tracking-tight">{data.name}</h1>
        <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted-foreground">
          <ResourceTypeLabel type={data.resource_type} />
          {data.region && <IconLabel icon={FACT_ICONS.region}>{data.region}</IconLabel>}
          {data.environment && (
            <IconLabel icon={FACT_ICONS.environment}>{data.environment}</IconLabel>
          )}
        </p>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>Risk context</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="flex flex-col gap-3 text-sm">
              <ContextRow
                label={<IconLabel icon={FACTOR_ICONS.criticality}>Criticality</IconLabel>}
                fact={data.context?.criticality}
                fallback={<SeverityBadge level={data.criticality} size="sm" />}
              />
              <ContextRow
                label={
                  <IconLabel icon={FACTOR_ICONS.dataSensitivity}>Data sensitivity</IconLabel>
                }
                fact={data.context?.data_sensitivity}
                fallback={
                  <SeverityBadge level={data.data_sensitivity} size="sm" />
                }
              />
              {/* Exposure has no provenance and needs none: it is read off the
                  configuration in the capture -- a public IP is attached or it
                  is not -- so there is nothing to attribute or declare. */}
              <Row
                icon={FACTOR_ICONS.exposure}
                label="Internet exposure"
                value={<SeverityBadge level={data.public_exposure} size="sm" />}
              />
              <Row
                icon={FACT_ICONS.environment}
                label="Environment"
                value={data.environment ?? "—"}
              />
              <Row
                icon={FACT_ICONS.firstSeen}
                label="First seen"
                value={formatDateTime(data.first_seen_at)}
              />
              <Row
                icon={FACT_ICONS.lastSeen}
                label="Last seen"
                value={formatDateTime(data.last_seen_at)}
              />
            </dl>
          </CardContent>
          <CardFooter className="border-t pt-4">
            {/* The provider's own id, in full: it is what the customer can
                paste into their portal, and truncating it would make it
                useless for the one thing it is here for. */}
            <p className="break-all font-mono text-xs text-muted-foreground">
              {data.provider_resource_id}
            </p>
          </CardFooter>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>
              Findings on this asset
              <span className="ml-2 text-sm font-normal text-muted-foreground tabular-nums">
                {data.findings.length}
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {data.findings.length === 0 ? (
              <p className="py-4 text-center text-sm text-muted-foreground">
                No findings on this asset.
              </p>
            ) : (
              <ul className="-mx-2 flex flex-col">
                {data.findings.map((finding) => (
                  <li key={finding.id}>
                    {/* The row is the link: the target is the whole line, not
                        the length of the title. */}
                    <Link
                      to={`/findings/${finding.id}`}
                      className="group flex items-center gap-3 rounded-lg px-2 py-2.5 transition-colors hover:bg-muted/50 focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
                    >
                      {finding.risk_score === null ? (
                        <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-dashed border-border text-xs text-muted-foreground">
                          —
                        </span>
                      ) : (
                        <ScoreTile
                          score={Number(finding.risk_score)}
                          level={finding.severity}
                          className="size-9 [&>span]:text-sm"
                        />
                      )}
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm font-medium text-foreground">
                          {finding.title}
                        </span>
                        <span className="block font-mono text-[11px] text-muted-foreground">
                          {finding.rule_id}
                        </span>
                      </span>
                      <SeverityBadge level={finding.severity} size="sm" />
                      <StatusPill status={finding.status} />
                      <ChevronRightIcon
                        className="size-4 shrink-0 text-muted-foreground/60 transition-transform group-hover:translate-x-0.5"
                        aria-hidden
                      />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      <AssetNeighborhood
        providerResourceId={data.provider_resource_id}
        name={data.name}
      />

      <BlastRadius
        providerResourceId={data.provider_resource_id}
        name={data.name}
      />

      <Card>
        <CardHeader>
          <CardTitle>Configuration</CardTitle>
          <CardDescription>
            As collected in the most recent snapshot
          </CardDescription>
        </CardHeader>
        <CardContent>
          <CodeBlock
            code={JSON.stringify(data.metadata, null, 2)}
            label="Copy this configuration"
          />
        </CardContent>
      </Card>
    </div>
  );
}

function Row({
  label,
  value,
  icon,
}: {
  label: string;
  value: React.ReactNode;
  icon?: LucideIcon;
}) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-muted-foreground">
        {icon ? <IconLabel icon={icon}>{label}</IconLabel> : label}
      </dt>
      <dd className="font-medium text-foreground">{value}</dd>
    </div>
  );
}
