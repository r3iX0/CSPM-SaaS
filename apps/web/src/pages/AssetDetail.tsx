import { createElement, useState } from "react";
import { Link, useLocation, useParams, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ChevronRightIcon, ExternalLinkIcon, type LucideIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { Level } from "@/lib/types";
import { useT } from "@/i18n";
import { StatusPill } from "@/components/security/StatusPill";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { ScoreTile } from "@/components/security/ScoreTile";
import { cn, formatDate, formatDateTime, formatRelative } from "@/lib/format";
import { FACT_ICONS, FACTOR_ICONS, resourceTypeIcon } from "@/lib/icons";
import { portalUrl } from "@/lib/portal";
import { IconLabel, ResourceTypeLabel } from "@/components/security/IconLabel";
import { Breadcrumbs, DetailSkeleton, ErrorState } from "@/components/common/states";
import { CodeBlock } from "@/components/common/CodeBlock";
import { CopyButton } from "@/components/common/CopyButton";
import { SegmentedFilter } from "@/components/common/SegmentedFilter";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ContextRow, type ContextFact } from "@/components/security/ContextProvenance";
import { AssetNeighborhood } from "@/components/graph/AssetNeighborhood";
import { BlastRadius } from "@/components/graph/BlastRadius";

interface AssetFinding {
  id: string;
  rule_id: string;
  title: string;
  severity: string;
  status: string;
  risk_score: number | null;
}

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
  /** Set once a later scan looked for the asset and did not find it. */
  absent_since?: string | null;
  /** The map's lens for where the asset sits (DECISIONS.md §111). */
  placement?: {
    scope_id: string;
    scope_name: string;
    resource_group: string | null;
  };
  /** The directory it lives in, for a portal link that opens in the right one. */
  tenant_id?: string | null;
  /** OPEN and IN_PROGRESS, counted by the API. */
  open_findings?: number;
  /** Highest risk first, open and closed alike. */
  findings: AssetFinding[];
}

type Tab = "findings" | "connections" | "configuration";

const OPEN = new Set(["OPEN", "IN_PROGRESS"]);
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

/**
 * One asset: whether it is in trouble, what to fix, what it touches, and what
 * it is configured as (DECISIONS.md §112).
 *
 * The answer to "is this in trouble" sits above everything else, in the
 * summary strip, rather than being left to be counted off the findings list.
 * The rest is in tabs, because the graph and the configuration are each taller
 * than the screen and the findings -- usually a handful -- were being scrolled
 * past to reach them, or they past the findings. Connections loads only when
 * its tab opens: the graph is the whole tenant's, and opening the tab is the
 * request, so the two "draw it" buttons it used to sit behind are gone.
 */
export function AssetDetailPage() {
  const t = useT();
  const { assetId } = useParams();
  const location = useLocation();
  const [params, setParams] = useSearchParams();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["asset", assetId],
    queryFn: () => api.get<AssetDetail>(`/api/v1/assets/${assetId}`).then((r) => r.data),
  });

  // A link that names a centre or a route came for the graph -- the estate
  // map's asset boxes and a finding's "trace this route" both do -- so it opens
  // on Connections rather than landing on a tab that hides what it came for.
  const requested = params.get("tab");
  const tab: Tab =
    requested === "findings" || requested === "connections" || requested === "configuration"
      ? requested
      : params.has("around") || params.has("trace")
        ? "connections"
        : "findings";

  function selectTab(next: Tab) {
    setParams(
      (previous) => {
        const nextParams = new URLSearchParams(previous);
        nextParams.set("tab", next);
        return nextParams;
      },
      { replace: true },
    );
  }

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

  // Back to the list exactly as it was left -- filters, page, grouping, or the
  // map as opened -- when the asset was opened from there. Arriving any other
  // way, the inventory as it opens.
  const from = (location.state as { from?: unknown } | null)?.from;
  const back = typeof from === "string" && from.startsWith("/assets") ? from : "/assets";
  const open = data.findings.filter((finding) => OPEN.has(finding.status));
  const openCount = data.open_findings ?? open.length;

  return (
    <div className="flex flex-col gap-6">
      <Breadcrumbs trail={trail(data, back, t.assets.title)} />

      <Header asset={data} />

      {data.absent_since && (
        <Alert>
          <AlertTitle>Not seen since {formatDateTime(data.absent_since)}</AlertTitle>
          <AlertDescription>
            The last scan looked for this asset and did not find it: it was deleted, or
            CloudGuard lost access to where it was. Its findings are kept as they were at the
            last scan that saw it, and it is no longer part of any attack path.
          </AlertDescription>
        </Alert>
      )}

      <Summary asset={data} open={open} openCount={openCount} />

      <Tabs value={tab} onValueChange={(value) => selectTab(value as Tab)}>
        <TabsList>
          <TabsTrigger value="findings">
            Findings
            <span className="tabular-nums text-muted-foreground">{openCount}</span>
          </TabsTrigger>
          <TabsTrigger value="connections">Connections</TabsTrigger>
          <TabsTrigger value="configuration">Configuration</TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="pt-2">
          <FindingsPanel asset={data} />
        </TabsContent>

        {/* Panels are unmounted while closed, so the graph queries run only
            once this tab has been opened. */}
        <TabsContent value="connections" className="flex flex-col gap-6 pt-2">
          <AssetNeighborhood
            providerResourceId={data.provider_resource_id}
            name={data.name}
            drawNow
          />
          <BlastRadius providerResourceId={data.provider_resource_id} name={data.name} drawNow />
        </TabsContent>

        <TabsContent value="configuration" className="pt-2">
          <Card>
            <CardHeader>
              <CardTitle>Configuration</CardTitle>
              <CardDescription>
                As collected in the most recent snapshot that saw this asset
              </CardDescription>
            </CardHeader>
            <CardContent>
              <CodeBlock
                code={JSON.stringify(data.metadata, null, 2)}
                label="Copy this configuration"
              />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

/**
 * Assets, then where the asset sits -- its subscription and its group, each a
 * link to the estate map opened there -- then the asset. The map is the one
 * view that shows a group as a place, so that is where the trail leads.
 */
function trail(asset: AssetDetail, back: string, assetsTitle: string) {
  const crumbs: { label: string; to?: string }[] = [{ label: assetsTitle, to: back }];
  const placement = asset.placement;
  if (placement) {
    const scope = new URLSearchParams({ view: "graph", subscription_id: placement.scope_id });
    crumbs.push({ label: placement.scope_name, to: `/assets?${scope}` });
    if (placement.resource_group) {
      scope.set("resource_group", placement.resource_group);
      crumbs.push({ label: placement.resource_group, to: `/assets?${scope}` });
    }
  }
  crumbs.push({ label: asset.name });
  return crumbs;
}

function Header({ asset }: { asset: AssetDetail }) {
  const portal = portalUrl(asset);
  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-start">
      <div className="flex min-w-0 flex-1 items-start gap-4">
        {/* The asset's kind, as a mark: the same glyph its row carries in the
            inventory, so the page and the row that opened it are visibly the
            same thing. */}
        <span className="flex size-12 shrink-0 items-center justify-center rounded-xl border border-border bg-card text-muted-foreground shadow-xs">
          {createElement(resourceTypeIcon(asset.resource_type), {
            className: "size-5",
            "aria-hidden": true,
          })}
        </span>
        <div className="min-w-0">
          <h1 className="truncate text-2xl font-semibold tracking-tight">{asset.name}</h1>
          <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted-foreground">
            <ResourceTypeLabel type={asset.resource_type} />
            {asset.region && <IconLabel icon={FACT_ICONS.region}>{asset.region}</IconLabel>}
            {asset.environment && (
              <IconLabel icon={FACT_ICONS.environment}>{asset.environment}</IconLabel>
            )}
          </p>
          <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
            <IconLabel icon={FACT_ICONS.firstSeen}>
              First seen {formatDate(asset.first_seen_at)}
            </IconLabel>
            <span title={formatDateTime(asset.last_seen_at)}>
              <IconLabel icon={FACT_ICONS.lastSeen}>
                Last scanned {formatRelative(asset.last_seen_at)}
              </IconLabel>
            </span>
          </p>
        </div>
      </div>
      <div className="flex shrink-0 flex-wrap gap-2">
        {/* The provider's own id, whole: what the customer pastes into their
            portal or a ticket. Copied rather than shown, because at full
            length it is a paragraph, and truncated it is useless. */}
        <CopyButton text={asset.provider_resource_id} label="Copy ID" variant="outline" />
        {portal && (
          <a
            href={portal}
            target="_blank"
            rel="noreferrer"
            className={buttonVariants({ variant: "outline" })}
          >
            Open in Azure
            <ExternalLinkIcon data-icon="inline-end" aria-hidden />
          </a>
        )}
      </div>
    </div>
  );
}

/**
 * Whether the asset is in trouble, in one glance: what is open, and the three
 * factors every finding on it is scored by -- each with where the value came
 * from, because "CRITICAL" invites "says who?".
 */
function Summary({
  asset,
  open,
  openCount,
}: {
  asset: AssetDetail;
  open: AssetFinding[];
  openCount: number;
}) {
  const bySeverity = SEVERITY_ORDER.map(
    (level) => [level, open.filter((finding) => finding.severity === level).length] as const,
  ).filter(([, count]) => count > 0);

  return (
    <Card className="gap-0 py-0">
      <CardContent className="grid px-0 sm:grid-cols-2 lg:grid-cols-4">
        <Cell label="Open findings">
          <span className="text-2xl font-semibold tabular-nums">{openCount}</span>
          {bySeverity.length > 0 && (
            <span className="flex flex-wrap items-center gap-1.5">
              {bySeverity.map(([level, count]) => (
                <span key={level} className="flex items-center gap-1 text-xs tabular-nums">
                  {count}
                  <SeverityBadge level={level} size="sm" />
                </span>
              ))}
            </span>
          )}
        </Cell>
        <Cell icon={FACTOR_ICONS.criticality} label="Criticality">
          <dl className="w-full text-sm">
            <ContextRow
              label="Value"
              fact={asset.context?.criticality}
              fallback={<SeverityBadge level={asset.criticality} size="sm" />}
            />
          </dl>
        </Cell>
        <Cell icon={FACTOR_ICONS.dataSensitivity} label="Data sensitivity">
          <dl className="w-full text-sm">
            <ContextRow
              label="Value"
              fact={asset.context?.data_sensitivity}
              fallback={<SeverityBadge level={asset.data_sensitivity} size="sm" />}
            />
          </dl>
        </Cell>
        {/* Exposure has no provenance and needs none: it is read off the
            configuration in the capture -- a public IP is attached or it is
            not -- so there is nothing to attribute or declare. */}
        <Cell icon={FACTOR_ICONS.exposure} label="Internet exposure">
          <SeverityBadge level={asset.public_exposure} size="sm" />
        </Cell>
      </CardContent>
      <p className="border-t px-4 py-2 text-xs text-muted-foreground">
        Criticality, data sensitivity and exposure multiply the risk of every finding on this
        asset.
      </p>
    </Card>
  );
}

function Cell({
  label,
  icon,
  children,
}: {
  label: string;
  icon?: LucideIcon;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-2 border-b p-4 sm:odd:border-r lg:border-b-0 lg:border-r lg:last:border-r-0">
      <span className="text-xs font-medium text-muted-foreground">
        {icon ? <IconLabel icon={icon}>{label}</IconLabel> : label}
      </span>
      <div className="flex flex-wrap items-center gap-3">{children}</div>
    </div>
  );
}

/**
 * The findings, open first. Closed ones -- resolved, accepted, false
 * positive -- are history, and were mixed in among the live ones; they are one
 * press away, and the press is offered only when there are any.
 */
function FindingsPanel({ asset }: { asset: AssetDetail }) {
  const [show, setShow] = useState<"open" | "closed">("open");
  const open = asset.findings.filter((finding) => OPEN.has(finding.status));
  const closed = asset.findings.filter((finding) => !OPEN.has(finding.status));
  const rows = show === "open" ? open : closed;
  const azureType = asset.metadata?.azure_type;

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        {closed.length > 0 && (
          <SegmentedFilter
            label="Which findings"
            value={show}
            onChange={(value) => setShow(value as "open" | "closed")}
            segments={[
              { value: "open", label: `Open (${open.length})` },
              { value: "closed", label: `Closed (${closed.length})` },
            ]}
          />
        )}

        {rows.length === 0 && show === "open" && (
          // Two different nothings. "No findings" is only true where
          // CloudGuard has rules for the kind of resource; for anything it
          // does not model, it is the absence of a check, and saying "no
          // findings" would present that as a clean bill of health.
          <p className="py-4 text-center text-sm text-muted-foreground">
            {asset.resource_type === "unknown"
              ? `CloudGuard has no checks for this kind of resource${
                  typeof azureType === "string" ? ` (${azureType})` : ""
                } yet, so nothing here has been evaluated.`
              : `No open findings. Last scanned ${formatRelative(asset.last_seen_at)}.`}
          </p>
        )}

        {rows.length > 0 && (
          <ul className="-mx-2 flex flex-col">
            {rows.map((finding) => (
              <li key={finding.id}>
                {/* The row is the link: the target is the whole line, not
                    the length of the title. */}
                <Link
                  to={`/findings/${finding.id}`}
                  className={cn(
                    "group flex items-center gap-3 rounded-lg px-2 py-2.5 transition-colors hover:bg-muted/50",
                    "focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
                  )}
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
  );
}
