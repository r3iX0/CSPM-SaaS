import { useId, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  ChevronDownIcon,
  CrosshairIcon,
  RadarIcon,
  RouteIcon,
  ScissorsIcon,
  XIcon,
} from "lucide-react";

import type { MappedRoute, RouteMap, RouteMapEdge, RouteMapNode } from "@/lib/types";
import { useT } from "@/i18n";
import { cn, formatDay, label } from "@/lib/format";
import { CopyButton } from "@/components/common/CopyButton";
import { ResourceTypeLabel } from "@/components/security/IconLabel";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { AssetAccessPanel } from "./AssetAccess";
import { assetFindingsQuery, inspectQuery } from "./graphQueries";
import { bestCutAt, placeName } from "./routeOrder";

/**
 * What a box is, what it holds up, and what can be done about it
 * (DECISIONS.md §254). A click on a box used to land on a list of its routes;
 * it lands on this now, with the routes below it.
 *
 * Everything but the findings and the inspector's reading is on the page
 * already. Those two are asked for when the card opens, never with the page.
 */
export function AssetCard({
  node,
  map,
  through,
  compromised,
  onTrace,
  onCut,
  onCompromise,
  onClose,
}: {
  node: RouteMapNode;
  map: RouteMap;
  /** The routes through the box, in the list's order: the first is the worst. */
  through: readonly MappedRoute[];
  /** Whether the drawing shows what a compromise of it reaches (§255). */
  compromised: boolean;
  onTrace: (key: string) => void;
  onCut: (edge: RouteMapEdge) => void;
  onCompromise: () => void;
  onClose: () => void;
}) {
  const t = useT();
  const cut = bestCutAt(map.edges, node.id);
  const ways = new Set(through.map((route) => route.entry.id).filter((id) => id !== node.id));
  const reaches = new Set(through.map((route) => route.target.id).filter((id) => id !== node.id));
  const worst = through[0];
  const share = new URL(window.location.href);
  share.search = new URLSearchParams({ through: node.id }).toString();

  return (
    <section
      aria-label={t.attackPaths.cardLabel(node.name)}
      className="flex flex-col gap-3 border-b border-border p-3"
    >
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          {node.asset_id ? (
            <Link
              to={`/assets/${node.asset_id}`}
              className="focus-ring text-title font-medium underline-offset-4 hover:underline"
            >
              {node.name}
            </Link>
          ) : (
            <p className="text-title font-medium">{node.name}</p>
          )}
          <p className="flex flex-wrap items-center gap-x-2 text-meta text-muted-foreground">
            <ResourceTypeLabel type={node.resource_type} />
            <span>{placeName(node)}</span>
          </p>
        </div>
        <Button
          variant="ghost"
          size="icon-sm"
          aria-label={t.attackPaths.cardClose}
          onClick={onClose}
        >
          <XIcon />
        </Button>
      </div>

      <dl className="grid grid-cols-3 gap-2 text-meta">
        <Count name={t.attackPaths.cardRoutes} value={through.length} />
        <Count name={t.attackPaths.cardWaysIn} value={ways.size} />
        <Count name={t.attackPaths.cardReaches} value={reaches.size} />
      </dl>

      {cut && (
        <div className="flex flex-col gap-1 rounded-lg border border-ok-border bg-ok-bg/40 p-2">
          <p className="text-caption font-medium text-muted-foreground">
            {t.attackPaths.cardBestCut}
          </p>
          <p className="text-body">{cut.detail}</p>
          <div className="flex items-center justify-between gap-2">
            <span className="text-meta text-muted-foreground">
              {t.attackPaths.planCutCloses(cut.severs)}
            </span>
            <Button variant="outline" size="xs" onClick={() => onCut(cut)}>
              <ScissorsIcon data-icon="inline-start" />
              {t.attackPaths.addToPlan}
            </Button>
          </div>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        {worst && (
          <Button variant="outline" size="xs" onClick={() => onTrace(worst.key)}>
            <RouteIcon data-icon="inline-start" />
            {t.attackPaths.cardTraceWorst}
          </Button>
        )}
        <Button
          variant={compromised ? "secondary" : "outline"}
          size="xs"
          aria-pressed={compromised}
          onClick={onCompromise}
        >
          <CrosshairIcon data-icon="inline-start" />
          {t.attackPaths.cardCompromised}
        </Button>
        <CopyButton variant="ghost" label={t.attackPaths.cardCopy} text={share.toString()} />
      </div>

      {node.asset_id && <CardFindings assetId={node.asset_id} />}
      <CardInspector node={node} />
    </section>
  );
}

function Count({ name, value }: { name: string; value: number }) {
  return (
    <div className="flex flex-col">
      <dt className="text-muted-foreground">{name}</dt>
      <dd className="text-title font-medium tabular-nums">{value}</dd>
    </div>
  );
}

function CardFindings({ assetId }: { assetId: string }) {
  const t = useT();
  const findings = useQuery(assetFindingsQuery(assetId));
  if (findings.isPending) return <Skeleton className="h-10 w-full" />;
  if (findings.isError || findings.data.length === 0) return null;
  return (
    <div className="flex flex-col gap-1">
      <h4 className="text-caption font-medium text-muted-foreground">
        {t.attackPaths.cardFindings}
      </h4>
      <ul className="flex flex-col gap-1">
        {findings.data.map((finding) => (
          <li key={finding.id} className="flex items-center gap-2">
            <SeverityBadge level={finding.severity} size="sm" />
            <Link
              to={`/remediation?fix=${finding.id}`}
              className="focus-ring min-w-0 flex-1 truncate text-meta underline-offset-4 hover:underline"
            >
              {finding.title}
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Where it is defined in code, what happened to it lately, and who holds it (§254). */
function CardInspector({ node }: { node: RouteMapNode }) {
  const t = useT();
  const [access, setAccess] = useState(false);
  const panel = useId();
  const read = useQuery(inspectQuery(node.id));

  return (
    <div className="flex flex-col gap-2">
      {read.isPending ? (
        <Skeleton className="h-10 w-full" />
      ) : read.isError ? null : (
        <>
          <div className="flex flex-col gap-0.5 text-meta">
            <h4 className="text-caption font-medium text-muted-foreground">
              {t.attackPaths.cardCode}
            </h4>
            {read.data.defined_in.length === 0 ? (
              <p className="text-muted-foreground">{t.attackPaths.cardCodeNone}</p>
            ) : (
              read.data.defined_in.map((home) => (
                <p key={`${home.repository}|${home.address}`} className="font-mono break-all">
                  {home.repository}
                  {home.working_directory ? `/${home.working_directory}` : ""} · {home.address}
                </p>
              ))
            )}
          </div>
          <div className="flex flex-col gap-0.5 text-meta">
            <h4 className="text-caption font-medium text-muted-foreground">
              {t.attackPaths.cardActivity}
            </h4>
            {read.data.sign_in && (
              <p>
                {!read.data.sign_in.read
                  ? t.attackPaths.cardSignInUnread
                  : read.data.sign_in.last_sign_in
                    ? t.attackPaths.cardSignIn(formatDay(read.data.sign_in.last_sign_in))
                    : t.attackPaths.cardSignInNever}
              </p>
            )}
            {read.data.changes.length === 0 && !read.data.sign_in ? (
              <p className="text-muted-foreground">{t.attackPaths.cardNoChanges}</p>
            ) : (
              read.data.changes.slice(0, 3).map((change) => (
                <p key={`${change.change}|${change.observed_at}`}>
                  {label(change.change)}
                  {change.current_value ? ` (${change.current_value})` : ""}
                  <span className="text-muted-foreground"> · {formatDay(change.observed_at)}</span>
                </p>
              ))
            )}
          </div>
        </>
      )}
      <Button
        variant="ghost"
        size="xs"
        className="self-start"
        aria-expanded={access}
        aria-controls={panel}
        onClick={() => setAccess((was) => !was)}
      >
        <RadarIcon data-icon="inline-start" />
        {t.attackPaths.cardAccess}
        <ChevronDownIcon
          data-icon="inline-end"
          className={cn("transition-transform", access && "rotate-180")}
        />
      </Button>
      <div id={panel} hidden={!access}>
        {access && (
          <AssetAccessPanel
            providerResourceId={node.id}
            name={node.name}
            resourceType={node.resource_type}
          />
        )}
      </div>
    </div>
  );
}
