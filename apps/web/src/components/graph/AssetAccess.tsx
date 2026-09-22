import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { api, ApiError } from "@/lib/api";
import type {
  AccessAssetRef,
  AccessGrant,
  AccessHolder,
  AccessKind,
  AssetAccess,
} from "@/lib/types";
import { useT } from "@/i18n";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/common/states";
import { ResourceTypeLabel } from "@/components/security/IconLabel";

/** Containers a role is assigned at, rather than things with contents. */
const SCOPES = new Set(["subscription", "resource_group"]);

type Strings = ReturnType<typeof useT>;

/**
 * Who holds access to an asset, and what an identity holds (DECISIONS.md §125).
 *
 * The half of "who could take this" a route cannot answer: a route needs a
 * way in, and an administrator with Owner over the subscription is on no
 * route until something exposed runs as them. Read from the same evaluation
 * the routes are walked with, so a holder listed as able to take what the
 * asset holds is exactly one a route may pass through.
 *
 * Both halves come in one request, either possibly empty: an asset is held by
 * principals, an identity holds roles, and a managed identity's page is both.
 */
export function AssetAccessPanel({
  providerResourceId,
  name,
  resourceType,
}: {
  providerResourceId: string;
  name: string;
  resourceType: string;
}) {
  const t = useT();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["asset-access", providerResourceId],
    queryFn: () =>
      api
        .get<AssetAccess>(
          `/api/v1/attack-paths/access/${encodeURIComponent(providerResourceId)}`,
        )
        .then((r) => r.data),
    retry: false,
  });

  if (isLoading) {
    return (
      <Card>
        <CardContent className="flex flex-col gap-2">
          <Skeleton className="h-4 w-48" />
          <Skeleton className="h-4 w-72" />
          <Skeleton className="h-4 w-64" />
        </CardContent>
      </Card>
    );
  }
  if (error instanceof ApiError && error.status === 404) {
    return <p className="text-sm text-muted-foreground">{t.access.notInGraph}</p>;
  }
  if (error) {
    return (
      <ErrorState
        title={t.access.failed}
        detail="CloudGuard could not reach its own API to read the graph."
        impact="Nothing about your environment has changed — this is a problem displaying it."
        onRetry={() => refetch()}
      />
    );
  }
  if (!data) return null;

  // An identity's page leads with what it holds; nobody is assigned a role
  // *on* an identity, so its holders list is usually empty and is shown only
  // when there is something in it.
  const showHolders = data.holders.length > 0 || data.grants.length === 0;
  return (
    <div className="flex flex-col gap-6">
      {data.grants.length > 0 && <Grants grants={data.grants} name={name} />}
      {showHolders && (
        <Holders holders={data.holders} name={name} scope={SCOPES.has(resourceType)} />
      )}
    </div>
  );
}

function Holders({
  holders,
  name,
  scope,
}: {
  holders: AccessHolder[];
  name: string;
  scope: boolean;
}) {
  const t = useT();
  // The order a person looking for "who could take this" reads in. The API
  // sends them sorted the same way; grouping here only adds the headings.
  const groups: { title: string; members: AccessHolder[] }[] = scope
    ? [{ title: "", members: holders }]
    : [
        { title: t.access.controlsGroup, members: holders.filter((h) => h.controls) },
        // Whoever could activate a role: never control until they do (§130).
        { title: t.access.eligibleGroup, members: holders.filter((h) => h.eligible) },
        {
          title: t.access.manageGroup,
          members: holders.filter(
            (h) => !h.controls && !h.eligible && h.resolved && h.kinds.includes("manage"),
          ),
        },
        {
          title: t.access.readGroup,
          members: holders.filter(
            (h) => !h.controls && !h.eligible && h.resolved && !h.kinds.includes("manage"),
          ),
        },
        {
          title: t.access.unresolvedGroup,
          members: holders.filter((h) => !h.resolved && !h.eligible),
        },
      ];

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t.access.holdersTitle}</CardTitle>
        <CardDescription>
          {scope ? t.access.scopeHoldersDescription(name) : t.access.holdersDescription(name)}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        {holders.length === 0 && (
          <p className="text-sm text-muted-foreground">{t.access.holdersEmpty}</p>
        )}
        {groups
          .filter((group) => group.members.length > 0)
          .map((group) => (
            <section key={group.title || "all"} className="flex flex-col gap-2">
              {group.title && (
                <h3 className="text-xs font-medium text-muted-foreground">
                  {group.title} <span className="tabular-nums">({group.members.length})</span>
                </h3>
              )}
              <ul className="flex flex-col divide-y">
                {group.members.map((holder, index) => (
                  <HolderRow
                    key={`${holder.principal.id}:${holder.role}:${holder.at.id}:${index}`}
                    holder={holder}
                    scope={scope}
                  />
                ))}
              </ul>
            </section>
          ))}
      </CardContent>
    </Card>
  );
}

function HolderRow({ holder, scope }: { holder: AccessHolder; scope: boolean }) {
  const t = useT();
  return (
    <li className="flex flex-col gap-1 py-2 text-sm first:pt-0 last:pb-0">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <AssetLink asset={holder.principal} className="font-medium" />
        <span className="text-muted-foreground">{holder.role}</span>
        <span className="text-xs text-muted-foreground">
          {t.access.at(holder.at.name)}
          {holder.inherited_from &&
            `, ${t.access.inherited(ancestorName(holder.inherited_from))}`}
        </span>
      </div>
      <Notes
        t={t}
        phrases={[
          ...(scope ? [] : holder.kinds.map((kind) => t.access.kinds[kind])),
          ...(holder.through_directory ? [t.access.throughDirectory] : []),
          ...(holder.eligible ? [t.access.eligible] : []),
        ]}
        conditional={holder.conditional}
        resolved={holder.resolved}
      />
      {holder.members == null && holder.principal.resource_type === "group" && (
        <p className="text-xs text-muted-foreground">{capitalise(t.access.membersUnread)}</p>
      )}
      {holder.members != null && holder.members_total != null && (
        <Members holder={holder} />
      )}
      {holder.runs_on.length > 0 && (
        <p className="flex flex-wrap items-center gap-x-2 text-xs text-muted-foreground">
          <span>{t.access.runsOn}</span>
          {holder.runs_on.map((workload) => (
            <AssetLink key={workload.id} asset={workload} />
          ))}
        </p>
      )}
    </li>
  );
}

/**
 * Who a group's role reaches. Members CloudGuard read as accounts link to them;
 * the rest are names, because a name is all that was read.
 */
function Members({ holder }: { holder: AccessHolder }) {
  const t = useT();
  const unlisted = holder.unlisted_members ?? [];
  const shown = (holder.members?.length ?? 0) + unlisted.length;
  const more = (holder.members_total ?? 0) - shown;
  return (
    <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
      <span>{capitalise(t.access.members(holder.members_total ?? 0))}</span>
      {holder.members?.map((member) => (
        <AssetLink key={member.id} asset={member} />
      ))}
      {unlisted.map((name) => (
        <span key={name}>{name}</span>
      ))}
      {more > 0 && <span>{t.access.andMore(more)}</span>}
    </p>
  );
}

function Grants({ grants, name }: { grants: AccessGrant[]; name: string }) {
  const t = useT();
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t.access.grantsTitle}</CardTitle>
        <CardDescription>{t.access.grantsDescription(name)}</CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="flex flex-col divide-y">
          {grants.map((grant, index) => (
            <GrantRow key={`${grant.role}:${grant.scope}:${index}`} grant={grant} />
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

function GrantRow({ grant }: { grant: AccessGrant }) {
  const t = useT();
  const more = grant.controlled_total - grant.controlled.length;
  return (
    <li className="flex flex-col gap-1.5 py-3 text-sm first:pt-0 last:pb-0">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="font-medium">{grant.role}</span>
        <span className="text-xs text-muted-foreground">
          {grant.at ? (
            <>
              {t.access.at("")}
              <AssetLink asset={grant.at} />
            </>
          ) : (
            t.access.unplaced(grant.scope)
          )}
          {grant.inherited_from && `, ${t.access.inherited(ancestorName(grant.inherited_from))}`}
        </span>
        {grant.via && (
          <span className="text-xs text-muted-foreground">
            {grant.via.resource_type === "group" ? t.access.via : t.access.signsInAs}{" "}
            <AssetLink asset={grant.via} />
          </span>
        )}
      </div>
      <Notes
        t={t}
        phrases={[
          ...(grant.grants_access ? [t.access.kinds.grant_access] : []),
          ...(grant.through_directory ? [t.access.throughDirectory] : []),
          ...(grant.eligible ? [t.access.eligible] : []),
        ]}
        conditional={grant.conditional}
        resolved={grant.resolved}
      />
      {grant.resolved && grant.at && (
        <div className="flex flex-col gap-1 text-xs text-muted-foreground">
          <p className="font-medium text-foreground">
            {t.access.controlsCount(grant.controlled_total)}
          </p>
          {grant.controlled.length > 0 && (
            <p className="flex flex-wrap items-center gap-x-3 gap-y-1">
              {grant.controlled.map((asset) => (
                <AssetLink key={asset.id} asset={asset} withType />
              ))}
              {more > 0 && <span>{t.access.andMore(more)}</span>}
            </p>
          )}
        </div>
      )}
      {grant.resolved && grant.access.length > 0 && (
        <ul className="flex flex-col gap-0.5 text-xs text-muted-foreground">
          {grant.access.map((entry) => (
            <li key={entry.resource_type} className="flex flex-wrap items-center gap-x-2">
              <ResourceTypeLabel type={entry.resource_type} />
              <span>{describeKinds(t, entry.kinds)}</span>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

/** What is known about one role, and what is not, as one muted line. */
function Notes({
  t,
  phrases,
  conditional,
  resolved,
}: {
  t: Strings;
  phrases: string[];
  conditional: boolean;
  resolved: boolean;
}) {
  const parts = resolved ? [...phrases] : [t.access.unresolved];
  if (conditional) parts.push(t.access.conditional);
  if (parts.length === 0) return null;
  return <p className="text-xs text-muted-foreground">{capitalise(parts.join("; "))}</p>;
}

function AssetLink({
  asset,
  className,
  withType = false,
}: {
  asset: AccessAssetRef;
  className?: string;
  withType?: boolean;
}) {
  const label = withType ? (
    <ResourceTypeLabel type={asset.resource_type} label={asset.name} />
  ) : (
    asset.name
  );
  return asset.asset_id ? (
    <Link to={`/assets/${asset.asset_id}`} className={`hover:underline ${className ?? ""}`}>
      {label}
    </Link>
  ) : (
    <span className={className}>{label}</span>
  );
}

function describeKinds(t: Strings, kinds: AccessKind[]): string {
  return kinds.map((kind) => t.access.kinds[kind]).join(", ");
}

/** A management group by its name, or the root by what it is. */
function ancestorName(scope: string): string {
  const trimmed = scope.replace(/\/+$/, "");
  if (!trimmed) return "the tenant root";
  return `management group ${trimmed.split("/").pop()}`;
}

function capitalise(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}
