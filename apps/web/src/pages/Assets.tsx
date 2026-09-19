import { Fragment, useEffect, useMemo, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { BoxesIcon, SearchIcon, XIcon } from "lucide-react";
import { RISK_KIND_ICONS, resourceTypeIcon } from "@/lib/icons";
import { ResourceTypeLabel } from "@/components/security/IconLabel";

import { api } from "@/lib/api";
import type { Asset } from "@/lib/types";
import { useT } from "@/i18n";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { EstateGraph } from "@/components/assets/EstateGraph";
import { Badge } from "@/components/ui/badge";
import { EmptyState, ErrorState, PageHeader, TableSkeleton } from "@/components/common/states";
import { Button, buttonVariants } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { SelectField } from "@/components/common/SelectField";
import { SegmentedFilter } from "@/components/common/SegmentedFilter";
import { useUrlFilters } from "@/lib/useUrlFilters";
import { ROW_ACTIVE, useRowNavigation } from "@/lib/keyboard";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Pager } from "@/components/common/Pager";
import { cn, formatDate, formatRelative, resourceTypeLabel } from "@/lib/format";
import { scopeLabel } from "@/lib/scope";
import { stagger } from "@/lib/motion";

const PAGE_SIZE = 50;
const SEARCH_DEBOUNCE_MS = 250;

type GroupKey = "none" | "scope" | "resource_type" | "environment";

type View = "list" | "graph";

/** What the map marks an asset with, as one list filter (DECISIONS.md §112). */
const SIGNAL_PARAM: Record<string, string> = {
  entry: "entry_point",
  sensitive: "sensitive",
  route: "on_attack_path",
};

/**
 * The inventory, and what is worth knowing about each thing in it.
 *
 * Two problems with what this replaces, and the second was a plain bug.
 *
 * The list arrived alphabetically, so the most exposed asset in an estate was
 * wherever the alphabet put it. It now sorts by open findings first, because an
 * asset list in a security product is not a directory -- it is a queue.
 *
 * And the endpoint paginates (`limit`/`offset`, with the true count in `meta`)
 * while the page requested one default-sized page and rendered it as though it
 * were everything. A tenant with four hundred assets saw a hundred, with
 * nothing on the screen suggesting the other three hundred existed.
 *
 * Grouping by scope is the default, because that is how an estate is actually
 * organised and how responsibility for it is usually divided: a resource group
 * tends to have an owner, and "which of my resource groups is the problem" is a
 * question a flat list cannot answer. It is read out of the provider's own id
 * (`lib/scope.ts`) rather than requested, so it costs nothing.
 */
export function AssetsPage() {
  const t = useT();
  // Every filter, the view and the grouping live in the URL, so a filtered
  // inventory is a link -- and the scope filters the tree links into are the
  // same mechanism rather than a special case.
  const [filters, update] = useUrlFilters({
    q: "",
    environment: "all",
    exposure: "all",
    signal: "all",
    type: "all",
    group: "scope",
    view: "list",
    page: "0",
    subscription_id: "",
    resource_group: "",
  });
  const { environment, exposure, type, signal } = filters;
  const location = useLocation();
  // Carried into an asset's page, so its trail returns to this exact list --
  // filters, page and grouping -- rather than to a bare inventory.
  const returnTo = { from: `${location.pathname}${location.search}` };
  const groupBy = filters.group as GroupKey;
  // `tree` was the hierarchy view, which the map now is (§112): an old link to
  // it opens the map rather than falling back to the list.
  const view: View =
    filters.view === "graph" || filters.view === "tree" ? "graph" : "list";
  const page = Math.max(0, Number.parseInt(filters.page, 10) || 0);
  const subscriptionId = filters.subscription_id;
  const resourceGroup = filters.resource_group;
  const search = filters.q;

  // Typed here, written to the URL after a pause -- a request per keystroke is
  // what this page used to send.
  const [typed, setTyped] = useState(filters.q);
  useEffect(() => {
    const timer = setTimeout(() => {
      if (typed.trim() !== search) update({ q: typed.trim() || null, page: null });
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [typed, search, update]);

  function setPage(next: number) {
    update({ page: String(next) });
  }

  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (environment !== "all") params.set("environment", environment);
  if (exposure !== "all") params.set("exposure", exposure);
  if (type !== "all") params.set("resource_type", type);
  if (SIGNAL_PARAM[signal]) params.set(SIGNAL_PARAM[signal], "true");
  if (subscriptionId) params.set("subscription_id", subscriptionId);
  if (resourceGroup) params.set("resource_group", resourceGroup);
  params.set("limit", String(PAGE_SIZE));
  params.set("offset", String(page * PAGE_SIZE));

  function clearScope() {
    update({ subscription_id: null, resource_group: null, page: null });
  }

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: [
      "assets",
      search,
      environment,
      exposure,
      type,
      signal,
      subscriptionId,
      resourceGroup,
      page,
    ],
    queryFn: () =>
      api
        .get<Asset[]>(`/api/v1/assets?${params.toString()}`)
        .then((r) => {
          const meta = r.meta as
            | {
                total?: number;
                unchecked?: number;
                facets?: {
                  resource_type?: Record<string, number>;
                  environment?: Record<string, number>;
                };
              }
            | undefined;
          return {
            assets: r.data,
            total: meta?.total ?? r.data.length,
            // Counted over the whole filtered set by the API, not this page.
            unchecked: meta?.unchecked ?? 0,
            facets: meta?.facets ?? {},
          };
        }),
    // Paging without this blanks the table on every page turn, which reads as
    // the data having gone rather than as a page loading.
    placeholderData: keepPreviousData,
    // The map reads its own endpoint; a page of the list behind it is a
    // request nobody sees.
    enabled: view === "list",
  });

  // Memoised rather than `data?.assets ?? []`, which minted a new array every
  // render and so defeated the memos below -- they re-grouped
  // the whole page on every keystroke.
  const assets = useMemo(() => data?.assets ?? [], [data]);
  const total = data?.total ?? 0;
  const unchecked = data?.unchecked ?? 0;

  /**
   * The types and environments the filters offer, counted by the API over the
   * whole filtered set -- each without its own filter, so choosing one still
   * offers the rest. These used to be read off the fifty rows on the page, so
   * a type that happened to sort onto page two could not be chosen at all.
   * The selected value is kept even at a count of zero, so the menu never
   * loses the thing it is showing.
   */
  const facets = data?.facets;
  const types = useMemo(() => {
    const found = new Set(Object.keys(facets?.resource_type ?? {}));
    if (type !== "all") found.add(type);
    return [...found].sort();
  }, [facets, type]);
  const environments = useMemo(() => {
    const found = new Set(Object.keys(facets?.environment ?? {}));
    if (environment !== "all") found.add(environment);
    return [...found].sort();
  }, [facets, environment]);


  // `assets` arrives in queue order -- most open findings first, across the
  // whole set. The API sorts, because a page can only re-sort the rows it
  // holds; grouping below keeps that order within each group.
  const groups = useMemo(() => {
    if (groupBy === "none") return [["", assets] as const];
    const map = new Map<string, Asset[]>();
    for (const asset of assets) {
      const key =
        groupBy === "scope"
          ? scopeLabel(asset.provider_resource_id)
          : groupBy === "resource_type"
            ? resourceTypeLabel(asset.resource_type)
            : (asset.environment ?? "Unlabelled");
      map.set(key, [...(map.get(key) ?? []), asset]);
    }
    return [...map.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [assets, groupBy]);

  // Rows in the order they are drawn -- grouped, then within each group -- so
  // `j` moves down the screen rather than through the fetch order.
  const drawn = useMemo(() => groups.flatMap(([, rows]) => rows), [groups]);
  const rowIndex = useMemo(
    () => new Map(drawn.map((asset, index) => [asset.id, index])),
    [drawn],
  );
  const activeRow = useRowNavigation(
    view === "list" ? drawn.map((asset) => `/assets/${asset.id}`) : [],
  );

  const filtering =
    search !== "" ||
    environment !== "all" ||
    exposure !== "all" ||
    type !== "all" ||
    signal !== "all" ||
    subscriptionId !== "" ||
    resourceGroup !== "";
  const pages = Math.ceil(total / PAGE_SIZE);

  /** A filter change re-slices the whole set, so the page resets with it. */
  function resetTo(key: "type" | "environment" | "exposure" | "signal") {
    return (value: string | null) => update({ [key]: value ?? "all", page: null });
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        icon={BoxesIcon}
        title={t.assets.title}
        description="Everything CloudGuard has discovered, with what it is worth and how exposed it is."
        actions={
          // Two readings of one inventory: the queue and the map. The list
          // ranks by what is wrong; the map says which part of the estate --
          // and so which owner -- it is wrong in, and how those parts reach
          // each other. The hierarchy was a third reading of the second
          // question, and is now the map's own contents list (§111, §112).
          <SegmentedFilter
            label="View"
            value={view}
            onChange={(value) => update({ view: value })}
            segments={[
              { value: "list", label: "List" },
              { value: "graph", label: "Map" },
            ]}
          />
        }
      />

      {view === "graph" && (
        <MapIgnoresFilters
          active={[
            search && "search",
            type !== "all" && "type",
            environment !== "all" && "environment",
            exposure !== "all" && "exposure",
            signal !== "all" && "signal",
          ].filter((name): name is string => Boolean(name))}
          onClear={() => {
            setTyped("");
            update({ q: null, type: null, environment: null, exposure: null, signal: null });
          }}
        />
      )}

      {view === "graph" && <EstateGraph scopeId={subscriptionId} group={resourceGroup} />}

      {view === "list" && (
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
        <div className="relative flex-1 lg:max-w-xs">
          <SearchIcon
            className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            placeholder="Search by name"
            aria-label="Search assets"
            data-page-search
            className="pl-8"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <SelectField
            value={type}
            onValueChange={resetTo("type")}
            ariaLabel="Filter by type"
            className="w-[190px]"
            idleValue="all"
            options={[
              { value: "all", label: "All types" },
              ...types.map((value) => ({
                value,
                label: resourceTypeLabel(value),
                icon: resourceTypeIcon(value),
              })),
            ]}
          />

          <SelectField
            value={environment}
            onValueChange={resetTo("environment")}
            ariaLabel="Filter by environment"
            className="w-[170px]"
            idleValue="all"
            options={[
              { value: "all", label: "All environments" },
              ...environments.map((value) => ({
                value,
                label: value.charAt(0).toUpperCase() + value.slice(1),
              })),
            ]}
          />

          <SelectField
            value={exposure}
            onValueChange={resetTo("exposure")}
            ariaLabel="Filter by exposure"
            className="w-[160px]"
            idleValue="all"
            options={[
              { value: "all", label: "All exposure" },
              { value: "CRITICAL", label: "Critical" },
              { value: "HIGH", label: "High" },
              { value: "MEDIUM", label: "Medium" },
              { value: "LOW", label: "Low" },
              { value: "UNKNOWN", label: "Unknown" },
            ]}
          />

          {/* The map's three marks, as a filter: what it draws a globe, a
              cylinder or a route on. Counted with the graph's own predicates,
              so a box saying "2 reachable from the internet" and this list
              agree. */}
          <SelectField
            value={signal}
            onValueChange={resetTo("signal")}
            ariaLabel="Filter by what the map marks"
            className="w-[190px]"
            idleValue="all"
            options={[
              { value: "all", label: "Any asset" },
              { value: "entry", label: "Reachable from the internet" },
              { value: "sensitive", label: "Holds sensitive data" },
              { value: "route", label: "On an attack path" },
            ]}
          />

          <SelectField
            value={groupBy}
            onValueChange={(value) => update({ group: value || "none" })}
            ariaLabel="Group assets"
            className="w-[150px]"
            options={[
              { value: "none", label: "No grouping" },
              { value: "scope", label: "By resource group" },
              { value: "resource_type", label: "By type" },
              { value: "environment", label: "By environment" },
            ]}
          />
        </div>
      </div>
      )}

      {view === "list" && (subscriptionId || resourceGroup) && (
        <div className="flex items-center gap-2">
          <Badge variant="secondary" className="gap-1.5 font-normal">
            {resourceGroup ? (
              <>
                Resource group <code className="font-medium">{resourceGroup}</code>
              </>
            ) : (
              <>
                Subscription <code className="font-medium">{subscriptionId}</code>
              </>
            )}
            <button
              onClick={clearScope}
              aria-label="Clear scope filter"
              className="rounded-full text-muted-foreground transition-colors hover:text-foreground"
            >
              <XIcon className="size-3" />
            </button>
          </Badge>
        </div>
      )}

      {view === "list" && isLoading && <TableSkeleton columns={7} />}

      {view === "list" && error && (
        <ErrorState
          title="Could not load your assets"
          detail="CloudGuard could not reach its own API to read the inventory."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      {view === "list" && data && assets.length === 0 && (
        <EmptyState
          icon={BoxesIcon}
          title={filtering ? "No assets match these filters" : t.assets.empty}
          detail={
            filtering
              ? "Widen the filters, or clear the search, to see the rest of the inventory."
              : "Once a scan completes, everything it discovered appears here."
          }
          action={
            filtering ? (
              <Button
                variant="outline"
                onClick={() => {
                  setTyped("");
                  update({
                    q: null,
                    environment: null,
                    exposure: null,
                    signal: null,
                    type: null,
                    subscription_id: null,
                    resource_group: null,
                    page: null,
                  });
                }}
              >
                Clear filters
              </Button>
            ) : (
              <Link
                to="/scans"
                className={buttonVariants({ variant: "outline" })}
              >
                Run a scan
              </Link>
            )
          }
        />
      )}

      {view === "list" && data && assets.length > 0 && (
        <>
          <Card className="overflow-hidden py-0">
            <CardContent className="px-0">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="w-[30%]">Resource</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Environment</TableHead>
                    <TableHead>Criticality</TableHead>
                    <TableHead>Exposure</TableHead>
                    <TableHead className="text-right">{t.assets.openFindings}</TableHead>
                    <TableHead className="text-right">Last seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {/* A keyed Fragment rather than the `<>` shorthand, which
                      cannot take one. Each group renders a heading row and its
                      assets as siblings, so the wrapper is what sits in the
                      list -- and a keyless list child is how React ends up
                      reusing one group's rows under another's heading when the
                      grouping changes. The inner rows were keyed all along,
                      which is what made this look fine. */}
                  {groups.map(([groupName, rows]) => (
                    <Fragment key={groupName}>
                      {groupName && (
                        <TableRow className="hover:bg-transparent">
                          <TableCell
                            colSpan={7}
                            className="bg-muted/50 py-1.5 text-xs font-medium text-muted-foreground"
                          >
                            {groupName}
                            <span className="ml-2 tabular-nums opacity-70">{rows.length}</span>
                          </TableCell>
                        </TableRow>
                      )}
                      {rows.map((asset, index) => (
                        <TableRow
                          key={asset.id}
                          // Relative, so the name's overlay makes the whole
                          // row the way into the asset.
                          className={cn(
                            "relative cursor-pointer [animation:cg-rise_260ms_ease-out_both]",
                            ROW_ACTIVE,
                          )}
                          style={stagger(index)}
                          data-row-index={rowIndex.get(asset.id)}
                          data-active={activeRow === rowIndex.get(asset.id)}
                        >
                          <TableCell className="max-w-0">
                            <span className="flex min-w-0 items-center gap-1.5">
                              <Link
                                to={`/assets/${asset.id}`}
                                state={returnTo}
                                className="block truncate font-medium text-foreground after:absolute after:inset-0 hover:underline"
                              >
                                {asset.name}
                              </Link>
                              {/* The strongest thing a row can say: this asset
                                  is on a route from the internet to something
                                  sensitive. A mark rather than a column, so a
                                  row that is not stays quiet. */}
                              {asset.on_attack_path && <OnRouteMark />}
                            </span>
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            <ResourceTypeLabel
                              type={asset.resource_type}
                              label={asset.azure_type}
                            />
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {asset.environment ?? "—"}
                          </TableCell>
                          <TableCell>
                            <SeverityBadge level={asset.criticality} size="sm" />
                          </TableCell>
                          <TableCell>
                            <SeverityBadge level={asset.public_exposure} size="sm" />
                          </TableCell>
                          <TableCell className="text-right">
                            {/* A count, not a severity, so it gets no severity
                                colour -- but a non-zero one is drawn as a chip
                                so the rows with work on them stand out from the
                                rows without. */}
                            <span
                              className={cn(
                                "inline-flex min-w-7 justify-center rounded-md px-1.5 py-0.5 font-medium tabular-nums",
                                asset.open_findings === 0
                                  ? "text-muted-foreground/60"
                                  : "bg-muted text-foreground ring-1 ring-border",
                              )}
                            >
                              {asset.open_findings}
                            </span>
                          </TableCell>
                          <TableCell
                            className="text-right text-muted-foreground tabular-nums"
                            title={formatDate(asset.last_seen_at)}
                          >
                            {formatRelative(asset.last_seen_at)}
                          </TableCell>
                        </TableRow>
                      ))}
                    </Fragment>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-xs text-muted-foreground">
              {page * PAGE_SIZE + 1}–{page * PAGE_SIZE + assets.length} of {total} asset
              {total === 1 ? "" : "s"}
              {/* Said here rather than left to be inferred from the table. This
                  list used to show only the types the connector models and
                  silently omit the rest, so a subscription full of App Services
                  looked like a tidy inventory of storage and virtual machines --
                  an absence that read as coverage. The number is CloudGuard
                  reporting its own limits, which is the one thing a customer
                  cannot work out for themselves. */}
              {unchecked > 0 && (
                <>
                  {" · "}
                  <span className="text-medium">
                    {t.assets.unchecked.replace("{count}", String(unchecked))}
                  </span>
                </>
              )}
            </p>
            <Pager
              page={page}
              pages={pages}
              onPage={setPage}
              className="w-auto"
            />
          </div>
        </>
      )}
    </div>
  );
}

function OnRouteMark() {
  const Route = RISK_KIND_ICONS.ATTACK_PATH;
  return (
    <span
      title="On an attack path"
      className="inline-flex shrink-0 items-center gap-1 rounded-md border border-foreground/30 px-1 py-px text-[11px] font-medium text-foreground"
    >
      <Route className="size-3" aria-hidden />
      <span className="sr-only">On an attack path</span>
      <span aria-hidden>Path</span>
    </span>
  );
}

/**
 * Said, when the list's filters are set and the map is open. The map draws
 * every asset in the scope it has opened -- it is the estate's shape, and a
 * shape with holes cut by a search would be a wrong one -- so the filters stay
 * in the URL for the list and do nothing here. Unsaid, a map that ignored a
 * visible filter would read as a map that had applied it.
 */
function MapIgnoresFilters({
  active,
  onClear,
}: {
  active: string[];
  onClear: () => void;
}) {
  if (active.length === 0) return null;
  return (
    <p className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
      The map shows everything in the scope it has open. Your list filters ({active.join(", ")})
      apply to the list only.
      <Button variant="ghost" size="sm" onClick={onClear}>
        Clear them
      </Button>
    </p>
  );
}
