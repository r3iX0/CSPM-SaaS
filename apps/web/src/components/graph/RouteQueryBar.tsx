import { SearchIcon, XIcon } from "lucide-react";

import { useT } from "@/i18n";
import { CopyButton } from "@/components/common/CopyButton";
import { SelectField } from "@/components/common/SelectField";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { FACET_PARAMS, hasFacets, type RouteFacets } from "./routeFacets";
import { DEFAULT_SORT, ROUTE_SORTS, type RouteSort } from "./routeOrder";

const ANY = "any";

/**
 * Search, sort and facets, above the drawing (DECISIONS.md §253).
 *
 * They sat in the panel, which then held three jobs: narrowing, reading a
 * route and simulating. Here they narrow the list and the drawing together --
 * what does not match fades on the canvas rather than leaving it -- and every
 * one is in the URL, so "Copy investigation link" hands over exactly this.
 */
export function RouteQueryBar({
  query,
  onQuery,
  sort,
  onSort,
  facets,
  onFacet,
  onClear,
}: {
  query: string;
  onQuery: (query: string) => void;
  sort: RouteSort;
  onSort: (sort: RouteSort) => void;
  facets: RouteFacets;
  /** Set one facet's URL parameter, or clear it with null. */
  onFacet: (param: string, value: string | null) => void;
  onClear: () => void;
}) {
  const t = useT();
  const sorts: Record<RouteSort, string> = {
    worst: t.attackPaths.sortWorst,
    hops: t.attackPaths.sortHops,
    sensitive: t.attackPaths.sortSensitive,
    exposed: t.attackPaths.sortExposed,
    tracked: t.attackPaths.sortTracked,
  };
  const set = (param: string) => (value: string) => onFacet(param, value === ANY ? null : value);

  return (
    <div
      role="search"
      aria-label={t.attackPaths.queryLabel}
      className="flex flex-wrap items-center gap-2"
    >
      <div className="relative min-w-48 flex-1">
        <SearchIcon
          className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden
        />
        <Input
          type="search"
          value={query}
          onChange={(event) => onQuery(event.target.value)}
          placeholder={t.attackPaths.searchPlaceholder}
          aria-label={t.attackPaths.searchLabel}
          data-page-search
          className="h-8 pl-8 text-xs md:text-xs"
        />
      </div>
      <SelectField
        value={facets.reaches ?? ANY}
        onValueChange={set(FACET_PARAMS.reaches)}
        ariaLabel={t.attackPaths.facetReaches}
        idleValue={ANY}
        className="w-36"
        options={[
          { value: ANY, label: t.attackPaths.facetReachesAny },
          { value: "HIGH", label: t.attackPaths.facetReachesHigh },
          { value: "CRITICAL", label: t.attackPaths.facetReachesCritical },
        ]}
      />
      <SelectField
        value={facets.wayIn ?? ANY}
        onValueChange={set(FACET_PARAMS.wayIn)}
        ariaLabel={t.attackPaths.facetWayIn}
        idleValue={ANY}
        className="w-36"
        options={[
          { value: ANY, label: t.attackPaths.facetWayInAny },
          { value: "internet", label: t.attackPaths.facetWayInInternet },
          { value: "identity", label: t.attackPaths.facetWayInIdentity },
        ]}
      />
      <SelectField
        value={facets.link ?? ANY}
        onValueChange={set(FACET_PARAMS.link)}
        ariaLabel={t.attackPaths.facetLink}
        idleValue={ANY}
        className="w-36"
        options={[
          { value: ANY, label: t.attackPaths.facetLinkAny },
          { value: "role", label: t.attackPaths.facetLinkRole },
          { value: "network", label: t.attackPaths.facetLinkNetwork },
          { value: "identity", label: t.attackPaths.facetLinkIdentity },
        ]}
      />
      <SelectField
        value={facets.tracked ?? ANY}
        onValueChange={set(FACET_PARAMS.tracked)}
        ariaLabel={t.attackPaths.facetTracked}
        idleValue={ANY}
        className="w-32"
        options={[
          { value: ANY, label: t.attackPaths.facetTrackedAny },
          { value: "yes", label: t.attackPaths.facetTrackedYes },
          { value: "no", label: t.attackPaths.facetTrackedNo },
        ]}
      />
      <SelectField
        value={facets.maxHops === null ? ANY : String(facets.maxHops)}
        onValueChange={set(FACET_PARAMS.maxHops)}
        ariaLabel={t.attackPaths.facetHops}
        idleValue={ANY}
        className="w-32"
        options={[
          { value: ANY, label: t.attackPaths.facetHopsAny },
          ...[2, 3, 4].map((n) => ({ value: String(n), label: t.attackPaths.facetHopsAtMost(n) })),
        ]}
      />
      <SelectField
        value={sort}
        onValueChange={(value) => onSort(value as RouteSort)}
        options={ROUTE_SORTS.map((value) => ({ value, label: sorts[value] }))}
        ariaLabel={t.attackPaths.sortLabel}
        idleValue={DEFAULT_SORT}
        className="w-40"
      />
      {(hasFacets(facets) || query.trim() !== "") && (
        <Button variant="ghost" size="sm" onClick={onClear}>
          <XIcon data-icon="inline-start" />
          {t.attackPaths.facetClear}
        </Button>
      )}
      <CopyButton
        variant="ghost"
        label={t.attackPaths.copyInvestigation}
        text={window.location.href}
      />
    </div>
  );
}
