import { SearchIcon, SlidersHorizontalIcon, XIcon } from "lucide-react";

import { useT } from "@/i18n";
import { SelectField } from "@/components/common/SelectField";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { cn } from "@/lib/format";
import { FACET_PARAMS, hasFacets, type RouteFacets } from "./routeFacets";
import { DEFAULT_SORT, ROUTE_SORTS, type RouteSort } from "./routeOrder";

const ANY = "any";

/**
 * Search, sort and facets, over the drawing (DECISIONS.md §253, §259).
 *
 * They sat in the panel, which then held three jobs: narrowing, reading a
 * route and simulating. Here they narrow the list and the drawing together --
 * what does not match fades on the canvas rather than leaving it -- and every
 * one is in the URL, so "Copy investigation link" hands over exactly this.
 * Each facet in use is also a chip on the bar, which takes it off.
 */
export function RouteQueryBar({
  query,
  onQuery,
  sort,
  onSort,
  facets,
  onFacet,
  onClear,
  className,
}: {
  query: string;
  onQuery: (query: string) => void;
  sort: RouteSort;
  onSort: (sort: RouteSort) => void;
  facets: RouteFacets;
  /** Set one facet's URL parameter, or clear it with null. */
  onFacet: (param: string, value: string | null) => void;
  onClear: () => void;
  className?: string;
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
  const active = activeFacets(facets);

  const fields: Facet[] = [
    {
      param: FACET_PARAMS.reaches,
      label: t.attackPaths.facetReaches,
      value: facets.reaches,
      options: [
        { value: ANY, label: t.attackPaths.facetReachesAny },
        { value: "HIGH", label: t.attackPaths.facetReachesHigh },
        { value: "CRITICAL", label: t.attackPaths.facetReachesCritical },
      ],
    },
    {
      param: FACET_PARAMS.wayIn,
      label: t.attackPaths.facetWayIn,
      value: facets.wayIn,
      options: [
        { value: ANY, label: t.attackPaths.facetWayInAny },
        { value: "internet", label: t.attackPaths.facetWayInInternet },
        { value: "identity", label: t.attackPaths.facetWayInIdentity },
      ],
    },
    {
      param: FACET_PARAMS.link,
      label: t.attackPaths.facetLink,
      value: facets.link,
      options: [
        { value: ANY, label: t.attackPaths.facetLinkAny },
        { value: "role", label: t.attackPaths.facetLinkRole },
        { value: "network", label: t.attackPaths.facetLinkNetwork },
        { value: "identity", label: t.attackPaths.facetLinkIdentity },
      ],
    },
    {
      param: FACET_PARAMS.tracked,
      label: t.attackPaths.facetTracked,
      value: facets.tracked,
      options: [
        { value: ANY, label: t.attackPaths.facetTrackedAny },
        { value: "yes", label: t.attackPaths.facetTrackedYes },
        { value: "no", label: t.attackPaths.facetTrackedNo },
      ],
    },
    {
      param: FACET_PARAMS.maxHops,
      label: t.attackPaths.facetHops,
      value: facets.maxHops === null ? null : String(facets.maxHops),
      options: [
        { value: ANY, label: t.attackPaths.facetHopsAny },
        ...[2, 3, 4].map((n) => ({ value: String(n), label: t.attackPaths.facetHopsAtMost(n) })),
      ],
    },
  ];
  // Each facet in use, said as a chip on the bar that takes it off (§259):
  // what narrows the drawing stays in sight, not behind the Filters menu.
  const chips = fields.flatMap((field) => {
    const option = field.options.find((each) => each.value === field.value);
    return field.value !== null && option
      ? [{ param: field.param, label: `${field.label}: ${option.label}` }]
      : [];
  });

  return (
    <div
      role="search"
      aria-label={t.attackPaths.queryLabel}
      className={cn("flex flex-wrap items-center gap-1.5", className)}
    >
      <div className="relative min-w-40 flex-1 sm:max-w-64">
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
          className="h-8 rounded-lg border-transparent bg-foreground/6 pl-8 text-xs md:text-xs"
        />
      </div>
      {chips.map((chip) => (
        <span
          key={chip.param}
          className="flex h-7 items-center gap-0.5 rounded-full bg-primary-soft pr-0.5 pl-2.5 text-caption font-medium text-primary"
        >
          {chip.label}
          <button
            type="button"
            aria-label={t.attackPaths.facetRemove(chip.label)}
            onClick={() => onFacet(chip.param, null)}
            className="flex size-6 items-center justify-center rounded-full hover:bg-primary/15 focus-ring"
          >
            <XIcon className="size-3" aria-hidden />
          </button>
        </span>
      ))}
      {/* The five facets behind one control, so the drawing keeps the room
          (§259); the count on it says how many narrow the routes now. */}
      <Popover>
        <PopoverTrigger
          render={
            <Button variant={active > 0 ? "secondary" : "ghost"} size="sm">
              <SlidersHorizontalIcon data-icon="inline-start" />
              {t.attackPaths.facetsLabel}
              {active > 0 && (
                <span className="rounded-sm bg-primary px-1 text-caption text-primary-foreground tabular-nums">
                  {active}
                </span>
              )}
            </Button>
          }
        />
        <PopoverContent align="start" className="w-64" aria-label={t.attackPaths.facetsLabel}>
          <div className="flex flex-col gap-3">
            {fields.map((field) => (
              <div key={field.param} className="flex flex-col gap-1.5">
                <span aria-hidden className="text-meta font-medium text-muted-foreground">
                  {field.label}
                </span>
                <SelectField
                  value={field.value ?? ANY}
                  onValueChange={set(field.param)}
                  ariaLabel={field.label}
                  idleValue={ANY}
                  className="w-full"
                  options={field.options}
                />
              </div>
            ))}
          </div>
        </PopoverContent>
      </Popover>
      <SelectField
        value={sort}
        onValueChange={(value) => onSort(value as RouteSort)}
        options={ROUTE_SORTS.map((value) => ({ value, label: sorts[value] }))}
        ariaLabel={t.attackPaths.sortLabel}
        idleValue={DEFAULT_SORT}
        className="w-36"
      />
      {(hasFacets(facets) || query.trim() !== "") && (
        <Button variant="ghost" size="sm" onClick={onClear}>
          <XIcon data-icon="inline-start" />
          {t.attackPaths.facetClear}
        </Button>
      )}
    </div>
  );
}

/** One facet: its URL parameter, its name, its value now and what it can be. */
interface Facet {
  param: string;
  label: string;
  value: string | null;
  options: { value: string; label: string }[];
}

/** How many facets narrow the routes now. */
function activeFacets(facets: RouteFacets): number {
  return Object.values(facets).filter((value) => value !== null).length;
}
