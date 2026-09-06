import { useEffect, useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { LayersIcon, RadarIcon, SearchIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { Risk } from "@/lib/types";
import { useT } from "@/i18n";
import { HelpPopover } from "@/components/common/HelpPopover";
import { RiskDetailBody } from "@/components/risks/RiskDetailBody";
import { RiskTable } from "@/components/risks/RiskTable";
import { Card, CardContent } from "@/components/ui/card";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SelectField } from "@/components/common/SelectField";
import { cn } from "@/lib/format";

const PAGE_SIZE = 25;
const SEARCH_DEBOUNCE_MS = 250;

/**
 * What the findings mean, ranked.
 *
 * This page had the same silent truncation the findings list had: it asked for
 * risks with no `limit`, took the API's default hundred and rendered them as
 * the whole set. On a page whose entire claim is "these are your worst
 * problems, in order", showing the first hundred of four hundred is not a
 * display bug -- it is the wrong answer to the only question being asked.
 *
 * It also had no filters at all, on a list that mixes two kinds of thing and
 * four levels. Everything offered here is filtered by the database, so a filter
 * narrows the estate rather than the page.
 */
export function RisksPage() {
  const t = useT();
  const navigate = useNavigate();
  // The deep link still works, and now opens the ranking with that risk read
  // beside it rather than a page with no ranking on it: what a risk outranks
  // is half of what the score means.
  const { riskId } = useParams();
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [level, setLevel] = useState("all");
  const [status, setStatus] = useState("all");
  const [kind, setKind] = useState("all");
  const [page, setPage] = useState(0);
  // On by default: three rows reading the same sentence is the state this page
  // was actually in, and the reader has one mistake to fix, not three.
  const [grouped, setGrouped] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(0);
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [search]);

  const params = new URLSearchParams();
  if (debouncedSearch.trim()) params.set("search", debouncedSearch.trim());
  if (level !== "all") params.set("risk_level", level);
  if (status !== "all") params.set("status", status);
  if (kind !== "all") params.set("kind", kind);
  params.set("limit", String(PAGE_SIZE));
  params.set("offset", String(page * PAGE_SIZE));

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["risks", debouncedSearch, level, status, kind, page],
    queryFn: () =>
      api.get<Risk[]>(`/api/v1/risks?${params.toString()}`).then((r) => ({
        risks: r.data,
        total:
          (r.meta as { total?: number } | undefined)?.total ?? r.data.length,
      })),
    placeholderData: keepPreviousData,
  });

  const risks = data?.risks ?? [];
  const total = data?.total ?? 0;
  const pages = Math.ceil(total / PAGE_SIZE);
  const filtering =
    search.trim().length > 0 ||
    level !== "all" ||
    status !== "all" ||
    kind !== "all";

  function refilter(apply: () => void) {
    apply();
    setPage(0);
  }

  function clearFilters() {
    setSearch("");
    setLevel("all");
    setStatus("all");
    setKind("all");
    setPage(0);
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={
          <>
            {t.risks.title}
            <HelpPopover label="What a risk is">
              A finding is what CloudGuard observed. A risk is what that finding
              means on this asset — with this data on it, at this level of
              exposure, at this business criticality. The score is the product
              of those, not a count of alerts.
            </HelpPopover>
          </>
        }
        description={
          <>
            <span className="font-mono">{total}</span> open risk
            {total === 1 ? "" : "s"}
            {filtering && " matching these filters"}
          </>
        }
      />

      <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
        <div className="relative flex-1 lg:max-w-xs">
          <SearchIcon
            className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search risks"
            aria-label="Search risks"
            className="pl-8"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <SelectField
            value={level}
            onValueChange={(value) => refilter(() => setLevel(value || "all"))}
            ariaLabel="Filter by risk level"
            className="w-[150px]"
            options={[
              { value: "all", label: "All levels" },
              { value: "CRITICAL", label: "Critical" },
              { value: "HIGH", label: "High" },
              { value: "MEDIUM", label: "Medium" },
              { value: "LOW", label: "Low" },
              // UNKNOWN is a level the risk engine really assigns, and leaving
              // it out of the filter would hide the risks CloudGuard could not
              // score — the ones most worth looking at.
              { value: "UNKNOWN", label: "Unknown" },
            ]}
          />

          <SelectField
            value={status}
            onValueChange={(value) => refilter(() => setStatus(value || "all"))}
            ariaLabel="Filter by status"
            className="w-[160px]"
            options={[
              { value: "all", label: "All statuses" },
              { value: "OPEN", label: "Open" },
              { value: "IN_PROGRESS", label: "In progress" },
              { value: "ACCEPTED", label: "Accepted" },
              { value: "RESOLVED", label: "Resolved" },
            ]}
          />

          <SelectField
            value={kind}
            onValueChange={(value) => refilter(() => setKind(value || "all"))}
            ariaLabel="Filter by kind"
            className="w-[150px]"
            options={[
              { value: "all", label: "Findings and routes" },
              { value: "FINDING", label: "Findings only" },
              { value: "ATTACK_PATH", label: "Attack paths" },
              { value: "ESCALATION", label: "Escalations" },
            ]}
          />

          {/* Not a filter: nothing is hidden either way. It decides whether
              one mistake on three assets reads as one row or as three. */}
          <Button
            variant={grouped ? "secondary" : "outline"}
            size="sm"
            aria-pressed={grouped}
            onClick={() => setGrouped((on) => !on)}
          >
            <LayersIcon data-icon="inline-start" />
            {t.risks.groupDuplicates}
          </Button>
        </div>
      </div>

      {isLoading && <CardsSkeleton />}

      {error && (
        <ErrorState
          title="Could not load your risks"
          detail="CloudGuard could not reach its own API."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      {data && risks.length === 0 && (
        <EmptyState
          icon={RadarIcon}
          title={filtering ? "No risks match these filters" : t.risks.empty}
          detail={
            filtering
              ? "Widen the filters, or clear the search, to see the rest of the ranking."
              : undefined
          }
          action={
            filtering ? (
              <Button variant="outline" onClick={clearFilters}>
                Clear filters
              </Button>
            ) : undefined
          }
        />
      )}

      {data && risks.length > 0 && (
        <div className="flex gap-4">
          {/* Below `lg` there is no room for two columns, so the drawer is the
              page: the same component, so the narrow reading cannot drift from
              the wide one. */}
          <div
            className={cn(
              "flex min-w-0 flex-1 flex-col gap-3",
              riskId && "hidden lg:flex",
            )}
          >
            <Card>
              <CardContent className="px-0">
                {/* Both kinds in one table, deliberately. A route outranking
                    the findings inside it is only visible where they are
                    ranked together — on a page of its own it would be a second
                    opinion nobody compares. The kind filter can separate them;
                    the default does not. */}
                <RiskTable
                  risks={risks}
                  grouped={grouped}
                  selectedId={riskId}
                  onSelect={(risk) => navigate(`/risks/${risk.id}`)}
                />
              </CardContent>
            </Card>

            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="text-xs text-muted-foreground">
                <span className="font-mono">
                  {page * PAGE_SIZE + 1}–{page * PAGE_SIZE + risks.length} of{" "}
                  {total}
                </span>{" "}
                risk{total === 1 ? "" : "s"}
                {filtering ? " matching these filters" : ""}
              </p>
              {pages > 1 && (
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page === 0}
                    onClick={() => setPage((p) => Math.max(0, p - 1))}
                  >
                    Previous
                  </Button>
                  <span className="font-mono text-xs text-muted-foreground">
                    {page + 1} / {pages}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page + 1 >= pages}
                    onClick={() => setPage((p) => p + 1)}
                  >
                    Next
                  </Button>
                </div>
              )}
            </div>
          </div>

          {riskId && (
            <aside
              aria-label="Risk detail"
              className="min-w-0 flex-1 lg:w-[372px] lg:shrink-0 lg:flex-none"
            >
              <Card className="lg:sticky lg:top-[74px]">
                <CardContent>
                  <RiskDetailBody
                    key={riskId}
                    riskId={riskId}
                    onClose={() => navigate("/risks")}
                  />
                </CardContent>
              </Card>
            </aside>
          )}
        </div>
      )}
    </div>
  );
}
