import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ArchiveIcon, ListChecksIcon, SearchIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { Rule } from "@/lib/types";
import { useT } from "@/i18n";
import { RuleDetail } from "@/components/rules/RuleDetail";
import { RuleTable } from "@/components/rules/RuleTable";
import { HelpPopover } from "@/components/common/HelpPopover";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { SelectField } from "@/components/common/SelectField";
import { cn } from "@/lib/format";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

/**
 * Every check CloudGuard runs.
 *
 * Filtered in the browser, and that is not the compromise it would be
 * elsewhere: the catalogue is the product's own rulebook, it arrives whole in
 * one request, and it is dozens of entries rather than an estate's worth. There
 * is nothing here that a search could fail to see.
 */
export function RulesPage() {
  const t = useT();
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [showWithdrawn, setShowWithdrawn] = useState(false);
  // Local rather than in the URL: a rule has no route of its own, and the
  // catalogue is the one page in the product where a deep link to a row would
  // be a link to CloudGuard's own rulebook rather than to this estate.
  const [selected, setSelected] = useState<Rule | null>(null);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["rules"],
    queryFn: () => api.get<Rule[]>("/api/v1/rules").then((r) => r.data),
  });

  // Counted over everything the API returned, not over the filtered list: the
  // toggle has to say how many rules it would reveal, which is a fact about
  // the catalogue rather than about the current search.
  const withdrawnCount = useMemo(
    () => (data ?? []).filter((rule) => !rule.enabled).length,
    [data],
  );

  const rules = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return (data ?? []).filter((rule) => {
      // A withdrawn rule no longer runs. Listing it beside the live ones under
      // a heading that says "every check CloudGuard runs" overstated what is
      // being checked, so it is out unless asked for.
      if (!rule.enabled && !showWithdrawn) return false;
      if (severity !== "all" && rule.severity !== severity) return false;
      if (!needle) return true;
      return `${rule.name} ${rule.rule_id} ${rule.description} ${rule.category}`
        .toLowerCase()
        .includes(needle);
    });
  }, [data, search, severity, showWithdrawn]);

  const live = (data ?? []).length - withdrawnCount;
  const filtering = search.trim().length > 0 || severity !== "all";

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={
          <>
            {t.rules.title}
            <HelpPopover label="How rules behave">
              Every check CloudGuard runs. Rules are deterministic — no network,
              no database, no model — so the same environment always produces
              the same result, and a rule that cannot reach its evidence returns
              UNKNOWN rather than a pass.
            </HelpPopover>
          </>
        }
        description={
          data ? (
            <>
              <span className="font-mono">{live}</span> check
              {live === 1 ? "" : "s"} in the registry
              {withdrawnCount > 0 && (
                <>
                  {" · "}
                  <span className="font-mono">{withdrawnCount}</span> withdrawn
                </>
              )}
            </>
          ) : undefined
        }
      />

      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1 sm:max-w-xs">
          <SearchIcon
            className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search rules"
            aria-label="Search rules"
            className="pl-8"
          />
        </div>
        <SelectField
          value={severity}
          onValueChange={(value) => setSeverity(value || "all")}
          ariaLabel="Filter by severity"
          className="w-[150px]"
          options={[
            { value: "all", label: "All severities" },
            ...SEVERITIES.map((value) => ({
              value,
              label: value.charAt(0) + value.slice(1).toLowerCase(),
            })),
          ]}
        />
        {/* Offered only when there is something to reveal. A permanent toggle
            on a catalogue with nothing withdrawn implies rules are missing. */}
        {withdrawnCount > 0 && (
          <Button
            variant="outline"
            size="sm"
            aria-pressed={showWithdrawn}
            onClick={() => setShowWithdrawn((v) => !v)}
          >
            <ArchiveIcon className="size-4" aria-hidden />
            {showWithdrawn ? t.rules.hideWithdrawn : t.rules.showWithdrawn}
            {!showWithdrawn && (
              <span className="font-mono">{` (${withdrawnCount})`}</span>
            )}
          </Button>
        )}
      </div>

      {isLoading && <CardsSkeleton />}

      {error && (
        <ErrorState
          title="Could not load the rule catalogue"
          detail="CloudGuard could not reach its own API."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      {data && rules.length === 0 && (
        <EmptyState
          icon={ListChecksIcon}
          title={filtering ? "No rules match" : t.rules.empty}
          detail={
            filtering
              ? "Widen the filters to see the rest of the catalogue."
              : undefined
          }
          action={
            filtering ? (
              <Button
                variant="outline"
                onClick={() => {
                  setSearch("");
                  setSeverity("all");
                }}
              >
                Clear filters
              </Button>
            ) : undefined
          }
        />
      )}

      {rules.length > 0 && (
        <>
          <div className="flex gap-4">
            <div
              className={cn(
                "flex min-w-0 flex-1 flex-col gap-3",
                selected && "hidden lg:flex",
              )}
            >
              <Card className="overflow-hidden py-0">
                <CardContent className="px-0">
                  <RuleTable
                    rules={rules}
                    selectedId={selected?.rule_id}
                    onSelect={setSelected}
                  />
                </CardContent>
              </Card>
            </div>

            {selected && (
              <aside
                aria-label="Rule detail"
                className="min-w-0 flex-1 lg:w-[372px] lg:shrink-0 lg:flex-none"
              >
                <Card className="lg:sticky lg:top-[74px]">
                  <CardContent>
                    <RuleDetail
                      rule={selected}
                      onClose={() => setSelected(null)}
                    />
                  </CardContent>
                </Card>
              </aside>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            <span className="font-mono">
              {rules.length} of {live}
            </span>{" "}
            rule{live === 1 ? "" : "s"} CloudGuard runs
            {withdrawnCount > 0 && (
              <>
                , and <span className="font-mono">{withdrawnCount}</span>{" "}
                {t.rules.withdrawnCount}
              </>
            )}
          </p>
        </>
      )}
    </div>
  );
}
