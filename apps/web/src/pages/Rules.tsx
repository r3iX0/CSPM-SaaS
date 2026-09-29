import { useMemo, useState } from "react";
import { useUrlFilters } from "@/lib/useUrlFilters";
import { useQuery } from "@tanstack/react-query";
import { ArchiveIcon, ChevronDownIcon, ListChecksIcon, SearchIcon } from "lucide-react";
import { api } from "@/lib/api";
import type { Rule } from "@/lib/types";
import { useT } from "@/i18n";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { LiveStatus } from "@/components/common/LiveStatus";
import { SelectField } from "@/components/common/SelectField";
import { RemediationPanel } from "@/components/security/RemediationPanel";
import { EngineBadge, ProwlerPanel } from "@/components/security/EnginePanel";
import { cn, formatEffort, resourceTypeLabel } from "@/lib/format";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

/**
 * A Prowler check the deployment is not running: the scanner service is not
 * switched on, so it is mirrored disabled (DECISIONS.md §150). Not withdrawn --
 * nothing about the check changed -- and not listed as a check Cleave runs.
 */
function dormant(rule: Rule): boolean {
  return rule.engine === "prowler" && !rule.enabled;
}

/**
 * Every check CloudGuard runs.
 *
 * Filtered in the browser, and that is not the compromise it would be
 * elsewhere: the catalogue is the product's own rulebook, it arrives whole in
 * one request, and it is several hundred entries rather than an estate's worth.
 * There is nothing here that a search could fail to see.
 */
export function RulesPage() {
  const t = useT();
  // In the URL so a filtered catalogue is a link. The search filters in the
  // browser -- the whole catalogue arrives in one request -- so writing it on
  // every key costs no request, and `replace` keeps it out of the history.
  const [filters, update] = useUrlFilters({
    q: "",
    severity: "all",
    withdrawn: "",
    engine: "all",
  });
  const search = filters.q;
  const severity = filters.severity;
  const engine = filters.engine;
  const showWithdrawn = filters.withdrawn === "1";
  const setSearch = (value: string) => update({ q: value || null });
  const setSeverity = (value: string) => update({ severity: value });
  const setEngine = (value: string) => update({ engine: value });
  const setShowWithdrawn = (next: (value: boolean) => boolean) =>
    update({ withdrawn: next(showWithdrawn) ? "1" : null });

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["rules"],
    queryFn: () => api.get<Rule[]>("/api/v1/rules").then((r) => r.data),
  });

  // Counted over everything the API returned, not over the filtered list: the
  // toggle has to say how many rules it would reveal, which is a fact about
  // the catalogue rather than about the current search.
  const withdrawnCount = useMemo(
    () => (data ?? []).filter((rule) => !rule.enabled && !dormant(rule)).length,
    [data],
  );
  const dormantCount = useMemo(() => (data ?? []).filter(dormant).length, [data]);
  const extendedLive = useMemo(
    () => (data ?? []).some((rule) => rule.engine === "prowler" && rule.enabled),
    [data],
  );

  const rules = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return (data ?? []).filter((rule) => {
      // A withdrawn rule no longer runs. Listing it beside the live ones under
      // a heading that says "every check CloudGuard runs" overstated what is
      // being checked, so it is out unless asked for.
      if (dormant(rule)) return false;
      if (!rule.enabled && !showWithdrawn) return false;
      if (severity !== "all" && rule.severity !== severity) return false;
      if (engine !== "all" && (rule.engine ?? "native") !== engine) return false;
      if (!needle) return true;
      return `${rule.name} ${rule.rule_id} ${rule.description} ${rule.category}`
        .toLowerCase()
        .includes(needle);
    });
  }, [data, search, severity, showWithdrawn, engine]);

  const live = (data ?? []).length - withdrawnCount - dormantCount;
  const filtering = search.trim().length > 0 || severity !== "all" || engine !== "all";
  const emptyTitle = filtering ? "No rules match" : t.rules.empty;
  const countLine = `${rules.length} of ${live} rule${live === 1 ? "" : "s"} Cleave runs`;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t.rules.title}
        description="Every check Cleave runs. Deterministic: the same environment always gives the same result."
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
            data-page-search
            className="h-8 pl-8 text-[12.5px]"
          />
        </div>
        <SelectField
          value={severity}
          onValueChange={(value) => setSeverity(value || "all")}
          ariaLabel="Filter by severity"
          className="w-[160px]"
          idleValue="all"
          options={[
            { value: "all", label: "All severities" },
            ...SEVERITIES.map((value) => ({
              value,
              label: value.charAt(0) + value.slice(1).toLowerCase(),
            })),
          ]}
        />
        {/* Two engines answer the catalogue (DECISIONS.md §150): Cleave's own
            rules, and the extended checks Prowler runs beside them. */}
        {extendedLive && (
          <SelectField
            value={engine}
            onValueChange={(value) => setEngine(value || "all")}
            ariaLabel="Filter by engine"
            className="w-[180px]"
            idleValue="all"
            options={[
              { value: "all", label: "Both engines" },
              { value: "native", label: "Cleave rules" },
              { value: "prowler", label: "Extended checks" },
            ]}
          />
        )}
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
            {!showWithdrawn && ` (${withdrawnCount})`}
          </Button>
        )}
      </div>

      {isLoading && <CardsSkeleton />}

      {error && (
        <ErrorState
          title="Could not load the rule catalogue"
          detail="Cleave could not reach its own API."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      <LiveStatus quietFirst message={!data ? null : rules.length > 0 ? countLine : emptyTitle} />

      {data && rules.length === 0 && (
        <EmptyState
          icon={ListChecksIcon}
          title={emptyTitle}
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
                  update({ q: null, severity: null, engine: null });
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
          {/* A catalogue, so a list: a hundred-odd rules as separate cards
              was a page to scroll, not to scan. */}
          <div className="divide-y divide-border overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10">
            {rules.map((rule) => (
              <RuleCard key={rule.rule_id} rule={rule} />
            ))}
          </div>
          <p className="text-xs text-muted-foreground">
            {countLine}
            {withdrawnCount > 0 && `, and ${withdrawnCount} ${t.rules.withdrawnCount}`}
          </p>
          {dormantCount > 0 && (
            <p className="text-xs text-muted-foreground">
              {dormantCount} extended checks are catalogued and not running: this deployment has
              not switched the scanner service on.
            </p>
          )}
        </>
      )}
    </div>
  );
}

function RuleCard({ rule }: { rule: Rule }) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const frameworks = Object.entries(rule.compliance_mappings);

  return (
    <div className={cn(!rule.enabled && "bg-unknown-bg/40")}>
      <div className="flex flex-wrap items-start gap-x-4 gap-y-2 px-5 py-3">
        <span className="w-[4.5rem] shrink-0 pt-0.5">
          <SeverityBadge level={rule.severity} />
        </span>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-[13.5px] font-medium text-foreground">{rule.name}</p>
            {/* A tenant-wide rule is about the directory rather than any one
                resource, which is why nothing in the asset list carries it. */}
            {rule.scope === "aggregate" && <Badge variant="secondary">Tenant-wide</Badge>}
            <EngineBadge engine={rule.engine} version={rule.engine_version} />
            {/* Dashed and named rather than greyed. A rule that has stopped
                running is not a quieter rule -- it is one whose severity
                describes what it used to check. */}
            {!rule.enabled && (
              <span className="inline-flex items-center rounded-full border border-dashed border-unknown-border bg-unknown-bg px-2 py-px text-[11px] font-medium text-unknown">
                {t.rules.withdrawn}
              </span>
            )}
          </div>
          <p className="mt-0.5 line-clamp-1 text-[12.5px] text-muted-foreground">{rule.description}</p>
          <p className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11.5px] text-muted-foreground">
            <code className="font-mono text-[11px]">
              {rule.rule_id} · v{rule.version}
            </code>
            {rule.applies_to.length > 0 && (
              <span>
                Applies to{" "}
                <span className="text-foreground">
                  {rule.applies_to.map(resourceTypeLabel).join(", ")}
                </span>
              </span>
            )}
            {frameworks.map(([framework, controls]) => (
              <span key={framework}>
                {framework.replace(/_/g, " ")}{" "}
                <span className="text-foreground">{controls.join(", ")}</span>
              </span>
            ))}
          </p>
        </div>

        <div className="flex shrink-0 items-center gap-4">
          <div className="hidden text-right text-xs text-muted-foreground tabular-nums md:block">
            <p>{formatEffort(rule.estimated_effort_minutes)} to fix</p>
            <p className="mt-0.5">Exploitability {rule.exploitability}/5</p>
          </div>
          {/* Everything the catalogue held and never showed. Behind a toggle
              rather than always open: a page of rules each carrying its
              rationale and four fix formats is a document, not a list. */}
          <Button
            variant="ghost"
            size="sm"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? t.rules.hideDetail : t.rules.showDetail}
            <ChevronDownIcon
              data-icon="inline-end"
              aria-hidden
              className={cn("transition-transform", open && "rotate-180")}
            />
          </Button>
        </div>
      </div>

      {!rule.enabled && (
        <p className="mx-5 mb-3 rounded-lg border border-dashed border-unknown-border bg-unknown-bg px-3 py-2 text-xs leading-relaxed text-foreground">
          {t.rules.withdrawnHelp}
        </p>
      )}

      {open && (
        <div className="flex flex-col gap-4 border-t border-border bg-muted/40 px-5 py-4 sm:pl-[6.75rem]">
          {rule.rationale && (
            <div>
              <p className="text-xs font-medium text-muted-foreground">{t.rules.why}</p>
              <p className="mt-1 max-w-3xl text-sm leading-relaxed text-foreground">
                {rule.rationale}
              </p>
            </div>
          )}
          <RemediationPanel
            remediation={rule.remediation}
            spec={rule.remediation_spec}
            effortMinutes={rule.estimated_effort_minutes}
          />
          <ProwlerPanel detail={rule.prowler} />
        </div>
      )}
    </div>
  );
}
