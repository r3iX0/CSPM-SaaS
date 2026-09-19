import { createElement, useEffect, useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { motion } from "motion/react";
import { Link } from "react-router-dom";
import { ChevronRightIcon, RadarIcon, ScissorsIcon, SearchIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { ChokePoint, Risk } from "@/lib/types";
import { useT } from "@/i18n";
import { StatusPill } from "@/components/security/StatusPill";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { ScoreTile } from "@/components/security/ScoreTile";
import { Badge } from "@/components/ui/badge";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SelectField } from "@/components/common/SelectField";
import { SegmentedFilter } from "@/components/common/SegmentedFilter";
import { listContainer, listItem } from "@/lib/motion";
import { FACTOR_ICONS, RISK_KIND_ICONS } from "@/lib/icons";
import { IconLabel } from "@/components/security/IconLabel";
import type { LucideIcon } from "lucide-react";
import { Pager } from "@/components/common/Pager";
import { useUrlFilters } from "@/lib/useUrlFilters";
import { dialogOpen, isTypingTarget, plainKey, useRowNavigation } from "@/lib/keyboard";
import { useIsDemo } from "@/lib/useDemo";
import { formatDate } from "@/lib/format";
import { Checkbox } from "@/components/ui/checkbox";
import { RiskTriageBar } from "@/components/security/RiskTriage";

const PAGE_SIZE = 25;
const SEARCH_DEBOUNCE_MS = 250;

/**
 * The triage queue: what the findings mean, ranked, and what to do about each.
 *
 * Findings, routes and escalations used to be read on three pages and decided
 * about on one of them. This list already ranked all three together; it now
 * decides about them too -- select rows, then mark them in progress, accept or
 * reopen them (DECISIONS.md §103). The findings list stays, as the evidence a
 * risk is built from, and leaves the navigation.
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
  // Filters in the URL, so a filtered ranking is a link -- and so the
  // dashboard's risk-band bars, which link to `?level=CRITICAL`, land on the
  // band they name instead of on the whole list.
  const [filters, update] = useUrlFilters({
    q: "",
    level: "all",
    status: "all",
    kind: "all",
    page: "0",
  });
  const { level, status, kind } = filters;
  const debouncedSearch = filters.q;
  const page = Math.max(0, Number.parseInt(filters.page, 10) || 0);

  const [search, setSearch] = useState(filters.q);
  useEffect(() => {
    const timer = setTimeout(() => {
      if (search.trim() !== debouncedSearch) update({ q: search.trim() || null, page: null });
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [search, debouncedSearch, update]);

  function setPage(next: number) {
    update({ page: String(next) });
  }

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
  const activeRow = useRowNavigation(risks.map((risk) => `/risks/${risk.id}`));
  const isDemo = useIsDemo();

  // Ids rather than rows, so a refetch after a decision shows each selected
  // risk's new status. Only the rows on screen count: a selection is what the
  // reader can see, and a page turn must not carry off rows they cannot.
  const [selectedIds, setSelectedIds] = useState<ReadonlySet<string>>(new Set());
  const selected = risks.filter((risk) => selectedIds.has(risk.id));
  function toggle(id: string) {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  // `x` selects the row `j`/`k` has marked -- the pair that makes the queue
  // workable without a pointer. Not in the demo, where nothing can be decided.
  useEffect(() => {
    if (isDemo) return;
    function onKeyDown(event: KeyboardEvent) {
      if (!plainKey(event) || isTypingTarget(event.target) || dialogOpen()) return;
      const row = data?.risks[activeRow];
      if (event.key !== "x" || !row) return;
      event.preventDefault();
      toggle(row.id);
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [activeRow, data, isDemo]);

  // What to cut, above what to read -- only on the unfiltered first page, and
  // only once the list holds a route, since the answer costs a re-traversal per
  // candidate on the server.
  const hasRoutes = risks.some((risk) => risk.kind !== "FINDING");
  const total = data?.total ?? 0;
  const pages = Math.ceil(total / PAGE_SIZE);
  const filtering =
    search.trim().length > 0 ||
    level !== "all" ||
    status !== "all" ||
    kind !== "all";

  /** A filter change re-slices the set, so the page resets with it. */
  function refilter(patch: Partial<Record<keyof typeof filters, string | null>>) {
    update({ ...patch, page: null });
  }

  const chokes = useQuery({
    queryKey: ["attack-paths", "choke-points"],
    enabled: hasRoutes && page === 0 && !filtering,
    queryFn: () =>
      api.get<ChokePoint[]>("/api/v1/attack-paths/choke-points").then((r) => r.data),
  });

  function clearFilters() {
    setSearch("");
    refilter({ q: null, level: null, status: null, kind: null });
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        icon={RadarIcon}
        title={t.risks.title}
        description="Everything worth deciding about — findings, attack paths and escalations — worst first. Select rows to mark them in progress, accept them or reopen them."
      />

      {chokes.data && chokes.data.length > 0 && <TopFixes chokes={chokes.data} />}

      {/* The kind is the view -- one list, or one slice of it -- so every
          kind is named on screen, as the findings page names its statuses.
          Level, status and search refine whichever view is showing. */}
      <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
        <SegmentedFilter
          label="Filter by kind"
          value={kind}
          onChange={(value) => refilter({ kind: value })}
          segments={[
            { value: "all", label: "All risks" },
            { value: "FINDING", label: "Findings" },
            { value: "ATTACK_PATH", label: "Attack paths" },
            { value: "ESCALATION", label: "Escalations" },
          ]}
        />

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative w-full sm:w-64">
            <SearchIcon
              className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden
            />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search risks"
              aria-label="Search risks"
              data-page-search
              className="pl-8"
            />
          </div>

          {/* A select like every other filter in the product, and the same
              control the findings list filters severity with. */}
          <SelectField
            value={level}
            onValueChange={(value) => refilter({ level: value || "all" })}
            ariaLabel="Filter by risk level"
            className="w-[150px]"
            idleValue="all"
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
            onValueChange={(value) => refilter({ status: value || "all" })}
            ariaLabel="Filter by status"
            className="w-[160px]"
            idleValue="all"
            options={[
              { value: "all", label: "All statuses" },
              // OPEN is the queue's own view: nobody has decided about these.
              { value: "OPEN", label: "Needs triage" },
              { value: "IN_PROGRESS", label: "In progress" },
              { value: "ACCEPTED", label: "Accepted" },
              { value: "RESOLVED", label: "Resolved" },
            ]}
          />
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
        <>
          {!isDemo && (
            <RiskTriageBar selected={selected} onDone={() => setSelectedIds(new Set())} />
          )}
          {/* The ranking arrives a card at a time. Keyed by risk id, so a
              poll that returns the same ranking does not replay it -- only
              cards that are actually new animate, which keeps the movement a
              statement that something arrived. */}
          <motion.div
            className="flex flex-col gap-2.5"
            variants={listContainer}
            initial="initial"
            animate="animate"
          >
            {/* Both kinds in one list, deliberately. A route outranking the
                findings inside it is only visible where they are ranked
                together — on a page of its own it would be a second opinion
                nobody compares. The kind filter can separate them; the default
                does not. */}
            {risks.map((risk, index) => (
              <motion.div
                key={risk.id}
                variants={listItem}
                data-row-index={index}
                data-active={activeRow === index}
                className="rounded-xl data-[active=true]:ring-2 data-[active=true]:ring-foreground/60"
              >
                {risk.kind === "FINDING" ? (
                  <FindingRiskCard
                    risk={risk}
                    select={
                      isDemo ? undefined : (
                        <SelectRow
                          risk={risk}
                          checked={selectedIds.has(risk.id)}
                          onToggle={() => toggle(risk.id)}
                        />
                      )
                    }
                  />
                ) : (
                  <ScenarioCard
                    risk={risk}
                    select={
                      isDemo ? undefined : (
                        <SelectRow
                          risk={risk}
                          checked={selectedIds.has(risk.id)}
                          onToggle={() => toggle(risk.id)}
                        />
                      )
                    }
                  />
                )}
              </motion.div>
            ))}
          </motion.div>

          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-xs text-muted-foreground">
              {page * PAGE_SIZE + 1}–{page * PAGE_SIZE + risks.length} of{" "}
              {total} risk
              {total === 1 ? "" : "s"}
              {filtering ? " matching these filters" : ""}
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

/**
 * A route, scored as one thing.
 *
 * Rendered differently from a finding risk rather than as one with extra
 * fields, because the six weighted components do not apply: a scenario is
 * floored at its worst member and amplified for being short, and showing it
 * under "asset criticality / data sensitivity / exploitability" would invite
 * the reader to check numbers that were never used.
 *
 * Both scenario kinds render here, and the default is deliberately this way
 * round: anything that is not a finding risk was scored by the scenario
 * formula, so a new template added later shows honest arithmetic rather than
 * falling through to a card that would display components nobody computed.
 */
function ScenarioCard({ risk, select }: { risk: Risk; select?: React.ReactNode }) {
  const t = useT();
  const breakdown = risk.score_breakdown;
  const capped = (breakdown.uncapped ?? 0) > 100;
  const escalation = risk.kind === "ESCALATION";

  return (
    <RiskShell>
      <RiskHead
        risk={risk}
        select={select}
        badge={escalation ? t.risks.escalationBadge : t.risks.scenarioBadge}
        subtitle={escalation ? t.risks.escalationIntro : t.risks.scenarioIntro}
      />
      {risk.path.length > 0 && (
        <div className="border-t border-border px-4 py-3 sm:pl-20">
          <p className="text-xs font-medium text-muted-foreground">{t.risks.routeLabel}</p>
          <ol className="mt-2 flex flex-col gap-1.5">
            {risk.path.map((step, index) => (
              <li
                key={`${step.source_id}-${step.relationship}-${step.target_id}`}
                className="flex items-start gap-2.5 text-sm text-muted-foreground"
              >
                <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border bg-background text-[10px] font-medium text-muted-foreground">
                  {index + 1}
                </span>
                {step.description}
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* The arithmetic, in the terms the score was actually built from. A
          customer asking why this outranks the finding inside it gets the
          answer rather than a number. */}
      <RiskFooter>
        <span className="text-muted-foreground">
          {t.risks.worstMember}{" "}
          <strong className="text-foreground">
            {breakdown.worst_member ?? "—"}
          </strong>
        </span>
        <span className="text-muted-foreground">
          {t.risks.amplifier}{" "}
          <strong className="text-foreground">
            +{breakdown.amplifier ?? 0}
          </strong>
        </span>
        <span className="text-muted-foreground">
          Hops{" "}
          <strong className="text-foreground">
            {breakdown.hops ?? risk.path.length}
          </strong>
        </span>
        {capped && (
          <span className="text-muted-foreground">{t.risks.cappedNote}</span>
        )}
      </RiskFooter>
    </RiskShell>
  );
}

function FindingRiskCard({ risk, select }: { risk: Risk; select?: React.ReactNode }) {
  return (
    <RiskShell>
      <RiskHead risk={risk} select={select} subtitle={risk.description} />
      <RiskFooter>
        <Factor
          icon={FACTOR_ICONS.criticality}
          label="Asset criticality"
          value={<SeverityBadge level={risk.asset_criticality} size="sm" />}
        />
        <Factor
          icon={FACTOR_ICONS.dataSensitivity}
          label="Data sensitivity"
          value={<SeverityBadge level={risk.data_sensitivity} size="sm" />}
        />
        <Factor
          icon={FACTOR_ICONS.exposure}
          label="Internet exposure"
          value={<SeverityBadge level={risk.internet_exposure} size="sm" />}
        />
        <Factor
          icon={FACTOR_ICONS.exploitability}
          label="Exploitability"
          value={<strong className="text-foreground">{risk.exploitability}/5</strong>}
        />
        <Factor
          icon={FACTOR_ICONS.businessImpact}
          label="Business impact"
          value={<strong className="text-foreground">{risk.business_impact}</strong>}
        />
      </RiskFooter>
    </RiskShell>
  );
}

/**
 * The frame every ranked risk shares.
 *
 * The lift on hover is one border step -- enough that a pointer moving down
 * the ranking can tell which row it is over, and not so much that a page of
 * them looks like it is breathing.
 */
function RiskShell({ children }: { children: React.ReactNode }) {
  return (
    <article className="group relative overflow-hidden rounded-xl border border-border bg-card transition-colors hover:border-foreground/20">
      {children}
    </article>
  );
}

/**
 * Score first, then what it is. The number is what ranks the list, so it
 * leads the row as a tile tinted by its level rather than trailing it in
 * grey at the far edge, where it used to sit a screen-width from its title.
 */
function RiskHead({
  risk,
  select,
  badge,
  subtitle,
}: {
  risk: Risk;
  select?: React.ReactNode;
  badge?: string;
  subtitle: string;
}) {
  const findings = risk.finding_count ?? 0;
  const routes = risk.route_count ?? 0;
  return (
    <div className="flex items-start gap-4 p-4">
      {select}
      <ScoreTile score={Number(risk.risk_score)} level={risk.risk_level} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge level={risk.risk_level} />
          <StatusPill status={risk.status} />
          {/* Says which formula scored this, so the arithmetic below is read
              against the right one. */}
          {badge && (
            <Badge variant="outline" className="gap-1">
              {createElement(RISK_KIND_ICONS[risk.kind] ?? RISK_KIND_ICONS.FINDING, {
                className: "size-3",
                "aria-hidden": true,
              })}
              {badge}
            </Badge>
          )}
          {/* What deciding about this row decides about. A grouped risk is
              every asset failing the check, and a finding on a route is worth
              more than its own score says. */}
          {/* When an acceptance comes back to the queue. Without it an
              accepted row reads as settled for good. */}
          {risk.status === "ACCEPTED" && risk.accepted_until && (
            <Badge variant="outline">Accepted until {formatDate(risk.accepted_until)}</Badge>
          )}
          {risk.kind === "FINDING" && findings > 1 && (
            <Badge variant="outline">{findings} findings</Badge>
          )}
          {routes > 0 && (
            <Badge variant="outline" className="gap-1">
              {createElement(RISK_KIND_ICONS.ATTACK_PATH, {
                className: "size-3",
                "aria-hidden": true,
              })}
              On {routes} route{routes === 1 ? "" : "s"}
            </Badge>
          )}
        </div>
        <Link
          to={`/risks/${risk.id}`}
          // The overlay makes the whole card the way into the risk; the title
          // stays the link's accessible name.
          className="mt-1.5 block text-[15px] font-medium text-foreground underline-offset-4 after:absolute after:inset-0 hover:underline"
        >
          {risk.title}
        </Link>
        <p className="mt-0.5 line-clamp-2 max-w-3xl text-xs leading-relaxed text-muted-foreground">
          {subtitle}
        </p>
      </div>
      <ChevronRightIcon
        className="mt-1 size-4 shrink-0 text-muted-foreground/60 transition-transform group-hover:translate-x-0.5 group-hover:text-foreground"
        aria-hidden
      />
    </div>
  );
}

function RiskFooter({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap gap-x-6 gap-y-2 border-t border-border bg-muted/30 px-4 py-2.5 text-xs sm:pl-20">
      {children}
    </div>
  );
}

/**
 * One of the things this risk was weighed by. The icon is the same one the
 * risk detail and finding pages use for the factor, so five grey labels in a
 * row can be told apart by shape before they are read.
 */
function Factor({
  icon,
  label,
  value,
}: {
  icon: LucideIcon;
  label: string;
  value: React.ReactNode;
}) {
  return (
    <span className="flex items-center gap-1.5 text-muted-foreground">
      <IconLabel icon={icon}>{label}</IconLabel>
      {value}
    </span>
  );
}

/**
 * The row's checkbox. Raised above the card's link overlay, which otherwise
 * takes every click on the card -- a box that opened the risk instead of
 * selecting it would be the queue's first surprise.
 */
function SelectRow({
  risk,
  checked,
  onToggle,
}: {
  risk: Risk;
  checked: boolean;
  onToggle: () => void;
}) {
  return (
    <Checkbox
      className="relative z-10 mt-1"
      checked={checked}
      onCheckedChange={onToggle}
      aria-label={`Select ${risk.title}`}
    />
  );
}

/**
 * The links that close the most routes, above the list that ranks them.
 *
 * A fix is not a row in the queue -- it has no status and nothing can be
 * accepted about it -- but it is often the best answer to several rows at once,
 * so the three strongest are named here and the attack paths page has the rest
 * (DECISIONS.md §103).
 */
function TopFixes({ chokes }: { chokes: ChokePoint[] }) {
  return (
    <section
      aria-label="Top fixes"
      className="rounded-xl border border-ok-border bg-ok-bg px-4 py-3"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-medium text-ok">
          <ScissorsIcon className="size-4" aria-hidden />
          Top fixes
        </h2>
        <Link
          to="/attack-paths"
          className="text-xs text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
        >
          All routes and fixes
        </Link>
      </div>
      <ul className="mt-2 flex flex-col gap-1.5">
        {chokes.slice(0, 3).map((choke) => (
          <li
            key={`${choke.source.id}-${choke.relationship}-${choke.target.id}`}
            className="flex flex-wrap items-baseline justify-between gap-x-4 text-xs"
          >
            <span className="font-mono text-foreground">{choke.description}</span>
            <span className="text-muted-foreground">
              closes{" "}
              <strong className="tabular-nums text-foreground">{choke.severs}</strong> of{" "}
              {choke.total_routes} route{choke.total_routes === 1 ? "" : "s"}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}
