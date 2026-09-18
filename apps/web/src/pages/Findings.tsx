import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import {
  ArrowDownIcon,
  SearchIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  XIcon,
} from "lucide-react";
import { ResourceTypeLabel } from "@/components/security/IconLabel";

import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";
import { useT } from "@/i18n";
import { StatusPill } from "@/components/security/StatusPill";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { RiskScore } from "@/components/security/SecurityScore";
import {
  EmptyState,
  ErrorState,
  PageHeader,
  TableSkeleton,
} from "@/components/common/states";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  HoverCard,
  HoverCardContent,
  HoverCardTrigger,
} from "@/components/ui/hover-card";
import { Input } from "@/components/ui/input";
import { SelectField } from "@/components/common/SelectField";
import { SegmentedFilter } from "@/components/common/SegmentedFilter";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Pager } from "@/components/common/Pager";
import { cn, formatDate, formatRelative } from "@/lib/format";
import { stagger } from "@/lib/motion";
import { useUrlFilters } from "@/lib/useUrlFilters";
import { ROW_ACTIVE, useRowNavigation } from "@/lib/keyboard";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
const PAGE_SIZE = 50;
const SEARCH_DEBOUNCE_MS = 250;

type SortKey = "risk" | "severity" | "recent";

/**
 * The list a security engineer actually works from.
 *
 * **The bug this page had was silent, which is what made it serious.** It asked
 * for findings with no `limit`, took the API's default hundred, and rendered
 * them as though they were all of them -- so a tenant with four hundred
 * findings saw a hundred with nothing on screen saying so. Search and sort then
 * ran over that hundred in the browser, which turned a display problem into a
 * false negative: searching an estate and being told "no findings match" when
 * three hundred rows were never in the browser to match against.
 *
 * So both moved to the database (`GET /findings?search=&sort=`), and the page
 * pages properly. The cost is a round trip per keystroke, which the debounce
 * below pays for; the alternative was a security product answering questions
 * about data it did not have.
 *
 * Sorting defaults to risk rather than severity, deliberately. Severity is what
 * the *rule* says in the abstract; risk is what it means on this asset, with
 * this data, at this exposure -- and a HIGH on a production database outranks a
 * CRITICAL on an isolated sandbox. Severity remains available for the reader
 * who wants the rulebook's own order.
 */
export function FindingsPage() {
  const t = useT();
  // Every filter lives in the URL (`useUrlFilters`), so a filtered view is a
  // link: it survives a reload and the back button, can be sent to somebody,
  // and is the same thing the dashboard's tiles and a control's evidence link
  // *into*. `status` defaults to OPEN because open is the queue; a link that
  // scopes the list to one reading sends `status=all`, because "what rested on
  // this" honestly includes what has since been fixed.
  const [filters, update] = useUrlFilters({
    severity: "all",
    status: "OPEN",
    q: "",
    sort: "risk",
    page: "0",
    rule_id: "",
    evidence_id: "",
  });
  const severity = (SEVERITIES as readonly string[]).includes(filters.severity)
    ? filters.severity
    : "all";
  const status = filters.status;
  const sort: SortKey = (["risk", "severity", "recent"] as const).includes(
    filters.sort as SortKey,
  )
    ? (filters.sort as SortKey)
    : "risk";
  const page = Math.max(0, Number.parseInt(filters.page, 10) || 0);
  const ruleId = filters.rule_id;
  const evidenceId = filters.evidence_id;
  const debouncedSearch = filters.q;

  // What is typed is held here and written to the URL after a pause: a request
  // per keystroke would be six for "public", and a URL rewritten on every key
  // would be a history nobody could navigate.
  const [search, setSearch] = useState(filters.q);
  useEffect(() => {
    const timer = setTimeout(() => {
      if (search.trim() !== debouncedSearch) update({ q: search.trim() || null, page: null });
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [search, debouncedSearch, update]);

  /** Any filter change re-slices the set, so page 4 of the old one is meaningless. */
  function refilter(patch: Partial<Record<keyof typeof filters, string | null>>) {
    update({ ...patch, page: null });
  }

  function setPage(next: number) {
    update({ page: String(next) });
  }

  const params = new URLSearchParams();
  if (severity !== "all") params.set("severity", severity);
  if (status !== "all") params.set("status", status);
  if (ruleId) params.set("rule_id", ruleId);
  if (evidenceId) params.set("evidence_id", evidenceId);
  if (debouncedSearch.trim()) params.set("search", debouncedSearch.trim());
  params.set("sort", sort);
  params.set("limit", String(PAGE_SIZE));
  params.set("offset", String(page * PAGE_SIZE));

  /** Drop one or more scoping filters -- one write, so none is put back. */
  function clearParamFilters(...names: ("rule_id" | "evidence_id")[]) {
    refilter(Object.fromEntries(names.map((name) => [name, null])));
  }

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: [
      "findings",
      severity,
      status,
      ruleId,
      evidenceId,
      debouncedSearch,
      sort,
      page,
    ],
    queryFn: () =>
      api.get<Finding[]>(`/api/v1/findings?${params.toString()}`).then((r) => ({
        findings: r.data,
        total:
          (r.meta as { total?: number } | undefined)?.total ?? r.data.length,
      })),
    // Without this the table blanks on every page turn, which reads as the
    // findings having gone rather than as a page loading.
    placeholderData: keepPreviousData,
  });

  // Already filtered and ordered by the database; the page renders what it was
  // sent rather than re-deciding it.
  const rows = data?.findings ?? [];
  const activeRow = useRowNavigation(rows.map((finding) => `/findings/${finding.id}`));
  const total = data?.total ?? 0;
  const pages = Math.ceil(total / PAGE_SIZE);

  const filtered =
    search.trim().length > 0 ||
    severity !== "all" ||
    status !== "OPEN" ||
    !!ruleId ||
    !!evidenceId;



  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        icon={ShieldAlertIcon}
        title={t.findings.title}
        description="Misconfigurations CloudGuard observed, ranked by what they mean on the asset."
      />

      {/* Which slice, then how to narrow it. Status is the view -- open is
          the queue, the rest are its history -- so every one of them is named
          on screen; severity and search refine whichever view is showing. */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <SegmentedFilter
          label="Filter by status"
          value={status}
          onChange={(value) => refilter({ status: value })}
          segments={[
            { value: "OPEN", label: "Open" },
            { value: "IN_PROGRESS", label: "In progress" },
            { value: "RESOLVED", label: "Verified fixed" },
            { value: "ACCEPTED_RISK", label: "Risk accepted" },
            { value: "all", label: "All" },
          ]}
        />

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative w-full sm:w-72">
            <SearchIcon
              className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden
            />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search findings, rules or assets"
              aria-label="Search findings"
              data-page-search
              className="pl-8"
            />
          </div>
          {/* A select, like every other filter in the product: the trigger
              names the active severity, so it reads without opening. */}
          <SelectField
            value={severity}
            onValueChange={(value) => refilter({ severity: value || "all" })}
            ariaLabel="Filter by severity"
            className="w-[160px]"
            idleValue="all"
            options={[
              { value: "all", label: "All severities" },
              ...SEVERITIES.map((level) => ({
                value: level,
                label: level.charAt(0) + level.slice(1).toLowerCase(),
              })),
            ]}
          />
        </div>
      </div>

      {(ruleId || evidenceId) && (
        <div className="flex flex-wrap items-center gap-2">
          {ruleId && (
            <Badge variant="secondary" className="gap-1.5 font-normal">
              Rule <code className="font-medium">{ruleId}</code>
              <button
                onClick={() => clearParamFilters("rule_id")}
                aria-label="Clear rule filter"
                className="rounded-full text-muted-foreground transition-colors hover:text-foreground"
              >
                <XIcon className="size-3" />
              </button>
            </Badge>
          )}
          {evidenceId && (
            // Named for what it means rather than for the column: nobody
            // arrived here thinking about an evidence id, they clicked a
            // listing on a scan.
            <Badge variant="secondary" className="gap-1.5 font-normal">
              {t.findings.restingOnReading}
              <button
                onClick={() => clearParamFilters("evidence_id")}
                aria-label="Clear evidence filter"
                className="rounded-full text-muted-foreground transition-colors hover:text-foreground"
              >
                <XIcon className="size-3" />
              </button>
            </Badge>
          )}
        </div>
      )}

      {isLoading && <TableSkeleton columns={6} />}

      {error && (
        <ErrorState
          title="Could not load findings"
          detail="CloudGuard could not reach its own API to read your findings."
          impact="This is a problem loading the page, not a change in your security posture — nothing about your environment has been reassessed."
          onRetry={() => refetch()}
        />
      )}

      {data && rows.length === 0 && (
        <EmptyState
          icon={ShieldCheckIcon}
          title={
            filtered ? "No findings match these filters" : t.findings.empty
          }
          detail={
            filtered
              ? "Widen the filters, or clear the search, to see the rest of this environment."
              : "Your latest scan reached a verdict on every check it could run and raised nothing. Coverage gaps, if any, are shown on the scan."
          }
          action={
            filtered ? (
              <Button
                variant="outline"
                onClick={() => {
                  setSearch("");
                  // Every filter in one write, both scoping ones included, or
                  // "Clear filters" would leave the reader on an empty table
                  // with a chip still narrowing it.
                  refilter({
                    severity: null,
                    status: null,
                    q: null,
                    rule_id: null,
                    evidence_id: null,
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
                View scan coverage
              </Link>
            )
          }
        />
      )}

      {data && rows.length > 0 && (
        <>
          <Card className="overflow-hidden py-0">
            <CardContent className="px-0">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="w-[45%]">Finding</TableHead>
                    <SortableHead
                      label={t.common.severity}
                      sortKey="severity"
                      active={sort}
                      onSort={(key) => refilter({ sort: key })}
                    />
                    <TableHead>{t.findings.asset}</TableHead>
                    <SortableHead
                      label={t.findings.riskScore}
                      sortKey="risk"
                      active={sort}
                      align="right"
                      onSort={(key) => refilter({ sort: key })}
                    />
                    <TableHead>{t.common.status}</TableHead>
                    <SortableHead
                      label={t.findings.lastSeen}
                      sortKey="recent"
                      active={sort}
                      align="right"
                      onSort={(key) => refilter({ sort: key })}
                    />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((finding, index) => (
                    // The same arrival the dashboard's lists use, in CSS
                    // rather than through the motion runtime: a `tr` cannot be
                    // wrapped without breaking the table, and the rise is the
                    // one thing needed here. Capped at eight rows of stagger,
                    // so a fifty-row page does not become a slow page.
                    <TableRow
                      key={finding.id}
                      // Relative, so the title link's overlay covers this row
                      // and no more: the whole row opens the finding.
                      className={cn(
                        "group relative cursor-pointer [animation:cg-rise_260ms_ease-out_both]",
                        ROW_ACTIVE,
                      )}
                      style={stagger(index)}
                      data-row-index={index}
                      data-active={activeRow === index}
                    >
                      <TableCell className="max-w-0">
                        {/* The column truncates, which is right for a table
                            and wrong for the reader who has to open six rows
                            to work out which one they meant. The preview is
                            the untruncated title and what the rule says, on
                            hover and on focus -- it opens nothing and changes
                            nothing, so it costs a reader who wants the whole
                            page nothing either. */}
                        <HoverCard>
                          <HoverCardTrigger
                            render={
                              <Link
                                to={`/findings/${finding.id}`}
                                className="block truncate font-medium text-foreground after:absolute after:inset-0 hover:underline"
                              />
                            }
                          >
                            {finding.title}
                          </HoverCardTrigger>
                          <HoverCardContent
                            side="right"
                            align="start"
                            className="w-96"
                          >
                            <p className="text-sm font-medium">
                              {finding.title}
                            </p>
                            <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                              {finding.description}
                            </p>
                            <p className="mt-2 text-[11px] text-muted-foreground">
                              {finding.rule_id} · v{finding.rule_version}
                            </p>
                          </HoverCardContent>
                        </HoverCard>
                        <p className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
                          {finding.rule_id}
                        </p>
                      </TableCell>
                      <TableCell>
                        <SeverityBadge level={finding.severity} />
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {finding.resource ? (
                          <>
                            <span className="block max-w-[16rem] truncate text-foreground">
                              {finding.resource.name}
                            </span>
                            <ResourceTypeLabel
                              type={finding.resource.resource_type}
                              className="max-w-[16rem] text-xs"
                            />
                          </>
                        ) : (
                          <span className="italic">Tenant-wide</span>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <RiskScore score={finding.risk_score} />
                      </TableCell>
                      <TableCell>
                        <StatusPill status={finding.status} />
                      </TableCell>
                      <TableCell
                        className="text-right text-muted-foreground tabular-nums"
                        title={formatDate(finding.last_detected_at)}
                      >
                        {formatRelative(finding.last_detected_at)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-xs text-muted-foreground">
              {page * PAGE_SIZE + 1}–{page * PAGE_SIZE + rows.length} of {total}{" "}
              finding
              {total === 1 ? "" : "s"}
              {filtered ? " matching these filters" : ""}
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
 * A column that is also the way to order by it.
 *
 * Ordering used to live in a fourth dropdown beside the filters, which put the
 * control somewhere other than the thing it acts on and left the table's own
 * headers inert -- so the obvious gesture, clicking "Risk score", did nothing.
 *
 * One direction per column, not a toggle, because the backend orders each of
 * these the only way that is useful: worst risk, worst severity and most
 * recent all mean descending, and an ascending findings table would put the
 * least urgent row at the top of a security queue.
 */
function SortableHead({
  label,
  sortKey,
  active,
  align = "left",
  onSort,
}: {
  label: string;
  sortKey: SortKey;
  active: SortKey;
  align?: "left" | "right";
  onSort: (key: SortKey) => void;
}) {
  const isActive = active === sortKey;
  return (
    <TableHead
      aria-sort={isActive ? "descending" : "none"}
      className={align === "right" ? "text-right" : undefined}
    >
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        aria-label={`Sort by ${label.toLowerCase()}`}
        className={cn(
          "inline-flex items-center gap-1 rounded-sm transition-colors hover:text-foreground",
          "focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50",
          align === "right" && "flex-row-reverse",
          isActive && "text-foreground",
        )}
      >
        {label}
        <ArrowDownIcon
          className={cn(
            "size-3 transition-opacity",
            isActive ? "opacity-100" : "opacity-0",
          )}
          aria-hidden
        />
      </button>
    </TableHead>
  );
}
