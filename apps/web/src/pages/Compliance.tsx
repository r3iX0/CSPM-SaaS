import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowRightIcon, ClipboardCheckIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { ComplianceFramework, ComplianceFrameworkDetail, ControlStatus } from "@/lib/types";
import { useT } from "@/i18n";
import { cn } from "@/lib/format";
import { useUrlFilters } from "@/lib/useUrlFilters";
import { EvidenceNotice, StatusBar, StatusLegend } from "@/components/compliance";
import { Donut } from "@/components/charts/Donut";
import type { Slice } from "@/components/charts/DonutLegend";
import { CardsSkeleton, EmptyState, ErrorState, PageHeader } from "@/components/common/states";
import { SegmentedFilter } from "@/components/common/SegmentedFilter";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

/**
 * Framework overview.
 *
 * The headline number is deliberately how many controls reached a verdict out
 * of how many there are, never a compliance percentage. "You are 78% GDPR
 * compliant" is a sentence this product must never produce — it is not true,
 * it is not checkable, and someone would put it in front of an auditor. "CloudGuard can speak to 9 of these 11 requirements"
 * is both true and useful.
 */
export function CompliancePage() {
  const t = useT();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["compliance"],
    queryFn: () => api.get<ComplianceFramework[]>("/api/v1/compliance").then((r) => r.data),
  });

  return (
    <div className="flex flex-col gap-4">
      <PageHeader title={t.compliance.title} description={t.compliance.intro} />

      <EvidenceNotice />

      {isLoading && <CardsSkeleton count={4} />}

      {error && (
        <ErrorState
          title="Could not load the frameworks"
          detail="Cleave could not reach its own API."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      {data && data.length === 0 && (
        <EmptyState icon={ClipboardCheckIcon} title={t.compliance.empty} />
      )}

      <div className="grid gap-4 md:grid-cols-2">
        {data?.map((framework) => (
          <FrameworkCard key={framework.id} framework={framework} />
        ))}
      </div>

      {data && data.length > 0 && <DomainCoverage frameworks={data} />}
    </div>
  );
}

/**
 * The statuses a framework card counts, in the order a reader weighs them.
 * Coloured by what they are: a pass and a fail in their own tones, a control
 * with no verdict in the unknown tone -- never a quieter green -- and one no
 * rule checks in the border colour, because that is a fact about this
 * product, not about the estate.
 */
const STATUSES: { key: ControlStatus; label: string; tone: string; dot: string }[] = [
  { key: "PASSING", label: "passing", tone: "var(--sev-ok)", dot: "bg-ok" },
  { key: "FAILING", label: "failing", tone: "var(--sev-critical)", dot: "bg-critical" },
  { key: "INCONCLUSIVE", label: "inconclusive", tone: "var(--sev-unknown)", dot: "bg-unknown" },
  {
    key: "NOT_ASSESSED",
    label: "not assessed",
    tone: "var(--muted-foreground)",
    dot: "bg-muted-foreground",
  },
  {
    key: "NOT_COVERED",
    label: "not covered",
    tone: "var(--border)",
    dot: "border border-dashed border-muted-foreground bg-transparent",
  },
];

function FrameworkCard({ framework }: { framework: ComplianceFramework }) {
  const t = useT();
  const counts = framework.status_counts;
  const verdicts = (counts.PASSING ?? 0) + (counts.FAILING ?? 0);
  const slices: Slice[] = STATUSES.filter((status) => (counts[status.key] ?? 0) > 0).map(
    (status) => ({
      key: status.key,
      label: status.label,
      value: counts[status.key] ?? 0,
      tone: status.tone,
    }),
  );

  return (
    // The whole card is the way in (§31: a Link, never a Button around one).
    <Link
      to={`/compliance/${encodeURIComponent(framework.id)}`}
      className="group block rounded-xl outline-none focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring"
    >
      <Card className="flex h-full flex-col gap-0 py-0 transition-shadow group-hover:ring-foreground/25">
        <CardHeader className="py-4">
          <div className="flex items-start gap-4">
            {/* The ring is the controls divided by status; the figure in it
                is how many reached a verdict, pass or fail, out of how many
                there are. It was a percentage, and "94%" over a ring of red
                read as a grade to anyone who did not open the card -- a
                count out of a total cannot be (DECISIONS.md §185). */}
            <div className="flex shrink-0 flex-col items-center gap-1">
              <Donut
                slices={slices}
                centerValue={`${verdicts}/${framework.control_count}`}
                centerLabel=""
                ariaLabel={`${verdicts} of ${framework.control_count} controls ${t.compliance.withVerdict}`}
                className="size-16"
                valueClassName="text-meta"
              />
              <span className="text-caption text-muted-foreground">{t.compliance.withVerdict}</span>
            </div>
            <div className="min-w-0">
              <CardTitle>{framework.short_name}</CardTitle>
              <CardDescription className="mt-1">
                {framework.authority} · {framework.version}
              </CardDescription>
              <p className="mt-2 line-clamp-2 text-body leading-relaxed text-muted-foreground">
                {framework.summary}
              </p>
            </div>
          </div>
        </CardHeader>

        <CardContent className="flex-1 pb-4">
          <ul className="flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-muted-foreground">
            {STATUSES.filter((status) => (counts[status.key] ?? 0) > 0).map((status) => (
              <li key={status.key} className="flex items-center gap-1.5 tabular-nums">
                <span className={cn("size-2 shrink-0 rounded-full", status.dot)} aria-hidden />
                {counts[status.key]} {status.label}
              </li>
            ))}
            {framework.open_finding_count > 0 && (
              <li className="font-medium text-critical tabular-nums">
                {framework.open_finding_count} {t.compliance.openFindings}
              </li>
            )}
          </ul>
        </CardContent>

        <div className="flex items-center gap-1 border-t px-5 py-3 text-body font-medium text-foreground">
          {t.compliance.viewFramework}
          <ArrowRightIcon
            className="size-3.5 transition-transform group-hover:translate-x-0.5"
            aria-hidden
          />
        </div>
      </Card>
    </Link>
  );
}

/** How the domains of one framework are ordered: its own, or worst first. */
type DomainOrder = "catalogue" | "failing";

/**
 * Where each framework's evidence sits, section by section -- one framework
 * at a time.
 *
 * It was eleven grids of teal bars, one per framework, each bar the share of a
 * section's controls that reached a verdict. Teal at 96% over a section where
 * every control fails read as a grade, which is the one reading this page
 * exists to refuse (§185); the names were cut to fifteen letters; a bar said a
 * percentage of nothing in particular; and none of it led anywhere. Now a
 * section is a row: its full name, the same status bar the framework page
 * draws (failing, inconclusive, passing, not assessed, not covered), how many
 * of its controls reached a verdict out of how many, how many fail, and a link
 * to the framework's page narrowed to that section (DECISIONS.md §206).
 *
 * The framework is a tab held in the URL (`?domains=`), and only its controls
 * are read -- under the key the framework page shares -- rather than every
 * framework's at once on arrival.
 */
function DomainCoverage({ frameworks }: { frameworks: ComplianceFramework[] }) {
  const t = useT();
  const [filters, update] = useUrlFilters({ domains: "", domainOrder: "catalogue" });
  const selected =
    frameworks.find((framework) => framework.id === filters.domains) ?? frameworks[0];
  const order: DomainOrder = filters.domainOrder === "failing" ? "failing" : "catalogue";
  const first = frameworks[0]?.id;

  if (!selected) return null;
  return (
    <section
      aria-labelledby="domain-coverage"
      className="rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <header className="flex flex-wrap items-end justify-between gap-3 px-5 pt-4 pb-3">
        <div className="min-w-0">
          <h2 id="domain-coverage" className="text-body font-semibold">
            {t.compliance.domainsTitle}
          </h2>
          <p className="mt-1 text-xs text-muted-foreground">{t.compliance.domainsIntro}</p>
        </div>
        <SegmentedFilter
          label={t.compliance.domainsOrderLabel}
          value={order}
          onChange={(value) => update({ domainOrder: value })}
          segments={[
            { value: "catalogue", label: t.compliance.domainsCatalogue },
            { value: "failing", label: t.compliance.domainsWorst },
          ]}
        />
      </header>
      <Tabs
        value={selected.id}
        onValueChange={(value) =>
          update({ domains: typeof value === "string" && value !== first ? value : null })
        }
        className="gap-0"
      >
        <div className="overflow-x-auto border-b px-5">
          <TabsList variant="line" aria-label={t.compliance.domainsFramework}>
            {frameworks.map((framework) => (
              <TabsTrigger key={framework.id} value={framework.id} className="flex-none px-2">
                {framework.short_name}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
        <TabsContent value={selected.id}>
          <FrameworkDomains framework={selected} order={order} />
        </TabsContent>
      </Tabs>
    </section>
  );
}

function FrameworkDomains({
  framework,
  order,
}: {
  framework: ComplianceFramework;
  order: DomainOrder;
}) {
  const t = useT();
  const detail = useQuery({
    queryKey: ["compliance", framework.id],
    queryFn: () =>
      api
        .get<ComplianceFrameworkDetail>(`/api/v1/compliance/${encodeURIComponent(framework.id)}`)
        .then((r) => r.data),
    retry: false,
  });

  if (detail.isLoading) {
    return (
      <div className="flex flex-col gap-3 px-5 py-4">
        {[0, 1, 2, 3].map((row) => (
          <Skeleton key={row} className="h-5 w-full" />
        ))}
      </div>
    );
  }
  if (!detail.data?.controls) {
    return <p className="px-5 py-4 text-xs text-muted-foreground">{t.compliance.domainsFailed}</p>;
  }

  const rows = sortDomains(domainsOf(detail.data), order);
  const failing = rows.filter((domain) => domain.failing > 0).length;
  const unchecked = rows.filter((domain) => domain.counts.NOT_COVERED === domain.total).length;
  const base = `/compliance/${encodeURIComponent(framework.id)}`;

  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2 px-5 py-3">
        <p className="text-xs text-muted-foreground">
          {t.compliance.domainsSummary(rows.length, failing, unchecked)}
        </p>
        <StatusLegend />
      </div>
      <ul className="divide-y border-t">
        {rows.map((domain) => (
          <li key={domain.name}>
            <Link
              to={`${base}?section=${encodeURIComponent(domain.name)}`}
              className="grid grid-cols-1 gap-x-4 gap-y-1.5 px-5 py-2.5 outline-none hover:bg-muted/40 focus-visible:bg-muted/40 focus-ring-inset sm:grid-cols-[minmax(0,16rem)_minmax(0,1fr)_11rem] sm:items-center"
            >
              <span className="text-body text-foreground">{domain.name}</span>
              <StatusBar counts={domain.counts} total={domain.total} />
              <span className="text-xs text-muted-foreground tabular-nums sm:text-right">
                {domain.verdicts === 0 && domain.counts.NOT_COVERED === domain.total ? (
                  t.compliance.domainUnchecked(domain.total)
                ) : (
                  <>
                    {t.compliance.domainVerdicts(domain.verdicts, domain.total)}
                    {domain.failing > 0 && (
                      <>
                        {" · "}
                        <span className="font-medium text-critical">
                          {t.compliance.domainFailing(domain.failing)}
                        </span>
                      </>
                    )}
                  </>
                )}
              </span>
            </Link>
          </li>
        ))}
      </ul>
      <div className="border-t px-5 py-3">
        <Link
          to={base}
          className="inline-flex items-center gap-1 rounded-sm text-body font-medium text-foreground outline-none hover:underline focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring"
        >
          {t.compliance.domainsAll(framework.short_name)}
          <ArrowRightIcon className="size-3.5" aria-hidden />
        </Link>
      </div>
    </>
  );
}

interface Domain {
  name: string;
  counts: Record<ControlStatus, number>;
  total: number;
  verdicts: number;
  failing: number;
}

/** A framework's sections in its own order, each with its controls counted by status. */
function domainsOf(detail: ComplianceFrameworkDetail): Domain[] {
  const byGroup = new Map<string, Record<ControlStatus, number>>();
  for (const control of detail.controls) {
    const counts = byGroup.get(control.group) ?? {
      FAILING: 0,
      INCONCLUSIVE: 0,
      PASSING: 0,
      NOT_ASSESSED: 0,
      NOT_COVERED: 0,
    };
    counts[control.status] += 1;
    byGroup.set(control.group, counts);
  }
  return [...byGroup.entries()].map(([name, counts]) => ({
    name,
    counts,
    total: Object.values(counts).reduce((sum, count) => sum + count, 0),
    verdicts: counts.PASSING + counts.FAILING,
    failing: counts.FAILING,
  }));
}

/**
 * Worst first, when asked: most failing controls, then most without a
 * verdict. Otherwise the framework's own order, which is the order an
 * auditor's spreadsheet is in.
 */
function sortDomains(domains: Domain[], order: DomainOrder): Domain[] {
  if (order === "catalogue") return domains;
  return [...domains].sort(
    (a, b) => b.failing - a.failing || b.total - b.verdicts - (a.total - a.verdicts),
  );
}
