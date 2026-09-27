import { lazy, Suspense } from "react";
import { Link } from "react-router-dom";
import { useQueries, useQuery } from "@tanstack/react-query";
import { ArrowRightIcon, ClipboardCheckIcon } from "lucide-react";

import { api } from "@/lib/api";
import type {
  ComplianceFramework,
  ComplianceFrameworkDetail,
  ControlStatus,
} from "@/lib/types";
import { useT } from "@/i18n";
import { cn, formatPercent } from "@/lib/format";
import { EvidenceNotice } from "@/components/compliance";
import { Bars } from "@/components/charts/Bars";
import type { Slice } from "@/components/charts/DonutLegend";
import { Skeleton } from "@/components/ui/skeleton";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

/** Recharts is lazy everywhere in this app; a ring is not worth blocking on. */
const Donut = lazy(() =>
  import("@/components/charts/Donut").then((m) => ({ default: m.Donut })),
);

/**
 * Framework overview.
 *
 * The headline number is deliberately *assessable coverage*, not a compliance
 * percentage. "You are 78% GDPR compliant" is a sentence this product must
 * never produce — it is not true, it is not checkable, and someone would put it
 * in front of an auditor. "CloudGuard can speak to 9 of these 11 requirements"
 * is both true and useful.
 */
export function CompliancePage() {
  const t = useT();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["compliance"],
    queryFn: () =>
      api.get<ComplianceFramework[]>("/api/v1/compliance").then((r) => r.data),
  });

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t.compliance.title}
        description={t.compliance.intro}
      />

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
  { key: "NOT_ASSESSED", label: "not assessed", tone: "var(--muted-foreground)", dot: "bg-muted-foreground" },
  { key: "NOT_COVERED", label: "not covered", tone: "var(--border)", dot: "border border-dashed border-muted-foreground bg-transparent" },
];

function FrameworkCard({ framework }: { framework: ComplianceFramework }) {
  const t = useT();
  const counts = framework.status_counts;
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
      className="group block rounded-xl outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
    >
      <Card className="flex h-full flex-col gap-0 py-0 transition-shadow group-hover:ring-foreground/25">
        <CardHeader className="py-4">
          <div className="flex items-start gap-4">
            {/* The ring is the controls divided by status; the figure in it
                is coverage -- the share that reached a conclusion -- so the
                one number on the card is never read as a grade. */}
            <div className="flex shrink-0 flex-col items-center gap-1">
              <Suspense fallback={<Skeleton className="size-16 rounded-full" />}>
                <Donut
                  slices={slices}
                  centerValue={formatPercent(framework.coverage_ratio)}
                  centerLabel=""
                  ariaLabel={`${formatPercent(framework.coverage_ratio)} of ${framework.control_count} controls reached a conclusion`}
                  className="size-16"
                  valueClassName="text-[14.5px]"
                />
              </Suspense>
              <span className="text-[11px] text-muted-foreground">assessable</span>
            </div>
            <div className="min-w-0">
              <CardTitle>{framework.short_name}</CardTitle>
              <CardDescription className="mt-1">
                {framework.authority} · {framework.version}
              </CardDescription>
              <p className="mt-2 line-clamp-2 text-[13px] leading-relaxed text-muted-foreground">
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

        <div className="flex items-center gap-1 border-t px-5 py-3 text-[13px] font-medium text-foreground">
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

/**
 * Where each framework's assessable evidence concentrates, domain by domain.
 *
 * A domain's figure is the share of its controls that reached a conclusion --
 * coverage, never a verdict, in the same terms as the card's ring. Read from
 * each framework's own controls (the detail the framework page reads, so the
 * two share a cache entry); a framework still loading draws nothing rather
 * than a row of empty bars.
 */
function DomainCoverage({ frameworks }: { frameworks: ComplianceFramework[] }) {
  const details = useQueries({
    queries: frameworks.map((framework) => ({
      queryKey: ["compliance", framework.id],
      queryFn: () =>
        api
          .get<ComplianceFrameworkDetail>(
            `/api/v1/compliance/${encodeURIComponent(framework.id)}`,
          )
          .then((r) => r.data),
      retry: false,
    })),
  });
  const loaded = details
    .map((query) => query.data)
    .filter((detail): detail is ComplianceFrameworkDetail => Boolean(detail?.controls));
  if (loaded.length === 0) return null;

  return (
    <section
      aria-labelledby="domain-coverage"
      className="rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <header className="px-5 py-4">
        <h2 id="domain-coverage" className="text-[13.5px] font-semibold">
          Coverage by domain
        </h2>
        <p className="mt-1 text-xs text-muted-foreground">
          Where assessable evidence concentrates for each framework, and where
          Cleave has nothing to show its work for.
        </p>
      </header>
      <div className="grid gap-6 border-t px-5 py-4 md:grid-cols-2">
        {loaded.map((detail) => (
          <div key={detail.id} className="min-w-0">
            <h3 className="mb-2.5 text-xs font-medium">{detail.short_name}</h3>
            <Bars
              ariaLabel={`${detail.short_name}: share of controls that reached a conclusion, by domain`}
              bars={domains(detail).map((domain) => ({
                key: domain.name,
                label: domain.name,
                value: domain.percent,
                of: 100,
                hideDenominator: true,
                unit: "%",
                tone: "var(--primary)",
              }))}
            />
          </div>
        ))}
      </div>
    </section>
  );
}

function domains(detail: ComplianceFrameworkDetail) {
  const byGroup = new Map<string, { total: number; concluded: number }>();
  for (const control of detail.controls) {
    const entry = byGroup.get(control.group) ?? { total: 0, concluded: 0 };
    entry.total += 1;
    if (control.status === "PASSING" || control.status === "FAILING") entry.concluded += 1;
    byGroup.set(control.group, entry);
  }
  return [...byGroup.entries()].map(([name, { total, concluded }]) => ({
    name,
    percent: total === 0 ? 0 : Math.round((concluded / total) * 100),
  }));
}
