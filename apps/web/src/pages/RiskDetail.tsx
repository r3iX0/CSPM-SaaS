import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeftIcon, RadarIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import type { RiskDetail } from "@/lib/types";
import { useT } from "@/i18n";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { StatusPill } from "@/components/security/StatusPill";
import { AttackPathRoute } from "@/components/graph/AttackPathRoute";
import { OpenInGraph } from "@/components/graph/OpenInGraph";
import { routeKeyOf } from "@/components/graph/routeKeys";
import {
  Breadcrumbs,
  DetailSkeleton,
  EmptyState,
  ErrorState,
} from "@/components/common/states";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { cn, formatDate, formatRelative } from "@/lib/format";
import { useIsDemo } from "@/lib/useDemo";
import { RiskDecisions } from "@/components/security/RiskTriage";
import { FACTOR_ICONS } from "@/lib/icons";
import { IconLabel } from "@/components/security/IconLabel";
import type { LucideIcon } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

/**
 * One risk, and the findings it was built from.
 *
 * The list ranks a route above the findings inside it, which is the whole
 * reason both live in one table -- and it asks the reader to take that on
 * trust, because nothing there says *which* findings the route is made of. A
 * scenario scored 96 sitting above a finding scored 84 is an assertion until
 * its members are named and each one can be opened.
 *
 * The arithmetic is shown in the terms the score was actually built from, and
 * the two formulas are kept apart for the same reason the list cards are:
 * showing a scenario the six weighted components would invite the reader to
 * check numbers that were never used.
 */
export function RiskDetailPage() {
  const t = useT();
  const { riskId } = useParams();
  const isDemo = useIsDemo();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["risk", riskId],
    queryFn: () =>
      api.get<RiskDetail>(`/api/v1/risks/${riskId}`).then((r) => r.data),
  });

  if (isLoading) return <DetailSkeleton />;

  if (error) {
    // A deleted risk is an ordinary thing -- the scan that raised it was
    // purged -- and reads as a broken product unless it is named as such.
    const missing = error instanceof ApiError && error.status === 404;
    return (
      <div className="flex flex-col gap-4">
        <BackLink label={t.risks.backToRisks} />
        <ErrorState
          title={missing ? t.risks.notFound : "Could not load this risk"}
          detail={
            missing
              ? t.risks.notFoundDetail
              : "Cleave could not reach its own API."
          }
          impact={
            missing
              ? undefined
              : "Nothing about your environment has changed — this is a problem displaying it."
          }
          onRetry={missing ? undefined : () => refetch()}
          action={
            missing ? (
              <Link
                to="/risks"
                className={buttonVariants({ variant: "outline" })}
              >
                {t.risks.backToRisks}
              </Link>
            ) : undefined
          }
        />
      </div>
    );
  }

  if (!data) return null;

  const scenario = data.kind !== "FINDING";
  // What a decision here reaches, for the accept dialog to say before the
  // click. The list endpoint counts it; the detail already has the members.
  const openFindings = data.findings.filter(
    (f) => f.status !== "RESOLVED" && f.status !== "FALSE_POSITIVE",
  ).length;
  const breakdown = data.score_breakdown;
  const components = breakdown.components ?? {};
  const capped = (breakdown.uncapped ?? 0) > 100;

  return (
    <div className="flex flex-col gap-4">
      <Breadcrumbs
        trail={[
          { label: t.risks.title, to: "/risks" },
          { label: data.title },
        ]}
      />

      <div>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge level={data.risk_level} />
          <StatusPill status={data.status} />
          {data.accepted_until && (
            <span className="text-xs text-muted-foreground">
              until {formatDate(data.accepted_until)}
            </span>
          )}
          {/* Says which formula scored this, so the arithmetic below is read
              against the right one. */}
          {scenario && (
            <Badge
              variant="outline"
              className="rounded-md bg-muted font-normal text-muted-foreground"
            >
              {data.kind === "ESCALATION"
                ? t.risks.escalationBadge
                : t.risks.scenarioBadge}
            </Badge>
          )}
        </div>
        <div className="mt-3 flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-2xl font-semibold tracking-[-0.02em] text-foreground">
              {data.title}
            </h1>
            <p className="mt-1.5 max-w-[78ch] text-[13.5px] leading-relaxed text-muted-foreground">
              {data.description}
            </p>
            {/* The one place a risk -- and so a finding -- is decided about
                (DECISIONS.md §107). Not in the demo, where the API refuses
                every write, and not on a resolved risk: only a scan closes one. */}
            {!isDemo && data.status !== "RESOLVED" && (
              <div className="mt-4 flex flex-wrap gap-2">
                <RiskDecisions risks={[{ ...data, finding_count: openFindings }]} />
              </div>
            )}
          </div>
          {/* The figure itself, in its level's colour -- "?" for a score
              over evidence that could not be read, never a number to rank. */}
          <div className="flex shrink-0 flex-col items-end gap-1">
            <span
              className={cn(
                "text-[36px] leading-none font-semibold tabular-nums",
                LEVEL_TEXT[data.risk_level] ?? "text-unknown",
              )}
              aria-label={
                data.risk_level === "UNKNOWN"
                  ? "Risk score: no verdict"
                  : `Risk score ${Math.round(Number(data.risk_score))}, ${data.risk_level.toLowerCase()}`
              }
            >
              {data.risk_level === "UNKNOWN" ? "?" : Math.round(Number(data.risk_score))}
            </span>
            <span className="text-[11.5px] text-muted-foreground" aria-hidden>
              risk score
            </span>
          </div>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="flex min-w-0 flex-col gap-4">
          {scenario && data.path.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>{t.risks.routeLabel}</CardTitle>
                <CardDescription>
                  {data.kind === "ESCALATION"
                    ? t.risks.escalationIntro
                    : t.risks.scenarioIntro}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <AttackPathRoute steps={data.path} />
                <div className="mt-3">
                  {/* An escalation ends at a scope rather than at data, so it
                      is not one of the attack paths the graph traces; it opens
                      around the entry point untraced. */}
                  <OpenInGraph
                    entryId={data.path[0].source_id}
                    traceKey={
                      data.kind === "ATTACK_PATH"
                        ? routeKeyOf(
                            data.path[0].source_id,
                            data.path[data.path.length - 1].target_id,
                          )
                        : undefined
                    }
                  />
                </div>
                {/* A route is a claim about how an environment is wired as of
                    a reading. Without this, one that survived the latest scan
                    and one nothing has re-checked since Tuesday look the same. */}
                <p className="mt-3 text-xs text-muted-foreground">
                  {data.observed_at
                    ? t.risks.lastSeen.replace(
                        "{when}",
                        formatRelative(data.observed_at),
                      )
                    : t.risks.lastSeenUnknown}
                </p>
              </CardContent>
            </Card>
          )}

          {/* The part the list cannot show. */}
          <Card>
            <CardHeader>
              <CardTitle>{t.risks.builtFrom}</CardTitle>
              <CardDescription>
                {scenario
                  ? t.risks.builtFromScenario
                  : data.findings.length > 1
                    ? t.risks.builtFromGroup
                    : t.risks.builtFromFinding}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {data.findings.length === 0 ? (
                <EmptyState
                  icon={RadarIcon}
                  title={t.risks.noMembers}
                  detail={t.risks.noMembersDetail}
                />
              ) : (
                <ul className="divide-y divide-border rounded-lg border border-border">
                  {data.findings.map((finding) => (
                    <li key={finding.id} className="px-4 py-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge level={finding.severity} size="sm" />
                        <StatusPill status={finding.status} />
                        <code className="font-mono text-[11px] text-muted-foreground">
                          {finding.rule_id}
                        </code>
                      </div>
                      <Link
                        to={`/findings/${finding.id}`}
                        className="mt-1 block text-[13.5px] font-medium text-foreground underline-offset-4 hover:underline"
                      >
                        {finding.title}
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="flex min-w-0 flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle>{t.risks.theArithmetic}</CardTitle>
            </CardHeader>
            <CardContent>
              {scenario ? (
                /* Floored at the worst member and amplified for being short.
                   The six weighted components do not apply, and showing them
                   would be working that was never done. */
                <dl className="flex flex-col gap-2 text-xs">
                  <Row
                    label={t.risks.worstMember}
                    value={breakdown.worst_member ?? "—"}
                  />
                  <Row
                    label={t.risks.amplifier}
                    value={`+${breakdown.amplifier ?? 0}`}
                  />
                  <Row
                    label="Hops"
                    value={breakdown.hops ?? data.path.length}
                  />
                  {capped && (
                    <p className="mt-1 text-xs text-muted-foreground">
                      {breakdown.uncapped} before the ceiling. {t.risks.cappedNote}
                    </p>
                  )}
                </dl>
              ) : (
                <ul className="flex flex-col gap-1.5">
                  {Object.entries(components).map(([name, component]) => (
                    <li
                      key={name}
                      className="flex items-center justify-between gap-3 text-xs"
                    >
                      <span className="text-muted-foreground">
                        {name.replace(/_/g, " ")}
                        <span className="ml-1">
                          ({component.value} × {component.weight})
                        </span>
                      </span>
                      <span className="font-medium tabular-nums text-foreground">
                        {component.contribution.toFixed(1)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          {/* The factors, for a finding risk. A scenario was not scored from
              them, so it does not get a panel inviting them to be read. */}
          {!scenario && (
            <Card>
              <CardHeader>
                <CardTitle>What was weighed</CardTitle>
              </CardHeader>
              <CardContent>
                <dl className="flex flex-col gap-2 text-xs">
                  <Row
                    icon={FACTOR_ICONS.criticality}
                    label="Asset criticality"
                    value={<SeverityBadge level={data.asset_criticality} size="sm" />}
                  />
                  <Row
                    icon={FACTOR_ICONS.dataSensitivity}
                    label="Data sensitivity"
                    value={<SeverityBadge level={data.data_sensitivity} size="sm" />}
                  />
                  <Row
                    icon={FACTOR_ICONS.exposure}
                    label="Internet exposure"
                    value={<SeverityBadge level={data.internet_exposure} size="sm" />}
                  />
                  <Row
                    icon={FACTOR_ICONS.exploitability}
                    label="Exploitability"
                    value={`${data.exploitability}/5`}
                  />
                  <Row
                    icon={FACTOR_ICONS.businessImpact}
                    label="Business impact"
                    value={data.business_impact}
                  />
                </dl>
              </CardContent>
            </Card>
          )}

          {/* What a decision here does and does not do, where the decision is
              made: accepting records a person's call, and only a scan closes
              anything (DECISIONS.md §107). */}
          <Card className="bg-muted/40">
            <CardHeader>
              <CardTitle>Nothing resolves without proof</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-[13px] leading-relaxed text-muted-foreground">
                Accepting a risk records a decision and a date. It does not
                close the findings underneath it, and a route stays drawn until
                a scan stops tracing it.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

/** A score's figure in its level's colour. */
const LEVEL_TEXT: Record<string, string> = {
  CRITICAL: "text-critical",
  HIGH: "text-high",
  MEDIUM: "text-medium",
  LOW: "text-low",
  UNKNOWN: "text-unknown",
};

function BackLink({ label }: { label: string }) {
  return (
    <Link
      to="/risks"
      className={cn(
        buttonVariants({ variant: "ghost", size: "sm" }),
        "-ml-2 self-start text-muted-foreground",
      )}
    >
      <ArrowLeftIcon data-icon="inline-start" />
      {label}
    </Link>
  );
}

function Row({
  label,
  value,
  icon,
}: {
  label: string;
  value: React.ReactNode;
  icon?: LucideIcon;
}) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-muted-foreground">
        {icon ? <IconLabel icon={icon}>{label}</IconLabel> : label}
      </dt>
      <dd className="font-medium tabular-nums text-foreground">{value}</dd>
    </div>
  );
}
