import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { CheckIcon, CircleIcon, XIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import type { FindingDetail, Level, RiskDetail } from "@/lib/types";
import { useT } from "@/i18n";
import { AttackPathRoute } from "@/components/graph/AttackPathRoute";
import { CodeBlock } from "@/components/common/CodeBlock";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { StatusPill } from "@/components/security/StatusPill";
import { TrackFix } from "@/components/security/TrackFix";
import { DetailSkeleton, EmptyState, ErrorState } from "@/components/common/states";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, formatRelative } from "@/lib/format";

/**
 * One risk, read beside the ranking rather than instead of it.
 *
 * The list used to be eleven full-width cards, each carrying a five-line
 * paragraph, three of them byte-identical (docs/UI_REDESIGN.md §4.2). The
 * prose was worth keeping and showing eleven times was not, so it lives here:
 * one risk at a time, next to the row it explains, so the reader can compare
 * what they are reading against what it outranks.
 *
 * The same component is the whole page below `lg`, where there is no room for
 * two columns. One implementation, so the narrow reading cannot drift from the
 * wide one.
 */
export function RiskDetailBody({
  riskId,
  onClose,
}: {
  riskId: string;
  /** Present in the drawer, absent when this is the page. */
  onClose?: () => void;
}) {
  const t = useT();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["risk", riskId],
    queryFn: () =>
      api.get<RiskDetail>(`/api/v1/risks/${riskId}`).then((r) => r.data),
  });

  if (isLoading) return <DetailSkeleton />;

  if (error) {
    // A deleted risk is an ordinary thing — the scan that raised it was
    // purged — and reads as a broken product unless it is named as such.
    const missing = error instanceof ApiError && error.status === 404;
    return (
      <ErrorState
        title={missing ? t.risks.notFound : "Could not load this risk"}
        detail={
          missing
            ? t.risks.notFoundDetail
            : "CloudGuard could not reach its own API."
        }
        impact={
          missing
            ? undefined
            : "Nothing about your environment has changed — this is a problem displaying it."
        }
        onRetry={missing ? undefined : () => refetch()}
      />
    );
  }

  if (!data) return null;

  const scenario = data.kind !== "FINDING";
  const ownFinding = scenario ? undefined : data.findings[0];

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge level={data.risk_level} size="sm" />
            <StatusPill status={data.status} />
            {/* Says which formula scored this, so the arithmetic below is read
                against the right one. */}
            {scenario && (
              <Badge variant="outline">
                {data.kind === "ESCALATION"
                  ? t.risks.escalationBadge
                  : t.risks.scenarioBadge}
              </Badge>
            )}
          </div>
          <h2 className="mt-2 text-base font-semibold leading-snug text-foreground">
            {data.title}
          </h2>
        </div>
        {onClose && (
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={onClose}
            aria-label="Close this risk"
          >
            <XIcon />
          </Button>
        )}
      </div>

      <Score risk={data} />

      <Section label={t.risks.whyThisMatters}>
        <p className="text-[13px] leading-relaxed text-muted-foreground">
          {data.description}
        </p>
      </Section>

      {/* Not the six weighted components — those are arithmetic. This is the
          three statements about the estate that the arithmetic was built on,
          each one either established or admittedly not. */}
      <Section label={t.risks.whatRaisesIt}>
        <ul className="flex flex-col gap-1.5">
          <Raiser
            level={data.internet_exposure}
            yes="Reachable from the internet"
            no="Not reachable from the internet"
            unknown="Internet exposure not established"
          />
          <Raiser
            level={data.data_sensitivity}
            yes="Holds data you marked sensitive"
            no="Holds nothing marked sensitive"
            unknown="Data sensitivity not declared"
          />
          <Raiser
            level={data.asset_criticality}
            yes="Runs something you marked business-critical"
            no="Not marked business-critical"
            unknown="Business criticality not declared"
          />
        </ul>
      </Section>

      {scenario ? (
        <>
          {data.path.length > 0 && (
            <Section label={t.risks.routeLabel}>
              <AttackPathRoute steps={data.path} />
              {/* A route is a claim about how an environment is wired as of a
                  reading. Without this, one that survived the latest scan and
                  one nothing has re-checked since Tuesday look the same. */}
              <p className="mt-3 text-xs text-muted-foreground">
                {data.observed_at
                  ? t.risks.lastSeen.replace(
                      "{when}",
                      formatRelative(data.observed_at),
                    )
                  : t.risks.lastSeenUnknown}
              </p>
            </Section>
          )}
        </>
      ) : (
        ownFinding && <Fix findingId={ownFinding.id} />
      )}

      {/* The part the list cannot show: a route scored above the findings
          inside it is an assertion until its members are named. */}
      <Section
        label={scenario ? t.risks.builtFrom : t.risks.builtFromFindingLabel}
      >
        {data.findings.length === 0 ? (
          <EmptyState
            icon={CircleIcon}
            title={t.risks.noMembers}
            detail={t.risks.noMembersDetail}
          />
        ) : (
          <ul className="flex flex-col gap-2">
            {data.findings.map((finding) => (
              <li key={finding.id} className="rounded-lg border p-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge level={finding.severity} size="sm" />
                  <code className="truncate font-mono text-[11px] text-meta-foreground">
                    {finding.rule_id}
                  </code>
                </div>
                {/* The title is the link, not the box: the accessible name of
                    a link should be what it opens, not the box's contents. */}
                <Link
                  to={`/findings/${finding.id}`}
                  className="mt-1 block text-[13px] font-medium text-foreground underline-offset-4 hover:underline"
                >
                  {finding.title}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}

/**
 * The score, and the two numbers it was built from.
 *
 * A scenario is floored at its worst member and amplified for being short, and
 * showing it the six weighted components would invite the reader to check
 * numbers nobody computed.
 */
function Score({ risk }: { risk: RiskDetail }) {
  const t = useT();
  const scenario = risk.kind !== "FINDING";
  const breakdown = risk.score_breakdown ?? {};
  const components = breakdown.components ?? {};
  const capped = (breakdown.uncapped ?? 0) > 100;

  return (
    <div className="flex gap-4 rounded-lg border bg-muted/30 p-3">
      <div className="shrink-0 text-center">
        <p className="font-mono text-3xl font-semibold leading-none text-foreground">
          {Number(risk.risk_score).toFixed(0)}
        </p>
        <p className="mt-1 text-[10px] uppercase tracking-[0.12em] text-meta-foreground">
          {t.risks.riskScore}
        </p>
      </div>

      <dl className="min-w-0 flex-1 flex-col gap-1 text-xs">
        {scenario ? (
          <>
            <Line
              label={t.risks.worstMember}
              value={breakdown.worst_member ?? "—"}
            />
            <Line
              label={t.risks.amplifier}
              value={`+${breakdown.amplifier ?? 0}`}
            />
            <Line label="Hops" value={breakdown.hops ?? risk.path.length} />
            {capped && (
              <p className="mt-1 text-[11px] text-muted-foreground">
                {breakdown.uncapped} before the ceiling. {t.risks.cappedNote}
              </p>
            )}
          </>
        ) : (
          Object.entries(components).map(([name, component]) => (
            <Line
              key={name}
              label={`${name.replace(/_/g, " ")} (${component.value} × ${component.weight})`}
              value={component.contribution.toFixed(1)}
            />
          ))
        )}
      </dl>
    </div>
  );
}

/**
 * The command, and what it will and will not do.
 *
 * Fetched from the member finding rather than carried on the risk: the fix
 * belongs to the rule that raised the finding, and the risk is what that
 * finding means. One request, cached under the key the finding page uses.
 */
function Fix({ findingId }: { findingId: string }) {
  const t = useT();
  const { data } = useQuery({
    queryKey: ["finding", findingId],
    queryFn: () =>
      api.get<FindingDetail>(`/api/v1/findings/${findingId}`).then((r) => r.data),
    staleTime: 60_000,
    retry: false,
  });

  if (!data) return <Skeleton className="h-24 w-full" />;

  const cli = data.remediation_spec?.cli ?? [];

  return (
    <Section label={t.risks.severingIt}>
      {cli.length > 0 ? (
        <CodeBlock code={cli.join("\n")} />
      ) : (
        <p className="text-[13px] leading-relaxed text-muted-foreground">
          {data.remediation}
        </p>
      )}

      <p className="mt-2 text-[11px] leading-relaxed text-meta-foreground">
        {t.risks.onlyAScanCloses}
      </p>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <TrackFix
          findingId={data.id}
          status={data.status}
          effortMinutes={data.estimated_effort_minutes}
        />
        {/* Accepting a risk writes an audit record with the reason it was
            accepted, and the field for that reason is on the finding. A button
            here would either ask for it in a drawer that has no room, or write
            an empty justification. */}
        <Link
          to={`/findings/${data.id}`}
          className={buttonVariants({ variant: "outline", size: "sm" })}
        >
          {t.risks.openTheFinding}
        </Link>
      </div>
    </Section>
  );
}

function Section({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <section>
      <h3 className="text-[11px] font-medium uppercase tracking-[0.12em] text-meta-foreground">
        {label}
      </h3>
      <div className="mt-2">{children}</div>
    </section>
  );
}

function Line({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="min-w-0 truncate text-muted-foreground">{label}</dt>
      <dd className="shrink-0 font-mono font-medium text-foreground">{value}</dd>
    </div>
  );
}

/**
 * One input to the score, in the reader's terms.
 *
 * UNKNOWN is its own state and reads as a gap rather than as a no: an asset
 * nobody classified is not an asset holding nothing, and the hollow mark says
 * which of the two this is.
 */
function Raiser({
  level,
  yes,
  no,
  unknown,
}: {
  level: Level;
  yes: string;
  no: string;
  unknown: string;
}) {
  const raised = level === "CRITICAL" || level === "HIGH";
  const gap = level === "UNKNOWN";

  return (
    <li className="flex items-start gap-2 text-[13px]">
      {gap ? (
        <CircleIcon className="mt-0.5 size-3.5 shrink-0 text-unknown" aria-hidden />
      ) : (
        <CheckIcon
          className={cn(
            "mt-0.5 size-3.5 shrink-0",
            raised ? "text-critical" : "text-muted-foreground/50",
          )}
          aria-hidden
        />
      )}
      <span className={gap ? "text-muted-foreground" : "text-foreground"}>
        {gap ? unknown : raised ? yes : no}
      </span>
    </li>
  );
}
