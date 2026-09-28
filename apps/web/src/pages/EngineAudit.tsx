import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { api } from "@/lib/api";
import type { EngineAudit } from "@/lib/types";
import { cn, formatDate, formatSeconds } from "@/lib/format";
import { ENGINE_AUDIT_ICON } from "@/lib/icons";
import { StatStrip } from "@/components/common/StatStrip";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/** What each kind of disagreement means, in the words a reader acts on. */
const KIND: Record<string, { label: string; meaning: string }> = {
  NATIVE_MISSED: {
    label: "Prowler failed, Cleave passed",
    meaning: "Possibly a case Cleave's rule is missing. Read these first.",
  },
  PROWLER_MISSED: {
    label: "Cleave failed, Prowler passed",
    meaning: "Possibly Cleave is stricter than it should be, or Prowler is lax.",
  },
  NATIVE_UNKNOWN: {
    label: "Cleave could not tell",
    meaning: "Prowler reached a verdict where Cleave's collectors could not read.",
  },
  PROWLER_UNKNOWN: {
    label: "Prowler could not tell",
    meaning: "Cleave reached a verdict where Prowler could not read.",
  },
};

/**
 * Where the two engines checked each other (DECISIONS.md §150).
 *
 * Every scan runs Cleave's own rules and, beside them, Prowler's checks. Where
 * a rule and the checks answering the same question reach different verdicts
 * on the same asset, the scan records it. An expected disagreement -- the two
 * ask slightly different questions, and the catalogue says why -- is listed
 * apart. An unexpected one is a bug in one engine or the other, and this page
 * exists so somebody goes and finds out which.
 */
export function EngineAuditPage() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["engine-audit"],
    queryFn: () => api.get<EngineAudit>("/api/v1/engine-audit").then((r) => r.data),
  });

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Engine audit"
        description="Where Cleave's rules and the extended checks (Prowler) disagreed about the same asset on the latest scan."
      />

      {isLoading && <CardsSkeleton />}

      {error && (
        <ErrorState
          title="Could not load the engine audit"
          detail="Cleave could not reach its own API."
          impact="Nothing about your environment has changed — this is a problem displaying it."
          onRetry={() => refetch()}
        />
      )}

      {data && !data.engine.enabled && (
        <EmptyState
          icon={ENGINE_AUDIT_ICON}
          title="The extended checks are not switched on"
          detail={`This deployment has not started the scanner service, so scans run Cleave's ${data.engine.native_rules} rules alone and there is nothing to compare them against.`}
        />
      )}

      {data && data.engine.enabled && !data.scan && (
        <EmptyState
          icon={ENGINE_AUDIT_ICON}
          title="No audited scan yet"
          detail="The audit appears after the first scan in which the extended checks ran."
        />
      )}

      {data?.scan && (
        <>
          <StatStrip
            stats={[
              {
                label: "Unexpected disagreements",
                value: data.summary.unexpected,
                alert: data.summary.unexpected > 0,
              },
              {
                label: "Expected disagreements",
                value: data.summary.total - data.summary.unexpected,
              },
              { label: "Extended checks", value: data.engine.checks_enabled },
              { label: "Cross-checking a rule", value: data.engine.checks_covered },
            ]}
          />
          <p className="text-xs text-muted-foreground">
            Scan of{" "}
            <Link to="/scans" className="text-primary hover:underline">
              {data.scan.completed_at ? formatDate(data.scan.completed_at) : data.scan.id}
            </Link>{" "}
            · Prowler {data.engine.prowler_version}
          </p>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">What the extended checks ran</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="flex flex-col divide-y divide-border">
                {data.assessments.map((run, i) => (
                  <li key={`${run.scope ?? run.provider}-${i}`} className="flex flex-col gap-1 py-2">
                    <div className="flex flex-wrap items-center gap-2 text-sm">
                      <span className="font-medium">{run.scope ?? "Scope"}</span>
                      <Badge
                        variant={run.outcome === "COMPLETE" ? "secondary" : "outline"}
                        className={cn(run.outcome === "FAILED" && "text-critical")}
                      >
                        {run.outcome.toLowerCase()}
                      </Badge>
                      <span className="text-xs tabular-nums text-muted-foreground">
                        {run.checks_completed} of {run.checks_requested} checks ·{" "}
                        {run.result_count} results
                        {run.duration_seconds != null &&
                          ` · ${formatSeconds(run.duration_seconds)}`}
                      </span>
                    </div>
                    {run.fatal && <p className="text-xs text-critical">{run.fatal}</p>}
                    {run.services_unread.length > 0 && (
                      <p className="text-xs text-muted-foreground">
                        Could not read {run.services_unread.join(", ")} — those checks read as
                        unknown, never as passing.
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          {data.pairs.length === 0 ? (
            <EmptyState
              icon={ENGINE_AUDIT_ICON}
              title="The engines agreed"
              detail="On every asset both engines judged, Cleave's rules and their Prowler counterparts reached the same verdict."
            />
          ) : (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Disagreements by rule</CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="flex flex-col divide-y divide-border">
                  {data.pairs.map((pair) => (
                    <li
                      key={`${pair.rule_id}-${pair.expected}`}
                      className="flex flex-col gap-1 py-2.5"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-medium">
                          {pair.rule_name ?? pair.rule_id}
                        </span>
                        <code className="font-mono text-[11px] text-muted-foreground">
                          {pair.rule_id}
                        </code>
                        <Badge variant={pair.expected ? "secondary" : "outline"}>
                          {pair.expected ? "expected" : "unexpected"}
                        </Badge>
                        <span className="text-xs tabular-nums text-muted-foreground">
                          {pair.count} asset{pair.count === 1 ? "" : "s"}
                        </span>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Against{" "}
                        {pair.checks.map((check, i) => (
                          <span key={check}>
                            {i > 0 && ", "}
                            <code className="font-mono text-[11px]">{check}</code>
                          </span>
                        ))}
                      </p>
                      {pair.note && (
                        <p className="text-xs leading-relaxed text-muted-foreground">
                          {pair.note}
                        </p>
                      )}
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}

          {data.divergences.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Each disagreement</CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="flex flex-col divide-y divide-border">
                  {data.divergences.map((row, i) => (
                    <li
                      key={`${row.rule_id}-${row.provider_resource_id ?? "scope"}-${i}`}
                      className="flex flex-col gap-0.5 py-2"
                    >
                      <div className="flex flex-wrap items-center gap-2 text-sm">
                        {row.resource ? (
                          <Link
                            to={`/assets/${row.resource.id}`}
                            className="font-medium text-primary hover:underline"
                          >
                            {row.resource.name ?? row.provider_resource_id}
                          </Link>
                        ) : (
                          <span className="font-medium">
                            {row.provider_resource_id ?? "The scope as a whole"}
                          </span>
                        )}
                        <span className="text-xs text-muted-foreground">
                          {KIND[row.kind]?.label ?? row.kind}
                        </span>
                        {row.expected && <Badge variant="secondary">expected</Badge>}
                      </div>
                      <p className="text-xs text-muted-foreground">
                        <code className="font-mono text-[11px]">{row.rule_id}</code> said{" "}
                        {row.native_state.toLowerCase()}; Prowler said{" "}
                        {row.prowler_state.toLowerCase()}. {!row.expected && KIND[row.kind]?.meaning}
                      </p>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
