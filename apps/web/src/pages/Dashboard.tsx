import { useQuery } from "@tanstack/react-query";
import { m } from "motion/react";

import { ApiError, api, auth } from "@/lib/api";
import { supabaseSignOut } from "@/lib/supabase";
import type {
  ChangeEvent,
  ChokePoint,
  CloudAccount,
  ComplianceFramework,
  Dashboard,
  Scan,
} from "@/lib/types";
import { useT } from "@/i18n";
import { GettingStarted } from "@/components/dashboard/GettingStarted";
import { PostureHeader } from "@/components/dashboard/PostureHeader";
import { ScorePanel } from "@/components/dashboard/ScorePanel";
import { SeverityStrip } from "@/components/dashboard/SeverityStrip";
import { ComplianceSummary } from "@/components/dashboard/ComplianceSummary";
import { CoveragePanel } from "@/components/dashboard/CoveragePanel";
import { RegionPanel } from "@/components/dashboard/RegionPanel";
import { PriorityRisks } from "@/components/dashboard/PriorityRisks";
import { CutPanel } from "@/components/dashboard/CutPanel";
import { FixesProved } from "@/components/dashboard/FixesProved";
import { RecentChanges } from "@/components/dashboard/RecentChanges";
import { TodayStats } from "@/components/dashboard/TodayStats";
import { DashboardSkeleton, ErrorState, PageHeader } from "@/components/common/states";
import { Button } from "@/components/ui/button";
import { listContainer, listItem } from "@/lib/motion";
import { useRiskCount } from "@/lib/useRiskCount";
import { IN_FLIGHT } from "@/components/scans/status";

/**
 * The page that answers "how secure am I right now", read top to bottom as one
 * argument rather than as a wall of cards.
 *
 * The order is the argument, in three zones (DECISIONS.md §178):
 *
 *   where the posture stands        score and trend, the figures that qualify
 *                                   it (risks, routes, coverage), severity
 *   what to do next                 the ranked risks, the one link to cut
 *   the detail behind both          coverage, fixes proved, what moved,
 *                                   compliance, and where it all runs
 *
 * Each panel says what it is in a line; how it is measured is a question mark
 * beside its title (§166). Coverage is stated twice on purpose: as a figure
 * beside the score, which it qualifies, and in full below.
 *
 * Inventory counts — assets, subscriptions, resources — are deliberately not on
 * this page as headline figures. They are true and they answer a different
 * question, and every pixel one takes is a pixel not spent on what is wrong.
 *
 * Three requests, not one. The dashboard aggregate is a set of database
 * aggregates and answers quickly; attack paths cost a graph build and changes
 * are a windowed feed, so folding them into the primary payload would make the
 * numbers everybody came for wait on the two panels nobody scrolls to first.
 * Both fail quietly: a dashboard that cannot draw its last panel is still a
 * dashboard.
 */
export function DashboardPage() {
  const t = useT();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api.get<Dashboard>("/api/v1/dashboard").then((r) => r.data),
    refetchInterval: 20_000,
    retry: false, // a 401 will not fix itself; surface it immediately
  });

  const accounts = useQuery({
    queryKey: ["cloud-accounts"],
    queryFn: () => api.get<CloudAccount[]>("/api/v1/cloud-accounts").then((r) => r.data),
    retry: false,
  });

  // The same key the risks page reads, so the two agree on the link to cut.
  const chokes = useQuery({
    queryKey: ["attack-paths", "choke-points"],
    queryFn: () => api.get<ChokePoint[]>("/api/v1/attack-paths/choke-points").then((r) => r.data),
    retry: false,
  });

  const changes = useQuery({
    queryKey: ["dashboard-changes"],
    queryFn: () => api.get<ChangeEvent[]>("/api/v1/changes?days=7&limit=5").then((r) => r.data),
    retry: false,
  });

  const compliance = useQuery({
    queryKey: ["compliance"],
    queryFn: () => api.get<ComplianceFramework[]>("/api/v1/compliance").then((r) => r.data),
    retry: false,
  });

  // Whether a scan is in flight, which changes what the freshness pill means:
  // numbers about to move are not the same as numbers going stale.
  const scans = useQuery({
    queryKey: ["scans", "indicator"],
    queryFn: () => api.get<Scan[]>("/api/v1/scans?limit=5").then((r) => r.data),
    retry: false,
  });

  // The risks list's own count: the dashboard's bands hold finding risks
  // only, and the figure beside the score speaks for attack paths and
  // escalations too.
  const riskCount = useRiskCount();

  if (isLoading) return <DashboardSkeleton />;
  if (error) return <DashboardError error={error} onRetry={() => refetch()} />;
  if (!data) return null;

  if (!data.last_scan) {
    return (
      <div className="flex flex-col gap-4">
        <PageHeader
          title={t.dashboard.title}
          description="Your cloud posture, and what Cleave could see while forming it."
        />
        {/* No score is rendered before a scan exists. A number over no evidence
            is a number about nothing, and a reassuring one is worse. What the
            page offers instead is the way to one: the checklist, which is the
            whole of this screen until the first scan lands. */}
        <GettingStarted
          dashboard={data}
          accounts={Array.isArray(accounts.data) ? accounts.data : []}
          variant="full"
        />
      </div>
    );
  }

  const scanning = Array.isArray(scans.data)
    ? scans.data.some((scan) => IN_FLIGHT.includes(scan.status))
    : false;
  const gaps = Object.entries(data.last_scan.collection_errors ?? {});

  const lastReading = data.history?.[data.history.length - 1];

  return (
    // Three zones, read top to bottom (DECISIONS.md §178): where the posture
    // stands, what to do next, and the detail behind both. The panels arrive
    // in that order with a small stagger -- three hundredths of a second
    // between them, to give the eye a path down the page, not a performance.
    <m.div
      className="flex flex-col gap-6"
      variants={listContainer}
      initial="initial"
      animate="animate"
    >
      <m.div variants={listItem}>
        <PostureHeader
          scannedAt={data.last_scan.completed_at}
          staleHours={data.evidence_freshness?.stale_hours ?? null}
          scanning={scanning}
        />
      </m.div>

      {/* What is left to set up, until it is done or put away. */}
      <m.div variants={listItem}>
        <GettingStarted
          dashboard={data}
          accounts={Array.isArray(accounts.data) ? accounts.data : []}
          variant="compact"
        />
      </m.div>

      {/* 1 -- where the posture stands, and what it is made of */}
      <m.div variants={listItem} className="flex flex-col gap-4">
        <ScorePanel
          score={data.security_score}
          delta={data.score_delta}
          history={data.history ?? []}
          today={
            <TodayStats
              risks={riskCount}
              routes={lastReading?.attack_path_count ?? null}
              coverage={data.coverage.ratio}
            />
          }
        />
        <SeverityStrip counts={data.findings_by_severity} unknown={data.coverage.unknown} />
      </m.div>

      {/* 2 -- what to do next: the risks, and the one change that closes most */}
      <m.div
        variants={listItem}
        className="grid gap-4 lg:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]"
      >
        <PriorityRisks risks={data.top_risks} />
        <CutPanel
          chokes={Array.isArray(chokes.data) ? chokes.data : undefined}
          loading={chokes.isLoading}
          failed={chokes.isError}
        />
      </m.div>

      {/* 3 -- the detail: what the reading covers, what is being fixed, what
          moved, what it adds up to for somebody who reports on it, and where
          it all runs. The map keeps a full row; it needs the width. */}
      <m.div variants={listItem} className="grid gap-4 lg:grid-cols-2">
        <CoveragePanel
          ratio={data.coverage.ratio}
          unknown={data.coverage.unknown}
          conclusive={data.coverage.conclusive}
          categories={data.coverage.categories}
          context={data.coverage.context}
          gaps={gaps}
          freshness={data.evidence_freshness ?? null}
        />
        <FixesProved
          verified={data.verified_resolved_last_30_days}
          inProgress={data.findings_by_status?.IN_PROGRESS ?? 0}
          // `open_finding_count` counts in-progress findings as open too, so
          // they come off it here rather than being counted in both cells.
          open={Math.max(0, data.open_finding_count - (data.findings_by_status?.IN_PROGRESS ?? 0))}
        />
        <RecentChanges events={changes.data} loading={changes.isLoading} />
        <ComplianceSummary
          frameworks={Array.isArray(compliance.data) ? compliance.data : undefined}
          loading={compliance.isLoading}
        />
        {/* Absent until something is tied to a region. */}
        {data.regions?.some((region) => region.region !== null) && (
          <div className="lg:col-span-2">
            <RegionPanel regions={data.regions} />
          </div>
        )}
      </m.div>
    </m.div>
  );
}

/**
 * A failed dashboard load used to render "Something went wrong", which told the
 * reader nothing and sent them to the browser console. The API returns a
 * machine-readable code and a written message in every error envelope, so show
 * them — and for an expired session, offer the action that actually fixes it.
 */
function DashboardError({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const t = useT();
  const apiError = error instanceof ApiError ? error : null;
  const isAuth = apiError?.status === 401;

  return (
    <div className="mx-auto max-w-lg">
      <ErrorState
        title={isAuth ? "Your session has expired" : t.dashboard.couldNotLoad}
        detail={
          isAuth
            ? "Sign in again to continue — your data is untouched."
            : (apiError?.message ?? "The API could not be reached.")
        }
        impact={
          isAuth
            ? undefined
            : "This is a problem loading the page, not a change in your posture — nothing has been reassessed."
        }
        onRetry={isAuth ? undefined : onRetry}
        action={
          isAuth ? (
            <Button
              size="sm"
              onClick={() => {
                auth.signOut();
                void supabaseSignOut();
              }}
            >
              {t.dashboard.signInAgain}
            </Button>
          ) : apiError ? (
            <span className="font-mono text-xs text-muted-foreground">
              {apiError.code} · HTTP {apiError.status}
            </span>
          ) : undefined
        }
      />
    </div>
  );
}
