import { Link } from "react-router-dom";

import type { ExposureMapData, PostureReading } from "@/lib/types";
import { useT } from "@/i18n";
import { ScoreRing } from "@/components/ScoreRing";
import { ScoreDelta } from "@/components/ScoreDelta";
import { ScoreTrend } from "@/components/ScoreTrend";
import { ExposureMap } from "@/components/dashboard/ExposureMap";
import { Skeleton } from "@/components/ui/skeleton";

/**
 * Where the estate stands, and what it is exposed through.
 *
 * Two panels became one: a score card and a posture-trend card that answered
 * halves of the same question, stacked (docs/UI_REDESIGN.md §4.1). The arc is
 * the proportion before the digits are read; the map beside it is what the
 * number is *about*, which a sparkline could never say.
 *
 * The gradient is the one place in this theme a gradient appears — two large,
 * very low-alpha washes — and it does not spread. Everything else takes its
 * depth from the fill step between page, panel and row.
 */
export function DashboardHero({
  score,
  delta,
  history,
  map,
  omitted,
  loadingMap,
  routes,
  entryPoints,
  sensitiveTargets,
}: {
  score: number;
  delta: number | null;
  history: PostureReading[];
  map: ExposureMapData | undefined;
  omitted: number;
  loadingMap: boolean;
  /** Routes traced, for the one line the attack-path panel is reduced to. */
  routes: number | undefined;
  entryPoints: number | undefined;
  sensitiveTargets: number | undefined;
}) {
  const t = useT();

  return (
    <section
      aria-labelledby="posture-score"
      className="relative overflow-hidden rounded-xl border bg-card"
    >
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(60% 80% at 12% 0%, color-mix(in oklab, var(--color-primary) 7%, transparent), transparent 70%), radial-gradient(50% 70% at 88% 100%, color-mix(in oklab, var(--sev-critical) 5%, transparent), transparent 70%)",
        }}
      />

      <div className="relative grid gap-6 p-5 lg:grid-cols-[240px_1fr]">
        <div className="flex flex-col items-center gap-2 lg:items-start">
          <h2
            id="posture-score"
            className="text-[11px] font-medium uppercase tracking-[0.12em] text-meta-foreground"
          >
            {t.dashboard.securityScore}
          </h2>
          <ScoreRing score={score} />
          <ScoreDelta delta={delta} />
          {/* The trend card this panel absorbed. §4.1 leaves the hero's third
              column undecided and the mockup draws no line at all; dropping it
              outright would take the only view of movement out of the product,
              so it stays here, small, under the number it is about. */}
          <div className="w-full">
            <ScoreTrend history={history} />
          </div>
        </div>

        <div className="flex min-w-0 flex-col gap-2 lg:border-l lg:pl-6">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h3 className="text-[11px] font-medium uppercase tracking-[0.12em] text-meta-foreground">
              {t.dashboard.exposureMap}
            </h3>
            {entryPoints !== undefined && (
              <p className="text-xs text-meta-foreground">
                <span className="font-mono">{entryPoints}</span>{" "}
                {t.dashboard.mapReachable}
              </p>
            )}
          </div>

          {loadingMap ? (
            <Skeleton className="min-h-40 w-full flex-1" />
          ) : (
            <ExposureMap map={map} omitted={omitted} className="flex-1" />
          )}

          {/* One line, not a section. The attack-path panel it replaces was
              empty for most tenants and took a panel's worth of the page to
              say so. */}
          <AttackPathLine
            routes={routes}
            entryPoints={entryPoints}
            sensitiveTargets={sensitiveTargets}
          />
        </div>
      </div>
    </section>
  );
}

function AttackPathLine({
  routes,
  entryPoints,
  sensitiveTargets,
}: {
  routes: number | undefined;
  entryPoints: number | undefined;
  sensitiveTargets: number | undefined;
}) {
  const t = useT();
  if (routes === undefined) return null;

  if (routes > 0) {
    return (
      <p className="text-xs text-muted-foreground">
        <span className="font-mono">{routes}</span> {t.dashboard.routesTraced}{" "}
        <Link
          to="/attack-paths"
          className="font-medium text-foreground underline underline-offset-2"
        >
          {t.dashboard.seeRoutes}
        </Link>
      </p>
    );
  }

  // Why there is no route matters more than that there is none: nothing
  // classified as sensitive is a gap in what CloudGuard was told, and a clean
  // "no attack paths" would read as reassurance.
  const reason =
    sensitiveTargets === 0
      ? t.dashboard.noRoutesUnclassified
      : entryPoints === 0
        ? t.dashboard.noRoutesNothingExposed
        : t.dashboard.noRoutesTraced;

  return <p className="text-xs text-muted-foreground">{reason}</p>;
}
