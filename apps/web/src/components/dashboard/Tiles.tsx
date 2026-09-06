import { Link } from "react-router-dom";

import { useT } from "@/i18n";
import { cn } from "@/lib/format";

/**
 * The four numbers the overview is answerable for.
 *
 * They replace a strip of five severity counts, which was the same set of
 * findings the panels below already drew twice. These four are not one set
 * counted four ways: what is open, how much of it is critical *on its asset*,
 * how much of the estate the opinion was formed from, and whether anything is
 * actually being closed.
 */
export function DashboardTiles({
  openRisks,
  critical,
  high,
  conclusive,
  evaluated,
  verified,
}: {
  openRisks: number;
  critical: number;
  high: number;
  conclusive: number;
  evaluated: number;
  verified: number;
}) {
  const t = useT();
  const assessed = evaluated > 0 ? Math.round((conclusive / evaluated) * 100) : null;

  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <Tile
        label={t.dashboard.tileOpenRisks}
        value={String(openRisks)}
        detail={t.dashboard.tileOpenRisksDetail}
        to="/risks"
      />
      <Tile
        label={t.dashboard.tileCriticalOnAsset}
        value={String(critical)}
        tone={critical > 0 ? "text-critical" : undefined}
        detail={t.dashboard.tileCriticalDetail.replace("{count}", String(high))}
        to="/risks?level=CRITICAL"
      />
      <Tile
        label={t.dashboard.tileAssessed}
        // Never a zero when nothing has been evaluated: no checks ran is not
        // the same statement as none of them concluded.
        value={assessed === null ? "—" : `${assessed}%`}
        tone={assessed !== null && assessed < 80 ? "text-medium" : undefined}
        detail={t.dashboard.tileAssessedDetail
          .replace("{conclusive}", String(conclusive))
          .replace("{evaluated}", String(evaluated))}
        to="/scans"
      />
      <Tile
        label={t.dashboard.tileVerified}
        value={String(verified)}
        tone={verified > 0 ? "text-ok" : undefined}
        detail={t.dashboard.tileVerifiedDetail}
        to="/remediation"
      />
    </div>
  );
}

function Tile({
  label,
  value,
  detail,
  tone,
  to,
}: {
  label: string;
  value: string;
  detail: string;
  tone?: string;
  to: string;
}) {
  return (
    <Link
      to={to}
      className="rounded-xl border bg-card px-4 py-3.5 transition-colors hover:bg-accent/40 focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
    >
      <p className="text-[11px] font-medium uppercase tracking-[0.12em] text-meta-foreground">
        {label}
      </p>
      <p
        className={cn(
          "mt-2 font-mono text-3xl font-semibold leading-none",
          tone ?? "text-foreground",
        )}
      >
        {value}
      </p>
      <p className="mt-2 text-xs text-meta-foreground">{detail}</p>
    </Link>
  );
}
