import { Link } from "react-router-dom";

import { SeverityBadge } from "@/components/security/SeverityBadge";
import { useCountUp } from "@/lib/motion";
import { cn } from "@/lib/format";

const LEVELS = [
  { level: "CRITICAL", label: "Critical" },
  { level: "HIGH", label: "High" },
  { level: "MEDIUM", label: "Medium" },
  { level: "LOW", label: "Low" },
] as const;

/**
 * What is open, by how serious it is on the asset it was found on — and which
 * way each of those has been moving.
 *
 * A strip rather than four cards. These are one measurement split four ways,
 * and giving each its own bordered box makes the reader compare containers
 * before they compare numbers.
 *
 * UNKNOWN sits at the end and is not a fifth severity: it is the count of
 * checks that reached no verdict, which is a different kind of fact and links
 * somewhere different. It is here rather than further down because a reader
 * tallying what is wrong must see what could not be answered in the same
 * glance. UNKNOWN is never a pass.
 */
export function SeverityStrip({
  counts,
  unknown,
}: {
  counts: Record<string, number>;
  unknown: number;
}) {
  return (
    <section
      aria-label="Open findings by severity"
      className="grid grid-cols-2 gap-px overflow-hidden rounded-xl bg-border ring-1 ring-foreground/10 sm:grid-cols-3 lg:grid-cols-5"
    >
      {LEVELS.map(({ level, label }) => (
        <Tile
          key={level}
          to={`/findings?severity=${level}`}
          badge={<SeverityBadge level={level}>{label}</SeverityBadge>}
          value={counts[level] ?? 0}
        />
      ))}

      <Tile
        to="/scans"
        badge={<SeverityBadge level="UNKNOWN">No verdict</SeverityBadge>}
        value={unknown}
      />
    </section>
  );
}

function Tile({
  to,
  badge,
  value,
}: {
  to: string;
  badge: React.ReactNode;
  value: number;
}) {
  const shown = Math.round(useCountUp(value));

  return (
    <Link
      to={to}
      className={cn(
        "flex flex-col gap-2.5 bg-card px-[18px] py-3.5 transition-colors hover:bg-muted/60",
        "focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring-inset focus-visible:ring-inset",
      )}
    >
      <span className="self-start">{badge}</span>
      {/* A zero is not an alarm: muted, so the eye lands on the counts that
          have something in them. */}
      <span
        className={cn(
          "text-[28px] leading-none font-semibold tabular-nums",
          value === 0 && "text-muted-foreground/60",
        )}
      >
        {shown}
      </span>
    </Link>
  );
}
