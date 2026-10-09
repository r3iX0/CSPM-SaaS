import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { useT } from "@/i18n";
import { api } from "@/lib/api";
import { cn } from "@/lib/format";
import type { ScoreMovement as Movement } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { InfoTip } from "@/components/common/InfoTip";
import { SeverityBadge } from "@/components/security/SeverityBadge";

/**
 * Why the score moved: the delta split into causes that add up to it (DECISIONS.md §235).
 *
 * A button beside the delta rather than a panel of its own, because the
 * question only arises once the number has moved, and the answer is a few lines.
 * The breakdown is read when the popover opens, not with the dashboard: it costs
 * a diff of two ledgers and the events between them, for a reader who asked.
 */
export function ScoreMovement() {
  const t = useT();
  return (
    <Popover>
      <PopoverTrigger
        render={
          <Button variant="link" size="sm" className="h-auto p-0 text-caption">
            {t.dashboard.movementWhy}
          </Button>
        }
      />
      <PopoverContent align="center" aria-label={t.dashboard.movementTitle} className="w-80">
        <MovementBody />
      </PopoverContent>
    </Popover>
  );
}

/** Mounted only while the popover is open, so nothing is fetched until it is. */
function MovementBody() {
  const t = useT();
  const { data, isPending, isError } = useQuery({
    queryKey: ["dashboard", "score-movement"],
    queryFn: () => api.get<Movement>("/api/v1/dashboard/score-movement").then((r) => r.data),
    staleTime: 60_000,
  });

  const heading = (
    <div className="flex items-center gap-1">
      <h3 className="text-body font-semibold">{t.dashboard.movementTitle}</h3>
      <InfoTip label={t.dashboard.movementExplainLabel}>{t.dashboard.movementExplain}</InfoTip>
    </div>
  );
  if (isPending) {
    return (
      <>
        {heading}
        <p className="text-meta text-muted-foreground">{t.dashboard.movementLoading}</p>
      </>
    );
  }
  if (isError) {
    return (
      <>
        {heading}
        <p className="text-meta text-muted-foreground">{t.dashboard.movementFailed}</p>
      </>
    );
  }
  if (!data.available || data.from_score === null || data.to_score === null) {
    return (
      <>
        {heading}
        <p className="text-meta text-muted-foreground">
          {data.reason === "not_recorded"
            ? t.dashboard.movementNotRecorded
            : t.dashboard.movementFirst}
        </p>
      </>
    );
  }

  return (
    <>
      {heading}
      <p className="text-meta text-muted-foreground">
        {t.dashboard.movementSince(data.from_score, data.to_score)}
      </p>
      <ul className="flex flex-col gap-2.5">
        {data.causes.map((cause) => (
          <li key={cause.cause} className="flex flex-col gap-1">
            <div className="flex items-baseline justify-between gap-3">
              <span className="text-meta font-medium">
                {t.dashboard.movementCauses[cause.cause]}
              </span>
              <Points points={cause.points} exact={cause.exact} />
            </div>
            <span className="text-caption text-muted-foreground">
              {t.dashboard.movementRisks(cause.risks)}
            </span>
            {cause.findings.length > 0 && (
              <ul className="flex flex-col gap-1">
                {cause.findings.map((finding) => (
                  <li key={finding.id} className="flex min-w-0 items-center gap-1.5">
                    <SeverityBadge level={finding.severity} size="sm" />
                    <Link
                      to={`/findings/${finding.id}`}
                      className="truncate text-caption underline-offset-2 hover:underline"
                    >
                      {finding.title}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ul>
    </>
  );
}

/** Signed points, in the score's terms: up is better. */
function Points({ points, exact }: { points: number; exact: number }) {
  const t = useT();
  const improved = exact > 0;
  const shown =
    points === 0 ? t.dashboard.movementUnderPoint : `${points > 0 ? "+" : "−"}${Math.abs(points)}`;
  return (
    <span
      className={cn(
        "shrink-0 text-meta font-medium tabular-nums",
        improved ? "text-ok" : "text-critical",
      )}
    >
      {shown}
    </span>
  );
}
