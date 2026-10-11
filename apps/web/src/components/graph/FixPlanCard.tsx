import type { ReactNode } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ListChecksIcon, ScissorsIcon } from "lucide-react";

import type { FixPlan } from "@/lib/types";
import { toast } from "sonner";

import { useT } from "@/i18n";
import { InfoTip } from "@/components/common/InfoTip";
import { Button } from "@/components/ui/button";
import { HowToFix } from "@/components/graph/HowToFix";
import { cutFixQuery } from "@/components/graph/graphQueries";
import { useTrackAll } from "@/lib/remediation";
import { useIsDemo } from "@/lib/useDemo";

/**
 * What to do first, before the drawing (DECISIONS.md §245).
 *
 * The page opened on three counts, a canvas and a list, and the best cut sat a
 * tab away. This leads with the answer: the changes that close the routes, in
 * the order to make them, each with what it closes once the ones before it are
 * made. "Try this plan" puts them in the simulator, so the drawing is the proof
 * rather than the first thing a reader has to work out.
 *
 * Never "the fewest": the plan is picked one change at a time and only its
 * counts are exact.
 */
export function FixPlanCard({
  plan,
  entryPoints,
  sensitiveTargets,
  onTry,
  trying,
  progress,
}: {
  plan: FixPlan;
  entryPoints: number;
  sensitiveTargets: number;
  /** Load every change into the simulator, in plan order. */
  onTry: () => void;
  /** Whether the simulator holds exactly this plan already. */
  trying: boolean;
  /** Whether it is getting better, from the route ledger (§249). */
  progress?: ReactNode;
}) {
  const t = useT();
  const total = plan.total_routes;
  const closed = total - plan.remaining;
  const lastIndex = plan.cuts.length - 1;
  const handOver = useHandOver(plan);
  const demo = useIsDemo();

  return (
    <section
      aria-labelledby="fix-plan-title"
      className="flex flex-col gap-3 rounded-xl bg-card p-4 ring-1 ring-foreground/10"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 flex-col gap-1">
          <div className="flex items-center gap-1">
            <h2 id="fix-plan-title" className="text-heading font-semibold">
              {plan.cuts.length === 0
                ? t.attackPaths.planNone
                : t.attackPaths.planHeadline(plan.cuts.length, closed, total)}
            </h2>
            <InfoTip label={t.attackPaths.planHelpLabel}>{t.attackPaths.planHelpExplain}</InfoTip>
          </div>
          <p className="text-body text-muted-foreground">
            {t.attackPaths.planContext(total, entryPoints, sensitiveTargets)}
          </p>
          {progress}
        </div>
        {plan.cuts.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {!demo && (
              <Button
                variant="outline"
                aria-disabled={handOver.isPending || undefined}
                onClick={() => {
                  if (!handOver.isPending) handOver.mutate();
                }}
              >
                <ListChecksIcon data-icon="inline-start" />
                {t.attackPaths.planTrackAll}
              </Button>
            )}
            <Button variant={trying ? "outline" : "default"} onClick={onTry} aria-pressed={trying}>
              <ScissorsIcon data-icon="inline-start" />
              {trying ? t.attackPaths.planTrying : t.attackPaths.planTry}
            </Button>
          </div>
        )}
      </div>

      {plan.cuts.length > 0 && (
        <ol className="flex flex-col divide-y divide-border">
          {plan.cuts.map((cut, index) => (
            <li
              key={`${cut.source.id}|${cut.relationship}|${cut.target.id}`}
              className="flex flex-col gap-1 py-2 first:pt-0 last:pb-0"
            >
              <div className="flex items-baseline gap-3">
                <span
                  aria-hidden
                  className="flex size-5 shrink-0 items-center justify-center rounded-full bg-muted text-caption font-medium tabular-nums"
                >
                  {index + 1}
                </span>
                <p className="min-w-0 flex-1 text-body">{cut.detail}</p>
                <p className="shrink-0 text-meta text-muted-foreground tabular-nums">
                  {index === 0
                    ? t.attackPaths.planCutCloses(cut.closes.length)
                    : index === lastIndex && plan.remaining === 0
                      ? t.attackPaths.planClosesLast(cut.closes.length)
                      : t.attackPaths.planClosesMore(cut.closes.length)}
                </p>
              </div>
              <HowToFix
                className="pl-8"
                link={{
                  source: cut.source.id,
                  relationship: cut.relationship,
                  target: cut.target.id,
                }}
              />
            </li>
          ))}
        </ol>
      )}

      {plan.remaining > 0 && (
        <p className="text-meta text-muted-foreground">
          {plan.cuts.length === 0
            ? t.attackPaths.planNoneDetail(plan.remaining)
            : t.attackPaths.planRemaining(plan.remaining)}
        </p>
      )}
    </section>
  );
}

/**
 * Track every open finding on the plan's changes in one step (§252): read how
 * to make each change, collect the findings on its two ends nobody tracks yet,
 * and queue them together. Said as "the findings on these changes", never as
 * the changes themselves, which only a scan confirms were made.
 */
function useHandOver(plan: FixPlan) {
  const t = useT();
  const client = useQueryClient();
  const trackAll = useTrackAll();
  return useMutation({
    mutationFn: async () => {
      const fixes = await Promise.all(
        plan.cuts.map((cut) =>
          client.query(
            cutFixQuery({
              source: cut.source.id,
              relationship: cut.relationship,
              target: cut.target.id,
            }),
          ),
        ),
      );
      const ids = [
        ...new Set(fixes.flatMap((fix) => fix.findings.filter((f) => !f.tracked).map((f) => f.id))),
      ];
      if (ids.length === 0) {
        toast.info(t.attackPaths.planNothingToTrack);
        return;
      }
      await trackAll.mutateAsync(ids);
      void client.invalidateQueries({ queryKey: ["attack-paths", "fix"] });
    },
  });
}
