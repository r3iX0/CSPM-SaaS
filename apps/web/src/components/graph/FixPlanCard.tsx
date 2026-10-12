import type { ReactNode } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowRightIcon, ListChecksIcon, ScissorsIcon } from "lucide-react";

import type { FixPlan } from "@/lib/types";
import { toast } from "sonner";

import { useT } from "@/i18n";
import { cn } from "@/lib/format";
import { InfoTip } from "@/components/common/InfoTip";
import { Button } from "@/components/ui/button";
import { HowToFix } from "@/components/graph/HowToFix";
import { Named } from "@/components/graph/Named";
import { cutFixQuery } from "@/components/graph/graphQueries";
import { useTrackAll } from "@/lib/remediation";
import { useIsDemo } from "@/lib/useDemo";

/**
 * What to do first, in a panel over the drawing (DECISIONS.md §245, §259).
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
  className,
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
  className?: string;
}) {
  const t = useT();
  const total = plan.total_routes;
  const closed = total - plan.remaining;
  const lastIndex = plan.cuts.length - 1;
  const handOver = useHandOver(plan);
  const demo = useIsDemo();

  return (
    <section aria-labelledby="fix-plan-title" className={cn("flex flex-col", className)}>
      {/* The answer, as a number and a bar: how many routes the plan leaves,
          and how much of that each change does (§259). */}
      <div className="mx-3 flex flex-col gap-3 rounded-xl bg-foreground/[0.035] p-4 ring-1 ring-border">
        <div className="flex items-center gap-1">
          <h2 id="fix-plan-title" className="text-title font-semibold tracking-tight">
            {plan.cuts.length === 0
              ? t.attackPaths.planNone
              : t.attackPaths.planHeadline(plan.cuts.length, closed, total)}
          </h2>
          <InfoTip label={t.attackPaths.planHelpLabel}>{t.attackPaths.planHelpExplain}</InfoTip>
        </div>
        {plan.cuts.length > 0 && (
          <>
            <div aria-hidden className="flex items-center gap-2.5">
              <span className="text-stat font-semibold tracking-tight text-muted-foreground tabular-nums">
                {total}
              </span>
              <ArrowRightIcon className="size-5 text-muted-foreground" />
              <span
                className={cn(
                  "text-stat font-semibold tracking-tight tabular-nums",
                  plan.remaining === 0 ? "text-ok" : "text-foreground",
                )}
              >
                {plan.remaining}
              </span>
              <span className="text-meta text-muted-foreground">{t.attackPaths.planLeft}</span>
            </div>
            <div aria-hidden className="flex gap-0.5">
              {plan.cuts.map((cut, index) => (
                <span
                  key={`${cut.source.id}|${cut.relationship}|${cut.target.id}`}
                  style={{ flexGrow: cut.closes.length, opacity: 1 - index * 0.14 }}
                  className="h-2 min-w-1 rounded-full bg-primary"
                />
              ))}
              {plan.remaining > 0 && (
                <span
                  style={{ flexGrow: plan.remaining }}
                  className="h-2 min-w-1 rounded-full bg-foreground/12"
                />
              )}
            </div>
          </>
        )}
        <p className="text-meta text-muted-foreground">
          {t.attackPaths.planContext(total, entryPoints, sensitiveTargets)}
        </p>
        {progress}
      </div>

      {plan.cuts.length > 0 && (
        <ol className="flex flex-col px-4 pt-4">
          {plan.cuts.map((cut, index) => (
            <li
              key={`${cut.source.id}|${cut.relationship}|${cut.target.id}`}
              // Told in plan order when it is tried: each change lights a step
              // after the one before (§256). One request for the whole plan.
              className={cn("flex gap-3", trying && `cg-reveal cg-step-${Math.min(index, 7)}`)}
            >
              <span className="flex w-5 shrink-0 flex-col items-center">
                <span
                  aria-hidden
                  className={cn(
                    "flex size-5 items-center justify-center rounded-full text-caption font-semibold tabular-nums",
                    index === 0
                      ? "bg-primary text-primary-foreground"
                      : "bg-foreground/6 text-muted-foreground ring-1 ring-border",
                  )}
                >
                  {index + 1}
                </span>
                {index < lastIndex && <span aria-hidden className="my-1 w-px flex-1 bg-border" />}
              </span>
              <div
                className={cn("flex min-w-0 flex-1 flex-col gap-1", index < lastIndex && "pb-4")}
              >
                <p className="text-body text-muted-foreground">
                  <Named text={cut.detail} names={[cut.source.name, cut.target.name]} />
                </p>
                <p
                  className={cn(
                    "text-meta tabular-nums",
                    index === 0 ? "font-medium text-ok" : "text-muted-foreground",
                  )}
                >
                  {index === 0
                    ? t.attackPaths.planCutCloses(cut.closes.length)
                    : index === lastIndex && plan.remaining === 0
                      ? t.attackPaths.planClosesLast(cut.closes.length)
                      : t.attackPaths.planClosesMore(cut.closes.length)}
                </p>
                <HowToFix
                  link={{
                    source: cut.source.id,
                    relationship: cut.relationship,
                    target: cut.target.id,
                  }}
                />
              </div>
            </li>
          ))}
        </ol>
      )}

      {plan.remaining > 0 && (
        <p className="px-4 pt-3 text-meta text-muted-foreground">
          {plan.cuts.length === 0
            ? t.attackPaths.planNoneDetail(plan.remaining)
            : t.attackPaths.planRemaining(plan.remaining)}
        </p>
      )}

      {/* The plan's actions stay at the foot of the panel while its steps
          scroll under them. */}
      {plan.cuts.length > 0 && (
        <div className="sticky bottom-0 mt-4 flex gap-2 border-t border-border bg-popover/95 p-3 backdrop-blur-md">
          <Button
            className="flex-1 shadow-lg shadow-primary/25"
            variant={trying ? "outline" : "default"}
            onClick={onTry}
            aria-pressed={trying}
          >
            <ScissorsIcon data-icon="inline-start" />
            {trying ? t.attackPaths.planTrying : t.attackPaths.planTry}
          </Button>
          {!demo && (
            <Button
              variant="outline"
              size="icon"
              aria-label={t.attackPaths.planTrackAll}
              title={t.attackPaths.planTrackAll}
              aria-disabled={handOver.isPending || undefined}
              onClick={() => {
                if (!handOver.isPending) handOver.mutate();
              }}
            >
              <ListChecksIcon />
            </Button>
          )}
        </div>
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
