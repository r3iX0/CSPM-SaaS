import { motion } from "motion/react";
import { CheckIcon } from "lucide-react";

import { useT } from "@/i18n";
import { setupSteps, stepIndex, type SetupStage } from "@/lib/connectionStage";
import { DURATION, EASE_OUT } from "@/lib/motion";
import { setupCopy } from "@/lib/setupCopy";
import type { Provider } from "@/lib/types";
import { cn } from "@/lib/format";

/**
 * The steps, and where the customer is in them.
 *
 * The same rows as the empty state's preview, in the same words. Somebody who
 * read "what the three minutes look like" before starting should recognise the
 * list they are now standing inside, rather than meet a second, differently
 * worded account of the same flow.
 *
 * Only the current row carries its explanation. The rail used to print all
 * four, which made it the densest block on the page while saying the least
 * that was new: a step behind the reader is finished, and one ahead of them is
 * a title until they reach it. The connector between rows fills as steps are
 * done, so moving on reads as progress along one line.
 *
 * Four rows on Azure and three on AWS, because AWS has no consent step. A rail
 * with a permanently grey "Grant consent" row would read as a flow that is
 * stuck on something nobody is going to do.
 */
export function SetupRail({
  stage,
  provider,
}: {
  stage: SetupStage;
  provider: Provider;
}) {
  const t = useT();
  const copy = setupCopy(t, provider);
  const steps = setupSteps(provider);
  const current = stepIndex(stage, provider);
  const finished = stage === "done";
  // How far along, counting the current step as half-done: a bar that sits at
  // zero on the first screen reads as nothing having started.
  const progress = finished ? 1 : (current + 0.5) / steps.length;

  return (
    <nav aria-label={copy.railHeading} className="flex flex-col gap-5">
      <div>
        <div className="flex items-baseline justify-between gap-3 text-xs">
          <span className="font-medium text-foreground">{copy.railHeading}</span>
          <span className="tabular-nums text-muted-foreground">
            {t.connection.step} {Math.min(current + 1, steps.length)} {t.connection.of}{" "}
            {steps.length}
          </span>
        </div>
        <div className="mt-2.5 h-1 overflow-hidden rounded-full bg-muted" aria-hidden>
          <motion.div
            className={cn("h-full rounded-full", finished ? "bg-ok" : "bg-foreground")}
            initial={false}
            animate={{ width: `${progress * 100}%` }}
            transition={{ duration: DURATION.page / 1000, ease: EASE_OUT }}
          />
        </div>
      </div>

      <ol>
        {steps.map((step, index) => {
          const done = index < current || (index === current && finished);
          const active = index === current && !finished;
          const last = index === steps.length - 1;
          return (
            <li
              key={step.stage}
              aria-current={active ? "step" : undefined}
              // On a phone the rail sits above the panel, where four rows of
              // it would push the step itself below the fold: there it is the
              // bar and the current row, and the full list is for wider screens.
              className={cn(
                "relative gap-3 pb-5 last:pb-0 max-lg:pb-0",
                active ? "flex" : "hidden lg:flex",
              )}
            >
              {!last && (
                <span
                  className="absolute top-7 bottom-1 left-3 hidden w-px -translate-x-1/2 overflow-hidden bg-border lg:block"
                  aria-hidden
                >
                  <motion.span
                    className="absolute inset-0 origin-top bg-ok"
                    initial={false}
                    animate={{ scaleY: done ? 1 : 0 }}
                    transition={{ duration: DURATION.page / 1000, ease: EASE_OUT }}
                  />
                </span>
              )}
              <span
                className={cn(
                  "relative flex size-6 shrink-0 items-center justify-center rounded-full text-[11px] font-semibold tabular-nums transition-colors",
                  // `text-background`, not `text-white`: in dark mode `--sev-ok`
                  // is a light green, and white on it measured 1.95:1.
                  done && "bg-ok text-background",
                  active && "bg-foreground text-background ring-4 ring-foreground/10",
                  !done && !active && "border border-border bg-background text-muted-foreground",
                )}
              >
                {/* A tick rather than a number once a step is behind the
                    reader, so finished and pending differ by shape and not by
                    colour alone. */}
                {done ? <CheckIcon className="size-3.5" strokeWidth={3} /> : index + 1}
              </span>
              <span className="min-w-0 pt-0.5">
                <span
                  className={cn(
                    "block text-sm leading-snug",
                    active ? "font-medium text-foreground" : "text-muted-foreground",
                    done && "text-foreground",
                  )}
                >
                  {copy[step.key]}
                </span>
                {active && (
                  <motion.span
                    className="mt-1 block text-xs leading-relaxed text-muted-foreground"
                    initial={{ opacity: 0, y: -2 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: DURATION.quick / 1000, ease: EASE_OUT }}
                  >
                    {copy[`${step.key}Detail`]}
                  </motion.span>
                )}
              </span>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
