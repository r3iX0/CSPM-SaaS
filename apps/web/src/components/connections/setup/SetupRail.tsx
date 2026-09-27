import { CheckIcon } from "lucide-react";

import { useT } from "@/i18n";
import {
  scopeName,
  setupSteps,
  stepIndex,
  type SetupStage,
  type SetupStepKey,
} from "@/lib/connectionStage";
import { setupCopy } from "@/lib/setupCopy";
import type { CloudConnection, Provider } from "@/lib/types";
import { cn, formatDate } from "@/lib/format";

/**
 * The steps, and where the customer is in them.
 *
 * The same rows as the empty state's preview, in the same words. Somebody who
 * read "what the three minutes look like" before starting should recognise the
 * list they are now standing inside, rather than meet a second, differently
 * worded account of the same flow.
 *
 * Each row carries one line under its title, and which line depends on where
 * the reader is: a finished step says what it settled -- the scope, when
 * consent was granted -- read off the connection rather than restated from the
 * copy; the current step says what it asks for; a step ahead is a title until
 * the reader reaches it.
 *
 * Four rows on Azure and three on AWS, because AWS has no consent step. A rail
 * with a permanently grey "Grant consent" row would read as a flow that is
 * stuck on something nobody is going to do.
 */
export function SetupRail({
  stage,
  provider,
  connection,
}: {
  stage: SetupStage;
  provider: Provider;
  connection: CloudConnection | null;
}) {
  const t = useT();
  const copy = setupCopy(t, provider);
  const steps = setupSteps(provider);
  const current = stepIndex(stage, provider);
  const finished = stage === "done";

  function settled(key: SetupStepKey): string | null {
    if (!connection) return null;
    if (key === "stepScope") return scopeName(connection);
    if (key === "stepConsent" && connection.consented_at) {
      return t.setup.railConsented(formatDate(connection.consented_at));
    }
    if (key === "stepDeploy" && connection.rbac_verified_at) {
      return t.setup.railVerified(formatDate(connection.rbac_verified_at));
    }
    return null;
  }

  return (
    <nav aria-label={copy.railHeading}>
      <ol className="flex flex-col gap-3.5">
        {steps.map((step, index) => {
          const done = index < current || (index === current && finished);
          const active = index === current && !finished;
          const note = done ? settled(step.key) : active ? copy[`${step.key}Detail`] : null;
          return (
            <li
              key={step.stage}
              aria-current={active ? "step" : undefined}
              // On a phone the rail sits above the panel, where four rows of
              // it would push the step itself below the fold: there it is the
              // current row, and the full list is for wider screens.
              className={cn("items-start gap-2.5", active ? "flex" : "hidden lg:flex")}
            >
              <span
                className={cn(
                  "flex size-5 shrink-0 items-center justify-center rounded-full text-[11px] tabular-nums transition-colors",
                  done && "bg-primary text-primary-foreground",
                  active && "border border-primary text-primary",
                  !done && !active && "border border-border text-muted-foreground",
                )}
              >
                {/* A tick rather than a number once a step is behind the
                    reader, so finished and pending differ by shape and not by
                    colour alone. */}
                {done ? <CheckIcon className="size-3" strokeWidth={3} aria-hidden /> : index + 1}
                {done && <span className="sr-only">{t.setup.railDone}</span>}
              </span>
              <span className="min-w-0">
                <span
                  className={cn(
                    "block text-[12.5px] leading-snug",
                    done || active ? "font-medium text-foreground" : "text-muted-foreground",
                  )}
                >
                  {copy[step.key]}
                </span>
                {note && (
                  <span className="mt-0.5 block text-[11.5px] leading-relaxed text-muted-foreground">
                    {note}
                  </span>
                )}
              </span>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
