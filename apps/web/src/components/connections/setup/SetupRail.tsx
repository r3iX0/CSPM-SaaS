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
import { useValueChange } from "@/lib/motion";
import { DrawnCheck } from "@/components/common/DrawnCheck";

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
      <ol className="flex flex-col">
        {steps.map((step, index) => {
          const done = index < current || (index === current && finished);
          const active = index === current && !finished;
          return (
            <RailStep
              key={step.stage}
              title={copy[step.key]}
              note={done ? settled(step.key) : active ? copy[`${step.key}Detail`] : null}
              number={index + 1}
              done={done}
              active={active}
              last={index === steps.length - 1}
              doneLabel={t.setup.railDone}
            />
          );
        })}
      </ol>
    </nav>
  );
}

/**
 * One row of the rail.
 *
 * Its own component for the hook: a step finishing while the reader watches --
 * consent landing, the role verified -- is news, so its number becomes a check
 * that draws itself and the line down to the next step fills. A step that was
 * already done when the page opened is drawn done, and nothing moves
 * (DECISIONS.md §167, §181). The line is a `scaleY` from the top, and the
 * circle's fill a colour transition.
 */
function RailStep({
  title,
  note,
  number,
  done,
  active,
  last,
  doneLabel,
}: {
  title: string;
  note: string | null;
  number: number;
  done: boolean;
  active: boolean;
  last: boolean;
  doneLabel: string;
}) {
  const { changes } = useValueChange(done);
  const justDone = done && changes > 0;
  return (
    <li
      aria-current={active ? "step" : undefined}
      // On a phone the rail sits above the panel, where four rows of it would
      // push the step itself below the fold: there it is the current row, and
      // the full list is for wider screens.
      className={cn("relative items-start gap-2.5 pb-3.5 last:pb-0", active ? "flex" : "hidden lg:flex")}
    >
      {!last && (
        <span
          className="absolute top-6 bottom-0.5 left-2.5 hidden w-px -translate-x-1/2 overflow-hidden bg-border lg:block"
          aria-hidden
        >
          <span
            className={cn(
              "block size-full origin-top bg-primary transition-transform duration-600 ease-out",
              done ? "scale-y-100" : "scale-y-0",
            )}
          />
        </span>
      )}
      <span
        className={cn(
          "relative flex size-5 shrink-0 items-center justify-center rounded-full text-caption tabular-nums transition-colors duration-240",
          done && "bg-primary text-primary-foreground",
          active && "border border-primary text-primary",
          !done && !active && "border border-border bg-card text-muted-foreground",
        )}
      >
        {/* A tick rather than a number once a step is behind the reader, so
            finished and pending differ by shape and not by colour alone. */}
        {done ? <DrawnCheck draw={justDone} className="size-3" /> : number}
        {done && <span className="sr-only">{doneLabel}</span>}
      </span>
      <span className="min-w-0">
        <span
          className={cn(
            "block text-meta leading-snug",
            done || active ? "font-medium text-foreground" : "text-muted-foreground",
          )}
        >
          {title}
        </span>
        {note && (
          <span className="mt-0.5 block text-caption leading-relaxed text-muted-foreground">
            {note}
          </span>
        )}
      </span>
    </li>
  );
}

