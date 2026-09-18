import type { ReactNode } from "react";

/**
 * The top of every step: a mark, a title, one sentence.
 *
 * Every step opens the same way so the reader's eye learns where to look once,
 * rather than finding each step's instruction in a different place. The mark is
 * the thing the step is about -- the provider whose console it sends you to,
 * or the state it is in -- not decoration, which is why a step with nothing to
 * show passes none.
 */
export function StepHeader({
  mark,
  title,
  description,
}: {
  mark?: ReactNode;
  title: ReactNode;
  description?: ReactNode;
}) {
  return (
    <div className="flex items-start gap-4">
      {mark && (
        <span className="flex size-11 shrink-0 items-center justify-center rounded-xl border border-border bg-muted/40 text-foreground shadow-xs">
          {mark}
        </span>
      )}
      <div className="min-w-0">
        <h2 className="text-lg font-semibold tracking-tight text-foreground">{title}</h2>
        {description && (
          <p className="mt-1 max-w-2xl text-sm leading-relaxed text-muted-foreground">
            {description}
          </p>
        )}
      </div>
    </div>
  );
}
