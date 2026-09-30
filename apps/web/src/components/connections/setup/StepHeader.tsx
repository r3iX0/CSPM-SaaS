import type { ReactNode } from "react";

/**
 * The top of every step: a title and one paragraph.
 *
 * Every step opens the same way so the reader's eye learns where to look once,
 * rather than finding each step's instruction in a different place. There is no
 * mark beside it: the page header already carries the provider's tile, and a
 * second one inside the panel said the same thing twice.
 */
export function StepHeader({
  title,
  description,
}: {
  title: ReactNode;
  description?: ReactNode;
}) {
  return (
    <div className="min-w-0">
      <h2 className="text-heading font-semibold tracking-[-0.015em] text-foreground">{title}</h2>
      {description && (
        <p className="mt-2 max-w-[70ch] text-body leading-[1.65] text-muted-foreground">
          {description}
        </p>
      )}
    </div>
  );
}
