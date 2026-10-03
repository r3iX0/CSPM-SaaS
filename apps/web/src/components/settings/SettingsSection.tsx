import type { ReactNode } from "react";

import { cn } from "@/lib/format";

/**
 * One settings topic: a heading, one line on what it is for, then its card.
 *
 * Stacked rather than two columns. A form is read top to bottom, and a side
 * column of explanation left the fields a width no field needs while pushing
 * the reason for them out of the reading line. `actions` sits beside the
 * heading -- "Invite someone", "New integration" -- so the way to add to a list
 * is where the list is named rather than in a form open under it all the time
 * (DECISIONS.md §207).
 */
export function SettingsSection({
  id,
  title,
  description,
  tone,
  actions,
  children,
}: {
  /** The anchor a link to this topic lands on. */
  id?: string;
  title: ReactNode;
  description?: ReactNode;
  /** `danger` for the section that deletes things; it is the only one. */
  tone?: "danger";
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section id={id} aria-labelledby={id ? `${id}-title` : undefined} className="scroll-mt-20">
      <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2">
        <div className="min-w-0">
          <h2
            id={id ? `${id}-title` : undefined}
            className={cn(
              "text-title font-semibold",
              tone === "danger" ? "text-critical" : "text-foreground",
            )}
          >
            {title}
          </h2>
          {description && (
            <p className="mt-1 max-w-[76ch] text-meta leading-relaxed text-muted-foreground">
              {description}
            </p>
          )}
        </div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </div>
      <div className="mt-4 min-w-0">{children}</div>
    </section>
  );
}
