import type { ReactNode } from "react";

import { cn } from "@/lib/format";

/**
 * One settings topic: a heading, one line on what it is for, then its card.
 *
 * Stacked rather than two columns. The page is narrow on purpose -- a form is
 * read top to bottom -- and at 820px a side column of explanation left the
 * fields a width no field needs while pushing the reason for them out of the
 * reading line.
 */
export function SettingsSection({
  id,
  title,
  description,
  tone,
  children,
}: {
  /** The anchor the page's section links jump to. */
  id?: string;
  title: ReactNode;
  description?: ReactNode;
  /** `danger` for the section that deletes things; it is the only one. */
  tone?: "danger";
  children: ReactNode;
}) {
  return (
    <section id={id} aria-labelledby={id ? `${id}-title` : undefined} className="scroll-mt-20">
      <h2
        id={id ? `${id}-title` : undefined}
        className={cn(
          "text-sm font-semibold",
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
      <div className="mt-3.5 min-w-0">{children}</div>
    </section>
  );
}
