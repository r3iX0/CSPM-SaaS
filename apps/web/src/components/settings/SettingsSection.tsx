import type { ReactNode } from "react";

import { cn } from "@/lib/format";

/**
 * One settings topic: what it is on the left, the controls on the right.
 *
 * The page used to be a column of cards, each opening with its own heading and
 * paragraph above its fields, so the explanation and the form competed for the
 * same width and every section read as the same weight. Two columns let a
 * reader scan the left edge for the topic they came for and only then look at
 * its fields -- the layout every settings page they already use has taught them.
 */
export function SettingsSection({
  title,
  description,
  tone,
  children,
}: {
  title: ReactNode;
  description?: ReactNode;
  /** `danger` for the section that deletes things; it is the only one. */
  tone?: "danger";
  children: ReactNode;
}) {
  return (
    <section className="grid gap-5 border-t border-border py-8 first:border-t-0 first:pt-0 lg:grid-cols-[17rem_minmax(0,1fr)] lg:gap-12">
      <div>
        <h2
          className={cn(
            "text-sm font-semibold",
            tone === "danger" ? "text-critical" : "text-foreground",
          )}
        >
          {title}
        </h2>
        {description && (
          <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">{description}</p>
        )}
      </div>
      <div className="min-w-0">{children}</div>
    </section>
  );
}
