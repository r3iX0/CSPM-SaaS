import { createElement } from "react";

import { cn, resourceTypeLabel } from "@/lib/format";
import { resourceTypeIcon } from "@/lib/icons";

/**
 * What kind of thing a row is about, as a small tile left of its name.
 *
 * The glyph comes from `lib/icons.ts` like every other meaningful icon, so a
 * storage account is the same cylinder here, on the graph and on its own page.
 * Decorative to a screen reader: the type is always written beside it, and
 * reading "storage account, Storage account" helps nobody.
 *
 * `unknown` tints the tile in the unknown tone, for a row whose verdict could
 * not be read -- it is the row, not the resource, that is in question.
 */
export function ResourceIcon({
  type,
  size = "default",
  unknown = false,
  className,
}: {
  type: string;
  size?: "default" | "sm";
  unknown?: boolean;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center justify-center rounded-md",
        size === "sm" ? "size-[22px]" : "size-6",
        unknown ? "bg-unknown-bg text-unknown" : "bg-muted text-muted-foreground",
        className,
      )}
      title={resourceTypeLabel(type)}
      aria-hidden
    >
      {createElement(resourceTypeIcon(type), {
        className: size === "sm" ? "size-3" : "size-[13px]",
        strokeWidth: 1.5,
      })}
    </span>
  );
}
