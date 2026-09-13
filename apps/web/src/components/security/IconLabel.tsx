import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";

import { cn, resourceTypeLabel } from "@/lib/format";
import { resourceTypeIcon } from "@/lib/icons";

/**
 * A word with its icon in front.
 *
 * The icon is decorative -- the word beside it says the same thing -- so it is
 * hidden from assistive technology rather than announced twice.
 */
export function IconLabel({
  icon: Icon,
  children,
  className,
}: {
  icon: LucideIcon;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span className={cn("inline-flex min-w-0 items-center gap-1.5", className)}>
      <Icon className="size-3.5 shrink-0" aria-hidden />
      <span className="truncate">{children}</span>
    </span>
  );
}

/**
 * A resource's type, with the shape of what it is.
 *
 * `label` overrides the neutral name -- the assets list shows the provider's
 * own type for resources CloudGuard does not model -- while the icon still
 * comes from the neutral type.
 */
export function ResourceTypeLabel({
  type,
  label,
  className,
}: {
  type: string;
  label?: string | null;
  className?: string;
}) {
  return (
    <IconLabel icon={resourceTypeIcon(type)} className={className}>
      {label ?? resourceTypeLabel(type)}
    </IconLabel>
  );
}
