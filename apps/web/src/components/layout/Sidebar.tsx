import { useQuery } from "@tanstack/react-query";
import { NavLink } from "react-router-dom";

import { NAV_GROUPS } from "@/components/layout/nav";
import { api } from "@/lib/api";
import type { Risk } from "@/lib/types";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/format";

/**
 * The navigation, in two widths.
 *
 * Collapsed it keeps the icons and drops the words, which is the trade a
 * fourteen-inch screen actually wants: the four groups are the product's
 * workflow and their order is what a returning reader navigates by, so the rail
 * keeps both the order and the grouping and gives up only the labels — and each
 * icon still says its own name on hover and to a screen reader.
 *
 * The active item is a rail and a wash rather than a filled pill: at 236px a
 * filled row is the heaviest object on the screen, and the thing it is
 * competing with is the reader's own data.
 */
export function SidebarNav({
  onNavigate,
  collapsed = false,
}: {
  onNavigate?: () => void;
  collapsed?: boolean;
}) {
  const openRisks = useOpenRiskCount();

  return (
    <nav
      className={cn("flex flex-col gap-6 py-4", collapsed ? "px-2" : "px-3")}
      aria-label="Main"
    >
      {NAV_GROUPS.map((group) => (
        <div key={group.label} className="flex flex-col gap-1">
          {collapsed ? (
            // A rule rather than a heading: the grouping is still information
            // even when there is no room to name it.
            <span className="mx-2 mb-1 border-t" aria-hidden />
          ) : (
            <p className="px-3 pb-1.5 text-[11px] font-medium uppercase tracking-[0.12em] text-meta-foreground">
              {group.label}
            </p>
          )}
          {group.items.map((item) => {
            // Only one destination carries a number, and it is the one a
            // reader comes back to the product for.
            const badge = item.to === "/risks" ? openRisks : null;
            const label =
              badge === null ? item.label : `${item.label} (${badge} open)`;

            const link = (
              <NavLink
                key={item.to}
                to={item.to}
                end={"end" in item ? item.end : undefined}
                onClick={onNavigate}
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-3 rounded-md text-sm transition-colors",
                    collapsed ? "justify-center px-2 py-2" : "px-3 py-2",
                    "focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50",
                    isActive
                      ? "bg-[linear-gradient(90deg,--alpha(var(--color-primary)/14%),transparent)] font-medium text-foreground shadow-[inset_2px_0_0_var(--color-primary)]"
                      : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground",
                  )
                }
              >
                <item.icon className="size-4 shrink-0" aria-hidden />
                {collapsed ? (
                  <span className="sr-only">{label}</span>
                ) : (
                  <>
                    <span className="min-w-0 flex-1 truncate">{item.label}</span>
                    {badge !== null && badge > 0 && (
                      <span className="shrink-0 rounded bg-critical-bg px-1.5 py-0.5 font-mono text-[11px] text-critical">
                        {badge}
                      </span>
                    )}
                  </>
                )}
              </NavLink>
            );

            if (!collapsed) return link;

            return (
              <Tooltip key={item.to}>
                <TooltipTrigger render={link} />
                <TooltipContent side="right">{label}</TooltipContent>
              </Tooltip>
            );
          })}
        </div>
      ))}
    </nav>
  );
}

/**
 * How many risks are open, for the badge.
 *
 * Deliberately the same request the risks page makes with no filters, so the
 * two numbers cannot disagree: the list's own definition of live decides what
 * counts, rather than the sidebar inventing a second one. A page of one is
 * asked for because only `meta.total` is read.
 */
function useOpenRiskCount(): number | null {
  const { data } = useQuery({
    queryKey: ["risks", "nav-count"],
    queryFn: () =>
      api
        .get<Risk[]>("/api/v1/risks?limit=1")
        .then((r) => (r.meta as { total?: number } | undefined)?.total ?? 0),
    // The navigation is not a dashboard: a number that is minutes old is
    // fine, and a rail that refetches on every route change is not.
    staleTime: 60_000,
    retry: false,
  });

  return data ?? null;
}
