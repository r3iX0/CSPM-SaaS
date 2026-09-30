import { NavLink, useMatch } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { NAV_GROUPS } from "@/components/layout/nav";
import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";
import { api } from "@/lib/api";
import type { Dashboard } from "@/lib/types";
import { useRiskCount } from "@/lib/useRiskCount";

type NavItem = (typeof NAV_GROUPS)[number]["items"][number];

/**
 * How many of each thing is open, beside the three destinations that are
 * lists of problems. Read from the overview's own payload -- the same cache
 * entry, so the overview and the navigation never disagree -- and absent until
 * it has arrived: a count that is not known is left out, never drawn as 0.
 */
function useNavCounts(): Partial<Record<string, number>> {
  const { data } = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api.get<Dashboard>("/api/v1/dashboard").then((r) => r.data),
    staleTime: 60_000,
    retry: false,
  });
  // The list's own count: the dashboard's bands leave out attack paths and
  // escalations, which the risks list shows.
  const risks = useRiskCount();
  if (!data || typeof data.open_finding_count !== "number") return {};
  const latest = data.history?.[data.history.length - 1];
  return {
    "/findings": data.open_finding_count,
    ...(risks !== null ? { "/risks": risks } : {}),
    ...(latest ? { "/attack-paths": latest.attack_path_count } : {}),
  };
}

/**
 * The navigation, in two widths.
 *
 * Collapsed it keeps the icons and drops the words, which is the trade a
 * fourteen-inch screen actually wants: the four groups are the product's
 * workflow and their order is what a returning reader navigates by, so the rail
 * keeps both the order and the grouping and gives up only the labels — and each
 * icon still says its own name on hover and to a screen reader.
 *
 * The collapsed/expanded switch is no longer a prop threaded down from the
 * shell. `Sidebar` owns that state now, so this reads it from context: one
 * source of truth means the rail, the labels, the tooltips and the mobile sheet
 * cannot disagree about which width they are in.
 */
export function SidebarNav() {
  const { state, isMobile, setOpenMobile } = useSidebar();
  // On mobile the sidebar is a sheet at full width, so it is never the rail
  // even when the desktop preference says collapsed.
  const collapsed = state === "collapsed" && !isMobile;
  const counts = useNavCounts();

  return (
    <>
      {NAV_GROUPS.map((group) => (
        <SidebarGroup key={group.label} className="p-0">
          {collapsed ? (
            // A rule rather than a heading: the grouping is still information
            // even when there is no room to name it.
            <span className="mx-2 mb-1 border-t" aria-hidden />
          ) : (
            <SidebarGroupLabel className="mb-1 h-auto px-2 text-caption tracking-[0.04em] text-muted-foreground uppercase">
              {group.label}
            </SidebarGroupLabel>
          )}
          <SidebarGroupContent>
            <SidebarMenu className="gap-0.5">
              {group.items.map((item) => (
                <NavRow
                  key={item.to}
                  item={item}
                  count={counts[item.to]}
                  // On a phone the navigation is a sheet covering the page it
                  // navigates to, so following a link has to close it. The
                  // shell used to pass this down; it belongs here, where the
                  // thing that knows it is a sheet lives.
                  onNavigate={isMobile ? () => setOpenMobile(false) : undefined}
                />
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      ))}
    </>
  );
}

/**
 * One destination.
 *
 * Its own component because of the hook: whether a row is current is a route
 * match, and a match per row inside `.map()` would be a hook count that depends
 * on the data. The array is static today, but the rule that keeps it safe
 * should not be "nobody makes the navigation dynamic".
 *
 * `useMatch` rather than `NavLink`'s own render-prop because the primitive
 * needs the answer as a prop -- the anchor itself is what carries the button
 * styling and the focus ring, so nothing may sit between them.
 */
function NavRow({
  item,
  count,
  onNavigate,
}: {
  item: NavItem;
  count?: number;
  onNavigate?: () => void;
}) {
  const exact = "end" in item && item.end === true;
  // Non-exact rows stay lit on their detail screens: a reader on
  // /findings/<id> has not left Findings, and a navigation that says otherwise
  // makes them look for where they are.
  const match = useMatch({ path: item.to, end: exact });

  return (
    <SidebarMenuItem>
      <SidebarMenuButton
        isActive={match !== null}
        tooltip={item.label}
        render={<NavLink to={item.to} end={exact} onClick={onNavigate} />}
        // The selected row is the brand's one job in the navigation: a soft
        // fill and a ring, the same weight of type as its neighbours.
        className="h-auto rounded-lg px-2.5 py-[7px] text-body data-active:bg-primary-soft data-active:font-normal data-active:text-foreground data-active:ring-1 data-active:ring-primary-border data-active:ring-inset"
      >
        <item.icon aria-hidden strokeWidth={1.5} />
        <span className="min-w-0 flex-1 truncate">
          {item.label}
          {count !== undefined && <span className="sr-only">, {count} open</span>}
        </span>
        {count !== undefined && (
          <span
            aria-hidden
            className="ml-auto text-caption text-muted-foreground tabular-nums group-data-[collapsible=icon]:hidden"
          >
            {count}
          </span>
        )}
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
}
