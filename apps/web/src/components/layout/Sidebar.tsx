import { NavLink, useMatch } from "react-router-dom";

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

type NavItem = (typeof NAV_GROUPS)[number]["items"][number];

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

  return (
    <>
      {NAV_GROUPS.map((group) => (
        <SidebarGroup key={group.label}>
          {collapsed ? (
            // A rule rather than a heading: the grouping is still information
            // even when there is no room to name it.
            <span className="mx-2 mb-1 border-t" aria-hidden />
          ) : (
            <SidebarGroupLabel>{group.label}</SidebarGroupLabel>
          )}
          <SidebarGroupContent>
            <SidebarMenu>
              {group.items.map((item) => (
                <NavRow
                  key={item.to}
                  item={item}
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
  onNavigate,
}: {
  item: NavItem;
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
      >
        <item.icon aria-hidden />
        <span>{item.label}</span>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
}
