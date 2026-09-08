import { useEffect, useState } from "react";
import { Link, Outlet, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { api, auth } from "@/lib/api";
import type { CloudAccount, Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { ShieldMark } from "@/components/Brand";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { AccountMenu } from "@/components/AccountMenu";
import { SidebarNav } from "@/components/layout/Sidebar";
import { PageTransition } from "@/components/PageTransition";
import { CommandPalette } from "@/components/layout/CommandPalette";
import { NotificationBell } from "@/components/layout/NotificationBell";
import { ScanIndicator } from "@/components/layout/ScanIndicator";
import { ThemeToggle } from "@/components/layout/ThemeToggle";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarInset,
  SidebarProvider,
  SidebarRail,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar";
import { Toaster } from "@/components/ui/sonner";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/format";

/** Where the rail preference lives. Per browser, like the theme. */
const COLLAPSE_KEY = "cloudguard.sidebar.collapsed";

/**
 * The application shell.
 *
 * A sidebar rather than the horizontal strip this replaced, for a reason that
 * is about the product rather than about fashion: ten peer tabs cannot express
 * that findings, risks and attack paths are three readings of one problem while
 * scans and connections are the machinery underneath. A column has room to
 * group them, and the groups are the security workflow (`layout/Sidebar.tsx`).
 *
 * The header keeps only what is true across every page: who you are, which
 * organization you are looking at, and whether CloudGuard is currently reading
 * your cloud. The last of those is new and is the one people ask for -- a scan
 * takes minutes, and previously nothing outside the scans page said one was
 * running.
 */
export function Shell() {
  const t = useT();
  const navigate = useNavigate();
  // A choice about the shape of the workspace, so it is remembered: somebody
  // working on a small laptop should not re-collapse the sidebar every morning.
  // Read lazily and defensively -- a browser with storage disabled must still
  // render an application.
  //
  // Kept here rather than left to the sidebar primitive, which persists to a
  // cookie upstream. This app already stores the theme in localStorage and
  // sets no cookies at all; a rail width is not a reason to start.
  const [open, setOpen] = useState(() => {
    try {
      return window.localStorage.getItem(COLLAPSE_KEY) !== "1";
    } catch {
      return true;
    }
  });

  useEffect(() => {
    try {
      window.localStorage.setItem(COLLAPSE_KEY, open ? "0" : "1");
    } catch {
      // Nothing to do: the preference simply does not survive the session.
    }
  }, [open]);

  const { data: orgs, isLoading } = useQuery({
    queryKey: ["organizations"],
    queryFn: () =>
      api.get<Organization[]>("/api/v1/organizations").then((r) => r.data),
  });

  // Both of these used to run during render, which meant navigating and writing
  // to a store that notifies subscribers while React was still rendering.
  useEffect(() => {
    if (isLoading || !orgs) return;

    // A signed-in user with no organization has not finished signing up.
    if (orgs.length === 0) {
      navigate("/onboarding", { replace: true });
      return;
    }

    // Only default when the stored choice names nothing real — otherwise this
    // would immediately undo whatever the user just picked.
    const selected = orgs.find((o) => o.id === auth.organizationId);
    if (!selected) auth.organizationId = orgs[0].id;
  }, [isLoading, orgs, navigate]);

  const current = orgs?.find((o) => o.id === auth.organizationId) ?? orgs?.[0];

  return (
    // One provider for the whole application: without it every tooltip runs its
    // own delay, so crossing a row of them makes each one wait again.
    <TooltipProvider delay={200}>
      <SidebarProvider open={open} onOpenChange={setOpen}>
        {/* `collapsible="icon"` is the rail this shell always had: navigation
            that scrolls away makes a long findings table a one-way trip, so it
            narrows to icons rather than leaving. On mobile the same component
            is the sheet, which is why there is no second copy of the
            navigation here any more. */}
        <Sidebar collapsible="icon">
          <SidebarHeader className="h-14 shrink-0 justify-center border-b group-data-[collapsible=icon]:items-center">
            <Link
              to="/"
              className="flex items-center gap-2.5 rounded-md px-2 outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50 group-data-[collapsible=icon]:px-0"
            >
              <ShieldMark className="size-5 shrink-0" />
              <span className="truncate text-sm font-semibold tracking-tight group-data-[collapsible=icon]:hidden">
                {t.app.name}
              </span>
            </Link>
          </SidebarHeader>
          <SidebarContent>
            <SidebarNav />
          </SidebarContent>
          <SidebarFooter className="border-t">
            <ConnectionBadge />
          </SidebarFooter>
          {/* The drag/click edge. It is what replaces the collapse button that
              used to sit in the footer, and it is reachable by keyboard. */}
          <SidebarRail />
        </Sidebar>

        <SidebarInset>
          <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b bg-background/95 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/80 sm:px-6">
            <NavToggle />

            <div className="ml-auto flex items-center gap-3">
              <CommandPalette />
              <ScanIndicator />
              {/* After the scan indicator and before the settings: what is
                  happening now, then what happened, then how the app looks. */}
              <NotificationBell />
              <ThemeToggle />
              <AccountMenu organizations={orgs ?? []} current={current} />
            </div>
          </header>

          <main className="mx-auto w-full max-w-[1400px] px-4 py-6 sm:px-6 lg:py-8">
            {/* Per-page, inside the chrome. A page that throws is one broken
                screen the reader can navigate away from, rather than a product
                that vanished -- and the root boundary is still behind this for
                anything the shell itself does.

                The boundary is outside the transition, not inside: an error
                that arrives mid-animation must not be something that animates
                away. */}
            <ErrorBoundary variant="page">
              <PageTransition>
                <Outlet />
              </PageTransition>
            </ErrorBoundary>
          </main>
        </SidebarInset>
      </SidebarProvider>

      {/* Mounted once, here, because an action's outcome outlives the panel it
        was taken in: marking a task done navigates nowhere, and the answer --
        that CloudGuard will look again rather than that the finding is now
        closed -- has to arrive somewhere that is always on screen. */}
      <Toaster position="bottom-right" />
    </TooltipProvider>
  );
}

/**
 * The control that opens and closes the navigation.
 *
 * A thin wrapper on the primitive's trigger for one reason: the primitive names
 * itself "Toggle Sidebar" in every state, and a control whose label does not
 * change is a control a screen-reader user cannot tell the state of. This says
 * which way it will go, and carries `aria-expanded` so assistive technology
 * does not have to infer it from the wording.
 *
 * Inside the provider rather than in `Shell`, because on a phone the same
 * button opens a sheet rather than widening a rail, and only the provider knows
 * which of those is true.
 */
function NavToggle() {
  const { isMobile, open, openMobile } = useSidebar();
  const shown = isMobile ? openMobile : open;

  return (
    <SidebarTrigger
      aria-label={shown ? "Collapse navigation" : "Expand navigation"}
      aria-expanded={shown}
    />
  );
}

/**
 * Whether CloudGuard can see anything at all.
 *
 * Sits at the foot of the sidebar because it is the precondition for every
 * number on every other screen: a product showing a security score of 100 over
 * an environment it has never connected to is not reassuring, it is wrong.
 */
function ConnectionBadge() {
  const { state, isMobile } = useSidebar();
  const collapsed = state === "collapsed" && !isMobile;

  const { data } = useQuery({
    queryKey: ["cloud-accounts"],
    queryFn: () =>
      api.get<CloudAccount[]>("/api/v1/cloud-accounts").then((r) => r.data),
    retry: false,
  });

  const count = data?.length ?? 0;
  const scannable = data?.filter((a) => a.is_scannable).length ?? 0;

  const summary =
    count === 0
      ? "No cloud connected"
      : scannable > 0
        ? `${scannable} subscription${scannable === 1 ? "" : "s"} monitored`
        : "Connected, not ready to scan";

  const dot = cn(
    "size-1.5 shrink-0 rounded-full transition-colors",
    count === 0
      ? "bg-muted-foreground"
      : scannable > 0
        ? "bg-ok"
        : "bg-medium",
  );

  // On the rail there is room for the state and not for the sentence. The dot
  // keeps its meaning and the sentence moves to a tooltip, rather than the
  // precondition for every number in the product disappearing with the labels.
  if (collapsed) {
    return (
      <Tooltip>
        <TooltipTrigger
          render={
            <Link
              to="/connections"
              aria-label={summary}
              className="flex size-7 items-center justify-center rounded-md hover:bg-sidebar-accent/60"
            />
          }
        >
          <span className={cn(dot, "size-2")} />
        </TooltipTrigger>
        <TooltipContent side="right">{summary}</TooltipContent>
      </Tooltip>
    );
  }

  if (count === 0) {
    return (
      <Link
        to="/connections"
        className="flex items-center gap-2 rounded-md border border-dashed px-2.5 py-2 text-xs text-muted-foreground transition-colors hover:border-solid hover:text-foreground"
      >
        <span className={dot} />
        No cloud connected
      </Link>
    );
  }

  return (
    <div className="flex items-center gap-2 px-2.5 py-2 text-xs text-muted-foreground">
      <span className={dot} />
      {summary}
    </div>
  );
}
