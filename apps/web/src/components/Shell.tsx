import { useEffect, useState } from "react";
import { Link, Outlet, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { api, auth } from "@/lib/api";
import type { CloudAccount, Dashboard, Organization } from "@/lib/types";
import { Wordmark } from "@/components/Brand";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { AccountMenu } from "@/components/AccountMenu";
import { SidebarNav } from "@/components/layout/Sidebar";
import { PageTransition } from "@/components/PageTransition";
import { CommandPalette } from "@/components/layout/CommandPalette";
import { KeyboardShortcuts } from "@/components/layout/KeyboardShortcuts";
import { DemoBanner } from "@/components/layout/DemoBanner";
import { NotificationBell } from "@/components/layout/NotificationBell";
import { ScanIndicator } from "@/components/layout/ScanIndicator";
import { ThemeToggle } from "@/components/layout/ThemeToggle";
import { ScanWizardProvider } from "@/components/scans/ScanWizardProvider";
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
import { cn, formatRelative } from "@/lib/format";

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
      <ScanWizardProvider>
      <SidebarProvider open={open} onOpenChange={setOpen}>
        {/* The first stop on the keyboard, and invisible until it is reached:
            without it every page begins with the whole navigation, a dozen
            links, before its own content (WCAG 2.4.1). */}
        <a
          href="#main-content"
          // Focus moved by hand rather than by the fragment: following it
          // would write `#main-content` into a URL the router owns.
          onClick={(event) => {
            event.preventDefault();
            document.getElementById("main-content")?.focus();
          }}
          className="sr-only focus-visible:not-sr-only focus-visible:fixed focus-visible:top-3 focus-visible:left-3 focus-visible:z-50 focus-visible:rounded-md focus-visible:bg-background focus-visible:px-3 focus-visible:py-2 focus-visible:text-sm focus-visible:font-medium focus-visible:shadow-md focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring"
        >
          Skip to content
        </a>
        {/* `collapsible="icon"` is the rail this shell always had: navigation
            that scrolls away makes a long findings table a one-way trip, so it
            narrows to icons rather than leaving. On mobile the same component
            is the sheet, which is why there is no second copy of the
            navigation here any more. */}
        <Sidebar collapsible="icon">
          <SidebarHeader className="h-14 shrink-0 justify-center border-b px-3 group-data-[collapsible=icon]:items-center">
            <Link
              to="/"
              className="flex items-center gap-2.5 rounded-md px-2 outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-ring group-data-[collapsible=icon]:px-0"
            >
              <Wordmark
                markClassName="size-5"
                labelClassName="group-data-[collapsible=icon]:sr-only"
              />
            </Link>
          </SidebarHeader>
          <SidebarContent className="gap-3.5 p-3 group-data-[collapsible=icon]:px-2">
            <SidebarNav />
          </SidebarContent>
          <SidebarFooter className="flex-row items-center gap-1 border-t group-data-[collapsible=icon]:flex-col">
            <div className="min-w-0 flex-1 group-data-[collapsible=icon]:flex-none">
              <ConnectionBadge />
            </div>
            {/* The collapse control lives at the foot of the column it
                collapses, beside the rail edge, rather than in the page
                header — so it does not move when the rail narrows. */}
            <NavToggle placement="sidebar" />
          </SidebarFooter>
          {/* The drag/click edge, a second way to do the same thing. */}
          <SidebarRail />
        </Sidebar>

        <SidebarInset>
          <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b bg-background/88 px-4 backdrop-blur-md sm:px-6">
            <NavToggle placement="header" />
            <CommandPalette />

            <div className="ml-auto flex items-center gap-2.5">
              <LastRead />
              <KeyboardShortcuts />
              <ScanIndicator />
              {/* After the scan indicator and before the settings: what is
                  happening now, then what happened, then how the app looks. */}
              <NotificationBell />
              <ThemeToggle />
              <AccountMenu organizations={orgs ?? []} current={current} />
            </div>
          </header>

          <DemoBanner />

          <main
            id="main-content"
            // Focusable from script only, for the skip link and for a new page
            // with no heading yet (`PageTransition`); never a tab stop.
            tabIndex={-1}
            className="mx-auto w-full max-w-[1240px] px-4 pt-6 pb-16 outline-none sm:px-6"
          >
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
      </ScanWizardProvider>

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
 * itself "Toggle sidebar" in every state, and a control whose label does not
 * change is a control a screen-reader user cannot tell the state of. This says
 * which way it will go, and carries `aria-expanded` so assistive technology
 * does not have to infer it from the wording.
 *
 * Rendered in one of two places, never both. On a desktop it sits at the foot
 * of the sidebar, where it stays put as the rail narrows. On a phone the sidebar
 * is a sheet that is not on screen until it is opened, so a control inside it
 * could never open it — there the trigger stays in the page header. Only the
 * provider knows which of those is true, which is why this reads `isMobile`
 * rather than hiding one copy with a breakpoint class.
 */
function NavToggle({ placement }: { placement: "sidebar" | "header" }) {
  const { isMobile, open, openMobile } = useSidebar();
  const shown = isMobile ? openMobile : open;

  if ((placement === "header") !== isMobile) return null;

  return (
    <SidebarTrigger
      aria-label={shown ? "Collapse navigation" : "Expand navigation"}
      aria-expanded={shown}
    />
  );
}

/**
 * When the environment was last read, in the header of every page.
 *
 * The age of the evidence is the one caveat every number in the product
 * carries, so it sits where every page can see it. From the overview's payload
 * (the same cache entry the navigation counts use); nothing is drawn until a
 * completed read is known -- an absent date is not "just now".
 */
function LastRead() {
  const { data } = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api.get<Dashboard>("/api/v1/dashboard").then((r) => r.data),
    staleTime: 60_000,
    retry: false,
  });
  const at = data?.last_scan?.completed_at;
  if (!at) return null;
  return (
    <span className="hidden items-center gap-1.5 text-xs text-muted-foreground md:flex">
      {/* Green only for a read that finished whole; one with gaps says so. */}
      <span
        className={cn(
          "size-1.5 shrink-0 rounded-full",
          data?.last_scan?.status === "COMPLETED" ? "bg-ok" : "bg-medium",
        )}
        aria-hidden
      />
      Last read <time dateTime={at}>{formatRelative(at)}</time>
    </span>
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
        className="flex items-center gap-2 rounded-md border border-dashed px-2.5 py-2 text-[11.5px] text-muted-foreground transition-colors hover:border-solid hover:text-foreground"
      >
        <span className={dot} />
        No cloud connected
      </Link>
    );
  }

  return (
    <div className="flex items-center gap-2 px-1.5 py-1.5 text-[11.5px] text-muted-foreground">
      <span className={dot} />
      {summary}
    </div>
  );
}
