import { createContext, useContext, useEffect } from "react";
import { matchPath, useLocation } from "react-router-dom";

import { NAV_GROUPS } from "@/components/layout/nav";

/**
 * What each route is called in the browser's tab, its history and a screen
 * reader's list of windows (WCAG 2.4.2).
 *
 * Every page used to be "Cleave": ten tabs open on ten findings were ten tabs
 * with one name, and the first thing a screen reader says on arriving anywhere
 * said nothing about where. The sidebar's labels are the names, so a page is
 * called what the navigation calls it; the routes the sidebar does not list
 * are named here. A detail page adds the thing it shows in front of its kind
 * once that has loaded (`usePageTitle`).
 */
const ROUTES: [pattern: string, title: string][] = [
  ...NAV_GROUPS.flatMap((group) =>
    group.items.map((item): [string, string] => [item.to, item.label]),
  ),
  ["/sign-in", "Sign in"],
  ["/demo", "Opening the demo"],
  ["/reset-password", "Set a new password"],
  ["/onboarding", "Get started"],
  ["/invite", "Join an organization"],
  ["/assets/:assetId", "Asset"],
  ["/findings/:findingId", "Finding"],
  ["/risks/:riskId", "Risk"],
  ["/compliance/:frameworkId", "Compliance framework"],
  ["/connections/new", "Connect an environment"],
  // Each settings page under the one name, so ten tabs on Settings say which
  // page each is (DECISIONS.md §207).
  ["/settings/general", "General · Settings"],
  ["/settings/members", "Members · Settings"],
  ["/settings/context", "Risk context · Settings"],
  ["/settings/integrations", "Integrations · Settings"],
  ["/settings/audit", "Audit packages · Settings"],
  ["/settings/activity", "Activity · Settings"],
  ["/auditor", "Audit packages"],
  ["/auditor/:grantId", "Audit package"],
  ["/settings/security", "Security · Settings"],
  ["/settings/preferences", "Preferences · Settings"],
  ["/connections/:connectionId/setup", "Environment setup"],
];

export const APP_TITLE = "Cleave";

/** The route's own name, or null for a path the router does not know. */
export function routeTitle(pathname: string): string | null {
  for (const [pattern, title] of ROUTES) {
    if (matchPath({ path: pattern, end: true }, pathname)) return title;
  }
  return null;
}

/** The whole title: what is shown, what kind of page it is, the product. */
export function documentTitle(pathname: string, name: string | null): string {
  return [name, routeTitle(pathname), APP_TITLE].filter(Boolean).join(" · ");
}

/** A detail page's name for itself, keyed by the path it was given on. */
export type PageName = { pathname: string; name: string } | null;

export const PageNameContext = createContext<(pathname: string, name: string | null) => void>(
  () => {},
);

/**
 * Name the page in the title once what it shows has loaded -- the finding's
 * title, the asset's name. The name is keyed by path, so a name left behind by
 * the page just closed never labels the next one.
 */
export function usePageTitle(name: string | null | undefined) {
  const { pathname } = useLocation();
  const setName = useContext(PageNameContext);
  useEffect(() => {
    if (!name) return;
    setName(pathname, name);
    return () => setName(pathname, null);
  }, [setName, pathname, name]);
}
