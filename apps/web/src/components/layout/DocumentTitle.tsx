import { useCallback, useEffect, useState, type ReactNode } from "react";
import { useLocation } from "react-router-dom";

import { PageNameContext, documentTitle, type PageName } from "@/lib/pageTitle";

/**
 * Keeps `document.title` on the page being shown (`lib/pageTitle.ts`).
 *
 * Mounted once, around every route, the sign-in screen included. The route
 * decides the title; a detail page adds its own name through `usePageTitle`,
 * which lands here rather than writing the title itself -- a child's effect
 * runs before its parent's, so a page that wrote the title directly would be
 * overwritten by this on the very render it arrived in.
 */
export function DocumentTitle({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  const [page, setPage] = useState<PageName>(null);

  const setName = useCallback((path: string, name: string | null) => {
    setPage((current) => {
      if (name) return { pathname: path, name };
      // Clearing only ever clears the page's own name.
      return current?.pathname === path ? null : current;
    });
  }, []);

  const name = page?.pathname === pathname ? page.name : null;
  useEffect(() => {
    document.title = documentTitle(pathname, name);
  }, [pathname, name]);

  return <PageNameContext.Provider value={setName}>{children}</PageNameContext.Provider>;
}
