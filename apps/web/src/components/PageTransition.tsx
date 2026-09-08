import { type ReactNode } from "react";
import { useLocation } from "react-router-dom";
import { AnimatePresence, motion } from "motion/react";

import { pageTransition } from "@/lib/motion";

/**
 * One page replacing another.
 *
 * Keyed on the pathname rather than on the element, because the element is the
 * same `<Outlet/>` on every route -- without the key React reconciles the two
 * pages into one and nothing animates at all.
 *
 * `mode="wait"` for a reason that is about reading rather than taste: these
 * pages are dense, and two of them overlapping mid-transition briefly shows a
 * security score from the page you left on top of the one you opened. The
 * outgoing page leaves first, and it leaves quickly (120ms) so the wait is not
 * felt.
 *
 * The search string is deliberately *not* part of the key. Filters, pagination
 * and the status chips on the findings list all live in the query string, and
 * re-playing a page transition on every filter change would animate the chrome
 * around a table whose rows are what actually changed.
 */
export function PageTransition({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();

  return (
    <AnimatePresence mode="wait" initial={false}>
      <motion.div
        key={pathname}
        initial={pageTransition.initial}
        animate={pageTransition.animate}
        exit={pageTransition.exit}
      >
        {children}
      </motion.div>
    </AnimatePresence>
  );
}
