import { useState, type ReactNode } from "react";
import { useLocation } from "react-router-dom";
import { AnimatePresence, motion } from "motion/react";

import { pageTransition } from "@/lib/motion";
import { arrivedByMorph } from "@/lib/viewTransition";

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
 *
 * **A morph into the graph is the one swap this does not animate (§140).** The
 * browser is already moving between its pictures of the two pages, and it has
 * frozen drawing while it waits for the second -- so an exit counted in
 * animation frames would never finish, and the page it is waiting for would
 * never mount. The key is held across that one navigation instead: the same
 * element takes the new page, the old one leaves at once, and the next
 * ordinary navigation animates as it always did.
 */
export function PageTransition({ children }: { children: ReactNode }) {
  const { pathname, state } = useLocation();
  // The key changes with the pathname, except on a morph; a change to the
  // search or the state alone never touches it.
  const [shown, setShown] = useState({ pathname, key: pathname });
  if (shown.pathname !== pathname) {
    setShown({ pathname, key: arrivedByMorph(state) ? shown.key : pathname });
  }

  return (
    <AnimatePresence mode="wait" initial={false}>
      <motion.div
        key={shown.key}
        initial={pageTransition.initial}
        animate={pageTransition.animate}
        exit={pageTransition.exit}
      >
        {children}
      </motion.div>
    </AnimatePresence>
  );
}
