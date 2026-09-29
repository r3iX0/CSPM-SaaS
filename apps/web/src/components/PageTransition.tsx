import { useEffect, useState, type ReactNode } from "react";
import { useLocation } from "react-router-dom";
import { AnimatePresence, m } from "motion/react";

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
      <m.div
        key={shown.key}
        initial={pageTransition.initial}
        animate={pageTransition.animate}
        exit={pageTransition.exit}
      >
        {children}
        <FocusOnArrival />
      </m.div>
    </AnimatePresence>
  );
}

/** Whether the app has shown a page yet: the first one is arrived at by loading. */
let arrivedOnce = false;

/**
 * Where the keyboard is when a new page arrives.
 *
 * A browser that loads a page starts the reader at its top; a router that
 * swaps one does nothing, and the link that was pressed is usually unmounted
 * with the page it sat on, so focus fell to `<body>` -- the next Tab restarted
 * at the navigation, and a screen reader said nothing about where it was. Focus
 * goes to the page's heading, which a screen reader reads out, or to `<main>`
 * while the page is still loading and has none (WCAG 2.4.3).
 *
 * Mounted inside the keyed element, so it runs when the new page is in the
 * document and not before -- the outgoing page leaves first (`mode="wait"`).
 * Not on the first page, which the browser already started at the top, and
 * not on a morph into the graph, which keeps the key and whose panel places
 * focus itself.
 */
function FocusOnArrival() {
  useEffect(() => {
    if (!arrivedOnce) {
      arrivedOnce = true;
      return;
    }
    const main = document.getElementById("main-content");
    if (!main) return;
    const heading = main.querySelector<HTMLElement>("h1");
    if (heading) {
      heading.tabIndex = -1;
      heading.style.outline = "none";
    }
    (heading ?? main).focus({ preventScroll: true });
  }, []);
  return null;
}
