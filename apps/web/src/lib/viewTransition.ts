/**
 * The morph from something on one page into the graph frame on the next.
 *
 * Motion (`motion`) cannot do this: it animates elements React holds, and the
 * two ends of this movement are on two pages, one unmounted before the other
 * mounts. The browser's View Transitions API can: it pictures the page before
 * and after a change and moves between the two, matching elements by name
 * (DECISIONS.md §140).
 *
 * Two rules keep it honest, and both are about not making the reader wait for
 * an animation:
 *
 * **It is an enhancement.** Where the browser has no `startViewTransition`, or
 * the reader has asked for less motion, the link is an ordinary link and the
 * page arrives as every other page does. Nothing about reading the graph
 * depends on having seen it grow.
 *
 * **It never waits long.** While the browser is between its two pictures the
 * page is frozen, so the frame gets `WAIT_MS` to appear. A link loads its graph
 * ahead (§139), so it is usually there at once; when it is not, the morph goes
 * ahead without it rather than holding a frozen page for a slow network.
 */

/** The name the source and the frame share while a morph runs. */
const NAME = "graph-frame";
/** Set on `<html>` while a morph runs, so the frame is named only then. */
const MORPHING = "cg-graph-morph";
/** How long a frozen page may wait for the frame before the morph goes ahead. */
const WAIT_MS = 300;

/** The attribute a page's graph frame carries: the one thing the morph lands on. */
export const GRAPH_FRAME = "data-graph-frame";
/** The attribute on what a link's morph starts from, when not the link itself. */
export const GRAPH_SOURCE = "data-graph-source";

/** History state a morphing navigation carries, for the page it arrives at. */
export const MORPH_STATE = { graphMorph: true } as const;

/** Whether a location was arrived at by a morph. */
export function arrivedByMorph(state: unknown): boolean {
  return (state as { graphMorph?: unknown } | null)?.graphMorph === true;
}

/** Whether this browser, for this reader, should morph at all. */
export function canMorph(): boolean {
  if (typeof document === "undefined" || typeof document.startViewTransition !== "function") {
    return false;
  }
  return !window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
}

/**
 * Picture the page with `source` named, run `go`, wait for a graph frame, and
 * move from the one to the other. Call only when `canMorph()` said yes.
 */
export function morphInto(source: HTMLElement, go: () => void): void {
  const root = document.documentElement;
  const settle = () => {
    root.classList.remove(MORPHING);
    source.style.viewTransitionName = "";
  };

  source.style.viewTransitionName = NAME;
  const transition = document.startViewTransition(async () => {
    // The first picture is taken; from here the name belongs to the frame.
    source.style.viewTransitionName = "";
    root.classList.add(MORPHING);
    go();
    await frameArrives();
  });
  transition.finished.then(settle, settle);
}

/**
 * Resolves once a graph frame is in the document, or after `WAIT_MS`.
 *
 * Timers and a mutation observer rather than animation frames: the browser
 * renders nothing while it waits for this, and a wait counted in frames that
 * are not being drawn would never end.
 */
function frameArrives(): Promise<void> {
  const present = () => document.querySelector(`[${GRAPH_FRAME}]`) !== null;
  return new Promise((resolve) => {
    // Two turns more once it is there, so what the page does on arriving -- a
    // scroll to the frame -- has happened before the second picture is taken.
    const done = () => {
      observer.disconnect();
      window.clearTimeout(timeout);
      window.setTimeout(() => window.setTimeout(resolve, 0), 0);
    };
    const observer = new MutationObserver(() => {
      if (present()) done();
    });
    const timeout = window.setTimeout(done, WAIT_MS);
    if (present()) done();
    else observer.observe(document.body, { childList: true, subtree: true });
  });
}
