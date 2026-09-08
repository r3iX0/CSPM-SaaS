import * as React from "react";

const MOBILE_BREAKPOINT = 768;

/**
 * Whether this is a viewport the sidebar should be a sheet on.
 *
 * Upstream starts at `undefined` and fills the answer in from an effect, which
 * renders one frame of "not mobile" on every phone and trips this project's
 * lint rule against setting state in an effect. Read the query up front
 * instead: `matchMedia` is synchronous, and the initial answer is as reliable
 * as the one an effect would have written a frame later.
 *
 * Guarded for the case where `matchMedia` does not exist, which is the test
 * environment and any server render: no media query means no small screen.
 */
function query(): boolean {
  if (typeof window === "undefined" || !window.matchMedia) return false;
  return window.matchMedia(`(max-width: ${MOBILE_BREAKPOINT - 1}px)`).matches;
}

export function useIsMobile() {
  const [isMobile, setIsMobile] = React.useState(query);

  React.useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mql = window.matchMedia(`(max-width: ${MOBILE_BREAKPOINT - 1}px)`);
    const onChange = () => setIsMobile(mql.matches);
    mql.addEventListener("change", onChange);
    return () => mql.removeEventListener("change", onChange);
  }, []);

  return isMobile;
}
