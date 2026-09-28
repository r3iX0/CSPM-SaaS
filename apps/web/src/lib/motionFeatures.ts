import { domAnimation } from "motion/react";

/**
 * The animation engine, loaded after the first paint.
 *
 * `main.tsx` hands this to `LazyMotion` as a dynamic import, so the entry
 * chunk carries only the `m` elements and the engine arrives in a chunk of its
 * own (DECISIONS.md §149). `domAnimation` rather than `domMax`: nothing here
 * animates layout or drags, and `LazyMotion strict` refuses a `motion.*`
 * element that would pull the whole engine back into the entry.
 */
export default domAnimation;
