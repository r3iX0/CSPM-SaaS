import { domMax } from "motion/react";

/**
 * The animation engine, loaded after the first paint.
 *
 * `main.tsx` hands this to `LazyMotion` as a dynamic import, so the entry
 * chunk carries only the `m` elements and the engine arrives in a chunk of its
 * own (DECISIONS.md §149). `domMax` since §179: rows that slide to their new
 * place when a filter changes, and the indicator that slides between filter
 * options and navigation rows, are layout animations, which `domAnimation`
 * does not carry. It still arrives after the first paint, so the page it draws
 * is never waiting on it; `LazyMotion strict` still refuses a `motion.*`
 * element that would pull the engine back into the entry.
 */
export default domMax;
