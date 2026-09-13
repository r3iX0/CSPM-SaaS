import { useEffect, useRef, useState } from "react";

/**
 * Whether this reader has asked the operating system for less motion.
 *
 * Consulted rather than assumed, and consulted live: somebody who turns it on
 * mid-session has said something about how they want to be treated, and a
 * dashboard that keeps animating until reload has not listened.
 *
 * Everything in this file degrades to *the final state, immediately* — never to
 * a slower version of the animation. Reduced motion means arriving, not
 * crawling.
 */
export function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() => {
    if (typeof window === "undefined" || !window.matchMedia) return false;
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  });

  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    const onChange = () => setReduced(query.matches);
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, []);

  return reduced;
}

/**
 * A number that counts up to its value.
 *
 * Two rules, and both are about not lying with motion:
 *
 * **It animates when the value changes, not when the component renders.** The
 * dashboard polls every twenty seconds; a count-up on every refetch would make
 * a page nobody touched twitch four times a minute, and a reader would learn to
 * distrust movement that means nothing.
 *
 * **It always ends on the exact value.** The easing is applied to the fraction
 * of the distance travelled, and the last frame is assigned rather than
 * interpolated, so a security score never settles on 71 because a float landed
 * short.
 */
export function useCountUp(value: number, durationMs = 650): number {
  const reduced = usePrefersReducedMotion();
  const [shown, setShown] = useState(value);
  const previous = useRef(value);

  useEffect(() => {
    const from = previous.current;
    previous.current = value;

    if (reduced || from === value) {
      setShown(value);
      return;
    }

    let frame = 0;
    const started = performance.now();

    const step = (now: number) => {
      const elapsed = now - started;
      if (elapsed >= durationMs) {
        setShown(value);
        return;
      }
      // Ease-out cubic: fast enough to feel immediate, slow enough at the end
      // that the reader's eye lands on the final digits rather than chasing.
      const progress = 1 - Math.pow(1 - elapsed / durationMs, 3);
      setShown(from + (value - from) * progress);
      frame = requestAnimationFrame(step);
    };

    frame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame);
  }, [value, durationMs, reduced]);

  return shown;
}

/**
 * A list that arrives a row at a time.
 *
 * Capped, deliberately: past about eight rows the stagger stops reading as
 * arrival and starts reading as a slow page, so later rows share the last
 * delay. Returns a style rather than a class so a caller can put it on whatever
 * element it already has.
 */
export function stagger(index: number, stepMs = 30): { animationDelay: string } {
  return { animationDelay: `${Math.min(index, 8) * stepMs}ms` };
}

/* -------------------------------------------------------------------------
 * Shared motion vocabulary
 *
 * The two hooks above animate numbers, which CSS cannot do. Everything below
 * animates elements, and exists because a React SPA cannot express one thing in
 * CSS at all: *exit*. A route that unmounts has no frames left to animate in,
 * so a page swap either cuts hard or the outgoing tree has to be kept alive by
 * something that knows it is leaving -- which is what `AnimatePresence` is for,
 * and is the reason a motion runtime is here rather than another keyframe.
 *
 * Timings and easings are declared once, here, rather than typed into each
 * component. Motion in this product is a claim that something arrived or
 * changed, and a dashboard where six panels each picked their own duration
 * makes six different claims about the same event.
 *
 * Reduced motion is answered in one place -- `<MotionConfig reducedMotion="user">`
 * in `main.tsx` -- exactly as the CSS half is answered by one media query in
 * `index.css`. Nothing below needs to check it, and nothing below should.
 * ---------------------------------------------------------------------- */

/** Milliseconds, shared with the chart libraries so a bar and a card agree. */
export const DURATION = {
  /** Hover, press, colour: fast enough to feel like the pointer did it. */
  instant: 120,
  /** The default. A panel arriving, a row appearing. */
  quick: 180,
  /** A page swapping, a drawer opening -- far enough to need the time. */
  page: 240,
  /** Charts drawing themselves. Longer, because the eye follows a path. */
  chart: 600,
} as const;

/** Ease-out: leaves immediately, settles gently. Movement the reader caused. */
export const EASE_OUT = [0.16, 1, 0.3, 1] as const;
/** Ease-in: for things leaving, which should not linger. */
export const EASE_IN = [0.4, 0, 1, 1] as const;

/**
 * A page arriving and leaving.
 *
 * Exit is deliberately shorter than enter and moves the other way. A swap where
 * both halves take the same time reads as a crossfade of two pages; a short
 * exit followed by a longer enter reads as one page replacing another.
 */
export const pageTransition = {
  initial: { opacity: 0, y: 6 },
  animate: {
    opacity: 1,
    y: 0,
    transition: { duration: DURATION.page / 1000, ease: EASE_OUT },
  },
  exit: {
    opacity: 0,
    y: -4,
    transition: { duration: DURATION.instant / 1000, ease: EASE_IN },
  },
} as const;

/** A panel or card arriving. The same rise the CSS `cg-rise` keyframe makes. */
export const fadeUp = {
  initial: { opacity: 0, y: 8 },
  animate: {
    opacity: 1,
    y: 0,
    transition: { duration: DURATION.quick / 1000, ease: EASE_OUT },
  },
} as const;

/**
 * A list whose rows arrive one at a time.
 *
 * There is no "animate on mount only" flag here, and none is needed: a motion
 * element runs `initial` when it mounts and never again, so a keyed row that
 * survives a refetch does not replay. That is exactly the rule this product
 * wants -- the dashboard polls every twenty seconds, and movement has to mean
 * something arrived rather than that a request came back. Keep the keys stable
 * and the animation stays honest.
 */
export const listContainer = {
  initial: {},
  animate: { transition: { staggerChildren: 0.03, delayChildren: 0.02 } },
} as const;

export const listItem = {
  initial: { opacity: 0, y: 6 },
  animate: {
    opacity: 1,
    y: 0,
    transition: { duration: DURATION.quick / 1000, ease: EASE_OUT },
  },
} as const;
