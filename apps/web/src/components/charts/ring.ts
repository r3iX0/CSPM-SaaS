import type { Slice } from "@/components/charts/DonutLegend";

/**
 * The geometry of `Donut`'s ring, apart from the component so it can be tested
 * as arithmetic and so the component's module exports components only.
 */

/** The ring is 28% of the radius deep: inner edge at 72%, outer at 100%. */
export const THICKNESS = 14;
/** The centre line of the stroke, inside a 100-unit box. */
export const RADIUS = 50 - THICKNESS / 2;
export const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
/** A gap of the surface between segments, so two adjacent colours never read as one wedge. */
const GAP_DEGREES = 1.5;
/**
 * The least a present slice is drawn as. A slice worth one finding out of four
 * hundred still has to be visible: a ring that silently drops the small share
 * is the same omission as a table that truncates without saying so.
 */
const MIN_DEGREES = 4;

export interface RingArc {
  slice: Slice;
  /** Along the circumference, in viewBox units, where the arc starts. */
  offset: number;
  /** How long it is, in the same units. */
  length: number;
}

/**
 * Where each segment of the ring sits, clockwise from the top.
 *
 * A slice of nothing is not drawn -- the ring shows what the whole is made of,
 * and a zero is not part of it. Every present slice gets at least
 * `MIN_DEGREES`, taken from the slices large enough to give it, so the whole
 * still closes at 360°.
 */
export function ringArcs(slices: Slice[]): RingArc[] {
  const present = slices.filter((slice) => slice.value > 0);
  const total = present.reduce((sum, slice) => sum + slice.value, 0);
  if (total === 0) return [];

  const gap = present.length > 1 ? GAP_DEGREES : 0;
  const available = 360 - gap * present.length;
  const natural = present.map((slice) => (slice.value / total) * available);
  const small = natural.map((degrees) => degrees < MIN_DEGREES);
  const raised = small.filter(Boolean).length * MIN_DEGREES;
  const rest = natural.reduce((sum, degrees, i) => (small[i] ? sum : sum + degrees), 0);
  const scale = rest > 0 ? (available - raised) / rest : 0;
  const degrees = natural.map((value, i) => (small[i] ? MIN_DEGREES : value * scale));

  let start = 0;
  return present.map((slice, i) => {
    const arc = {
      slice,
      offset: (start / 360) * CIRCUMFERENCE,
      length: (degrees[i] / 360) * CIRCUMFERENCE,
    };
    start += degrees[i] + gap;
    return arc;
  });
}
