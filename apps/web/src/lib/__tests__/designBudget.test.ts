import { describe, expect, it } from "vitest";

import { en } from "@/i18n/en";
import { OVER_BUDGET } from "@/i18n/overBudget";

/**
 * The two budgets the interface is held to (DECISIONS.md §166): how long a
 * line of copy may run, and which font sizes exist.
 */

/** Characters. About one line of a panel at the reading size. */
const COPY_BUDGET = 90;

/** Every string leaf of the catalogue, by its dotted key. */
function strings(node: unknown, path: string[] = []): [string, string][] {
  if (typeof node === "string") return [[path.join("."), node]];
  if (!node || typeof node !== "object") return [];
  return Object.entries(node).flatMap(([key, value]) => strings(value, [...path, key]));
}

/** A key ending `Explain` is read in an `InfoTip`, where length is the point. */
const isExplain = (key: string) => /Explain$/.test(key.split(".").at(-1) ?? "");

const overBudget = strings(en)
  .filter(([key, value]) => value.length > COPY_BUDGET && !isExplain(key))
  .map(([key]) => key);

describe("copy budget", () => {
  it("holds every new string to one line, or to an Explain key", () => {
    const allowed = new Set(OVER_BUDGET);
    expect(overBudget.filter((key) => !allowed.has(key))).toEqual([]);
  });

  it("drops a shortened string from the baseline, so the list only shrinks", () => {
    const over = new Set(overBudget);
    expect(OVER_BUDGET.filter((key) => !over.has(key))).toEqual([]);
  });
});

/**
 * Source text of every module but the vendored primitives and the tests. Read
 * through Vite's glob rather than `fs`, so the check needs no Node globals.
 */
const sources = import.meta.glob<string>(
  ["/src/**/*.{ts,tsx}", "!/src/components/ui/**", "!/src/**/__tests__/**", "!/src/test/**"],
  { query: "?raw", import: "default", eager: true },
);

describe("type scale", () => {
  it("names a font size by its step, never as text-[Npx]", () => {
    const offenders = Object.entries(sources).flatMap(([file, text]) =>
      [...text.matchAll(/text-\[\d+(?:\.\d+)?px\]/g)].map((match) => `${file}: ${match[0]}`),
    );
    expect(Object.keys(sources).length).toBeGreaterThan(100);
    expect(offenders).toEqual([]);
  });
});
