import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";

/**
 * A page's filters, held in the URL rather than in component state.
 *
 * Filters in state vanished on reload, did not survive the back button, and
 * could not be sent to anybody: "look at the critical open findings on the
 * storage accounts" had to be said in words and rebuilt by hand. In the URL a
 * filtered view is a link -- bookmarkable, shareable, restorable -- and a link
 * *into* a filtered view (the dashboard's severity tiles, a control's evidence)
 * is the same mechanism rather than a special case each page parses.
 *
 * A value equal to its default is left out of the URL, so an unfiltered page
 * has a clean address and "clear filters" is literally the bare path.
 *
 * Updates are patches written in one call, because two separate writes in the
 * same event would each start from the same snapshot and the second would put
 * back what the first removed -- changing a filter and resetting the page is
 * exactly that pair. Written with `replace`, so narrowing a list does not fill
 * the history with every intermediate state the reader passed through.
 */
export function useUrlFilters<K extends string>(
  defaults: Record<K, string>,
): [Record<K, string>, (patch: Partial<Record<K, string | null>>) => void] {
  const [params, setParams] = useSearchParams();
  // Defaults are a literal at the call site, so a new object every render.
  // Keyed on their content, so the updater stays stable for effects that
  // depend on it and changes only if the defaults themselves do.
  const defaultsKey = JSON.stringify(defaults);
  const stableDefaults = useMemo(
    () => JSON.parse(defaultsKey) as Record<K, string>,
    [defaultsKey],
  );

  const values = {} as Record<K, string>;
  for (const key of Object.keys(defaults) as K[]) {
    values[key] = params.get(key) ?? defaults[key];
  }

  const update = useCallback(
    (patch: Partial<Record<K, string | null>>) => {
      setParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          for (const [key, value] of Object.entries(patch) as [K, string | null | undefined][]) {
            if (value === null || value === undefined || value === stableDefaults[key]) {
              next.delete(key);
            } else {
              next.set(key, value);
            }
          }
          return next;
        },
        { replace: true },
      );
    },
    [setParams, stableDefaults],
  );

  return [values, update];
}
