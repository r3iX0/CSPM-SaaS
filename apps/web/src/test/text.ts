/**
 * Match an element by the whole sentence it renders, spans and all.
 *
 * Testing Library's default text matcher reads only an element's own text
 * nodes, so a sentence whose numerals are wrapped for the mono face --
 * `<span class="font-mono">9</span> open findings` -- stops matching the string
 * a reader actually sees. That is a presentational split, not a change to the
 * product's words, and the assertion should survive it.
 *
 * The innermost-element check keeps a query from also matching every ancestor
 * that happens to contain the same sentence.
 */
const normalise = (value: string | null | undefined) =>
  value?.replace(/\s+/g, " ").trim() ?? "";

export const wholeText =
  (expected: string) =>
  (_content: string, element: Element | null): boolean => {
    if (normalise(element?.textContent) !== expected) return false;
    return Array.from(element?.children ?? []).every(
      (child) => normalise(child.textContent) !== expected,
    );
  };

/**
 * The same idea for a partial match: the innermost element whose whole
 * rendered sentence contains the expected text or matches the pattern.
 */
export const containingText =
  (expected: string | RegExp) =>
  (_content: string, element: Element | null): boolean => {
    const hit = (value: string) =>
      typeof expected === "string" ? value.includes(expected) : expected.test(value);
    if (!hit(normalise(element?.textContent))) return false;
    return Array.from(element?.children ?? []).every(
      (child) => !hit(normalise(child.textContent)),
    );
  };
