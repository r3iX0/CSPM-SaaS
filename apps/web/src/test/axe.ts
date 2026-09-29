import axe from "axe-core";

/**
 * The rules jsdom cannot answer, or that a unit test's fragment cannot pass.
 *
 * `color-contrast`: jsdom computes no layout and resolves no custom property,
 * so every colour is unknown; the tokens' ratios are held in `index.css` and
 * DECISIONS.md §144 and §155 instead. `region`: a test mounts one page or one
 * component without the shell, so nothing it draws is inside a landmark --
 * the shell's own test holds the landmarks down.
 */
const OFF = { "color-contrast": { enabled: false }, region: { enabled: false } };

/** What axe finds wrong with what is on the page now, one line per element. */
export async function axeViolations(context: Element = document.body): Promise<string[]> {
  const result = await axe.run(context, { rules: OFF, resultTypes: ["violations"] });
  return result.violations.flatMap((violation) =>
    violation.nodes.map(
      (node) => `${violation.id} (${violation.help}): ${node.html.slice(0, 160)}`,
    ),
  );
}
