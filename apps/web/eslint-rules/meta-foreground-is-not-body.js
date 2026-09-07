/**
 * `--meta-foreground` and `--faint-foreground` may not carry body text.
 *
 * The two greys below `--muted-foreground` measure 4.11:1 and 3.20:1 on the
 * card in dark, 3.95:1 and 3.24:1 in light. Neither clears AA for body text,
 * and they are kept at those values on purpose: raising both to 4.5:1 lands
 * them on the same colour and destroys the two-step distinction the design uses
 * them for (DECISIONS.md §84). The constraint that makes that acceptable is
 * that they only ever appear in the 11-12.5px meta register.
 *
 * Until now that constraint lived in a comment and a decision record, which is
 * the state where the next person pairs one with `text-lg` in good faith. It is
 * the last item in `docs/UI_REDESIGN.md` §7.
 *
 * **Deliberately conservative.** It reports a meta colour paired with an
 * explicitly larger size in the same class list, and nothing else. It does not
 * demand that a size be stated: `<span className="text-meta-foreground">`
 * inside a `text-xs` parent is correct and common, and a rule that flagged it
 * would be a rule people turn off. So this catches the mistake that is visible
 * in one string and cannot catch one made across two elements -- which is worth
 * saying out loud rather than implying the check is complete.
 */

const META_COLOURS = /\btext-(meta|faint)-foreground\b/;

/** Anything at or above 13px, which is where the body register starts. */
const NAMED_TOO_LARGE = /\btext-(sm|base|lg|xl|[2-9]xl)\b/;
const ARBITRARY = /\btext-\[(\d+(?:\.\d+)?)px\]/g;

/** The top of the meta register: 12.5px meta, 11px section label. */
const META_CEILING_PX = 12.5;

function tooLargeIn(text) {
  const named = NAMED_TOO_LARGE.exec(text);
  if (named) return named[0];

  ARBITRARY.lastIndex = 0;
  let match;
  while ((match = ARBITRARY.exec(text)) !== null) {
    if (Number(match[1]) > META_CEILING_PX) return match[0];
  }
  return null;
}

export const metaForegroundIsNotBody = {
  meta: {
    type: "problem",
    docs: {
      description:
        "Keep --meta-foreground and --faint-foreground in the meta register; neither clears AA for body text.",
    },
    schema: [],
    messages: {
      tooLarge:
        "`{{colour}}` is below AA for body text ({{ratio}} on the card) and is paired here with `{{size}}`. Use `text-muted-foreground` for anything in the body register, or drop the size to the 11-12.5px meta register (DECISIONS.md §84).",
    },
  },

  create(context) {
    /** Both the `className="..."` case and the strings inside `cn(...)`. */
    function check(node, text) {
      if (typeof text !== "string") return;
      const colour = META_COLOURS.exec(text);
      if (!colour) return;

      const size = tooLargeIn(text);
      if (!size) return;

      context.report({
        node,
        messageId: "tooLarge",
        data: {
          colour: colour[0],
          size,
          ratio: colour[1] === "faint" ? "3.20:1" : "4.11:1",
        },
      });
    }

    return {
      Literal(node) {
        check(node, node.value);
      },
      TemplateElement(node) {
        check(node, node.value.cooked);
      },
    };
  },
};
