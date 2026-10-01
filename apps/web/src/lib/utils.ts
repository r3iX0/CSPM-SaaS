import { clsx, type ClassValue } from "clsx";
import { extendTailwindMerge } from "tailwind-merge";

/**
 * The type scale's steps, as `index.css` names them (DECISIONS.md §166).
 *
 * tailwind-merge knows Tailwind's own sizes and nothing else, so it reads an
 * unfamiliar `text-*` as a colour -- and `cn("text-body", "text-muted-foreground")`
 * would then drop the size as a duplicate colour. Telling it the names keeps a
 * size and a colour on one element.
 */
export const TYPE_SCALE = [
  "micro",
  "caption",
  "meta",
  "body",
  "title",
  "heading",
  "page",
  "stat",
  "display",
] as const;

const twMerge = extendTailwindMerge({
  extend: { classGroups: { "font-size": [{ text: [...TYPE_SCALE] }] } },
});

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
