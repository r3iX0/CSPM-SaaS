import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

/** Fired to open the shortcuts sheet from anywhere, the palette included. */
export const SHORTCUTS_EVENT = "cloudguard:shortcuts";

/**
 * Whether a key press belongs to something the reader is typing into.
 *
 * Every single-key shortcut has to stand down here: `j` in a search box is a
 * letter, not "next row", and a shortcut that ate it would make the product's
 * search boxes unusable for any word with a j in it.
 */
export function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
}

/** Whether a modal is up -- its own keys win, and the page behind it is inert. */
export function dialogOpen(): boolean {
  return document.querySelector('[role="dialog"], [role="alertdialog"]') !== null;
}

/** A plain key, with no modifier held -- ⌘K and friends are somebody else's. */
export function plainKey(event: KeyboardEvent): boolean {
  return !event.metaKey && !event.ctrlKey && !event.altKey;
}

/**
 * `j` and `k` through a list, `Enter` to open the row that is marked.
 *
 * The convention of every keyboard-first tool a security engineer already uses
 * -- mail clients, issue trackers, the terminal pager -- so it needs no
 * teaching beyond the `?` sheet. Nothing is marked until the first `j`, so a
 * reader who never touches the keyboard sees no highlight they did not ask for.
 *
 * The mark resets when the list changes: a new filter or page is a new list,
 * and row 7 of the old one means nothing in it.
 */
export function useRowNavigation(hrefs: string[]): number {
  const navigate = useNavigate();
  const listKey = hrefs.join("|");
  const [active, setActive] = useState(-1);
  const [seenKey, setSeenKey] = useState(listKey);
  if (seenKey !== listKey) {
    setSeenKey(listKey);
    setActive(-1);
  }

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (!plainKey(event) || isTypingTarget(event.target) || dialogOpen()) return;
      if (hrefs.length === 0) return;
      if (event.key === "j") {
        event.preventDefault();
        setActive((index) => Math.min(index + 1, hrefs.length - 1));
      } else if (event.key === "k") {
        event.preventDefault();
        setActive((index) => Math.max(index - 1, 0));
      } else if ((event.key === "Enter" || event.key === "o") && active >= 0) {
        event.preventDefault();
        navigate(hrefs[active]);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
    // `listKey` stands in for `hrefs`, which is a new array every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, listKey, navigate]);

  useEffect(() => {
    if (active < 0) return;
    document
      .querySelector(`[data-row-index="${active}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [active]);

  return active;
}

/**
 * The classes a keyboard-marked row wears: a tint and a bar on its leading
 * edge, so the mark reads as position rather than as a selection or a hover.
 */
export const ROW_ACTIVE =
  "data-[active=true]:bg-muted/60 data-[active=true]:shadow-[inset_2px_0_0_var(--foreground)]";
