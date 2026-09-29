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
 * Whether the key landed on something that answers keys itself -- a link, a
 * button, a tab, a canvas. `Enter` there is that control's, not the list's: a
 * reader who marked a row with `j` and then tabbed to a button pressed the
 * button, and used to be sent to the marked row instead.
 */
export function isControlTarget(target: EventTarget | null): boolean {
  return (
    target instanceof HTMLElement && target !== document.body && target.tabIndex >= 0
  );
}

/** Where the single-key preference lives. Per browser, like the theme. */
const SINGLE_KEY_STORAGE = "cloudguard.shortcuts.single-key";
const SINGLE_KEY_EVENT = "cloudguard:single-key-shortcuts";

/** The choice made in this page's life, for a browser whose storage refused it. */
let singleKeyOverride: boolean | null = null;

/**
 * Whether the one-letter shortcuts are on -- `g` then a letter, `/`, `?`,
 * `j`/`k`/`x`/`o` and `Enter` on a marked row.
 *
 * On unless turned off. They stand down in fields, but a reader driving the
 * page by speech says words, and a word spoken outside a field arrives as its
 * letters: "go" is `g` then `o`, which opened the overview. WCAG 2.1.4 asks that
 * shortcuts made of one character can be turned off, and the switch is in the
 * shortcuts sheet, which the palette opens with a modifier.
 */
export function singleKeyShortcutsOn(): boolean {
  try {
    return localStorage.getItem(SINGLE_KEY_STORAGE) !== "off";
  } catch {
    return true;
  }
}

export function setSingleKeyShortcuts(on: boolean): void {
  try {
    if (on) localStorage.removeItem(SINGLE_KEY_STORAGE);
    else localStorage.setItem(SINGLE_KEY_STORAGE, "off");
  } catch {
    // Storage refused: the choice lasts until the page is reloaded.
  }
  singleKeyOverride = on;
  window.dispatchEvent(new Event(SINGLE_KEY_EVENT));
}

/** Whether a plain key press should be read as a shortcut at all. */
export function singleKeyShortcut(event: KeyboardEvent): boolean {
  if (!plainKey(event) || isTypingTarget(event.target) || dialogOpen()) return false;
  return singleKeyOverride ?? singleKeyShortcutsOn();
}

/** The preference, kept current for the switch that shows it. */
export function useSingleKeyShortcuts(): boolean {
  const [on, setOn] = useState(() => singleKeyOverride ?? singleKeyShortcutsOn());
  useEffect(() => {
    const read = () => setOn(singleKeyOverride ?? singleKeyShortcutsOn());
    window.addEventListener(SINGLE_KEY_EVENT, read);
    return () => window.removeEventListener(SINGLE_KEY_EVENT, read);
  }, []);
  return on;
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
      if (!singleKeyShortcut(event)) return;
      if (hrefs.length === 0) return;
      if (event.key === "j") {
        event.preventDefault();
        setActive((index) => Math.min(index + 1, hrefs.length - 1));
      } else if (event.key === "k") {
        event.preventDefault();
        setActive((index) => Math.max(index - 1, 0));
      } else if (
        (event.key === "Enter" || event.key === "o") &&
        active >= 0 &&
        !isControlTarget(event.target)
      ) {
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
