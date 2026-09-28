import { lazy, Suspense, useEffect, useState } from "react";
import { SearchIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Kbd } from "@/components/ui/kbd";

const loadDialog = () => import("@/components/layout/CommandPaletteDialog");
const CommandPaletteDialog = lazy(() =>
  loadDialog().then((module) => ({ default: module.CommandPaletteDialog })),
);

/**
 * The label for the shortcut, which is display only.
 *
 * Both chords are bound regardless, so a wrong guess about the platform costs a
 * reader nothing worse than a hint naming the other key.
 */
function shortcutLabel(): string {
  const mac =
    typeof navigator !== "undefined" &&
    /Mac|iPhone|iPad/.test(navigator.userAgent);
  return mac ? "\u2318K" : "Ctrl K";
}

/**
 * The palette's trigger: the header control and the ⌘K chord.
 *
 * Only this half is in the entry chunk. The dialog -- its searches, its lists
 * and cmdk with the dialog runtime cmdk brings -- is fetched the first time
 * somebody asks for it, and ahead of that when the pointer or focus reaches
 * the control (DECISIONS.md §149). Every page paid for a palette most visits
 * never open.
 */
export function CommandPalette() {
  const [open, setOpen] = useState(false);
  // Mounted from the first opening on, and kept: closing it is not a reason
  // to fetch it again.
  const [wanted, setWanted] = useState(false);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key.toLowerCase() !== "k") return;
      // Cmd on a Mac, Ctrl elsewhere. Both, rather than detecting the platform:
      // a wrong guess leaves a user with no shortcut at all.
      if (!event.metaKey && !event.ctrlKey) return;
      event.preventDefault();
      setWanted(true);
      setOpen((previous) => !previous);
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  return (
    <>
      {/* A palette nobody knows about is dead weight, and the shortcut is
          undiscoverable by construction -- so the header carries a real
          control that names the key it stands for. */}
      {/* Says what it searches. Findings are not among them -- they are
          reached through their rule or their asset -- so the placeholder does
          not promise them. */}
      <Button
        variant="outline"
        size="sm"
        onClick={() => {
          setWanted(true);
          setOpen(true);
        }}
        onPointerEnter={() => void loadDialog()}
        onFocus={() => void loadDialog()}
        className="gap-2 font-normal text-muted-foreground sm:min-w-[220px] sm:justify-start sm:text-[12.5px]"
        aria-label="Search Cleave"
      >
        <SearchIcon data-icon="inline-start" strokeWidth={1.5} />
        <span className="hidden sm:inline">Search assets, rules, pages</span>
        <Kbd className="ml-auto hidden font-mono sm:inline-flex">{shortcutLabel()}</Kbd>
      </Button>

      {wanted && (
        <Suspense fallback={null}>
          <CommandPaletteDialog open={open} onOpenChange={setOpen} />
        </Suspense>
      )}
    </>
  );
}
