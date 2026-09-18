import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import { SHORTCUTS_EVENT, isTypingTarget, plainKey } from "@/lib/keyboard";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Kbd, KbdGroup } from "@/components/ui/kbd";

/** `g` then a letter: the pages a reader moves between most. */
const GO: Record<string, { to: string; label: string }> = {
  o: { to: "/", label: "Overview" },
  f: { to: "/findings", label: "Findings" },
  r: { to: "/risks", label: "Risks" },
  p: { to: "/attack-paths", label: "Attack paths" },
  a: { to: "/assets", label: "Assets" },
  m: { to: "/remediation", label: "Remediation" },
  c: { to: "/compliance", label: "Compliance" },
  s: { to: "/scans", label: "Scans" },
};

/** How long `g` waits for its letter before it is just a `g`. */
const SEQUENCE_MS = 1000;

/**
 * The product's keyboard, and the sheet that lists it.
 *
 * Mounted once in the shell. Three kinds of key, and all of them stand down
 * while the reader is typing or a dialog is open:
 *
 * * `g` then a letter goes to a page -- two keys rather than one, so a stray
 *   letter never navigates anywhere.
 * * `/` focuses the page's own search, wherever it is on the page. Pages mark
 *   theirs with `data-page-search`; a page without one ignores the key.
 * * `?` opens this sheet. Lists add `j`/`k`/`Enter` themselves
 *   (`useRowNavigation`), and ⌘K is the palette's own.
 */
export function KeyboardShortcuts() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const pendingG = useRef<number | null>(null);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (!plainKey(event) || isTypingTarget(event.target)) return;
      if (document.querySelector('[role="dialog"], [role="alertdialog"]')) return;

      if (pendingG.current !== null) {
        const target = GO[event.key];
        window.clearTimeout(pendingG.current);
        pendingG.current = null;
        if (target) {
          event.preventDefault();
          navigate(target.to);
        }
        return;
      }

      if (event.key === "g") {
        pendingG.current = window.setTimeout(() => {
          pendingG.current = null;
        }, SEQUENCE_MS);
      } else if (event.key === "/") {
        const search = document.querySelector<HTMLInputElement>("[data-page-search]");
        if (search) {
          event.preventDefault();
          search.focus();
          search.select();
        }
      } else if (event.key === "?") {
        event.preventDefault();
        setOpen(true);
      }
    }

    const onRequest = () => setOpen(true);
    document.addEventListener("keydown", onKeyDown);
    window.addEventListener(SHORTCUTS_EVENT, onRequest);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      window.removeEventListener(SHORTCUTS_EVENT, onRequest);
      if (pendingG.current !== null) window.clearTimeout(pendingG.current);
    };
  }, [navigate]);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Keyboard shortcuts</DialogTitle>
          <DialogDescription>
            None of these fire while you are typing in a field.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-6 sm:grid-cols-2">
          <ShortcutGroup title="Anywhere">
            <Shortcut keys={["⌘", "K"]} label="Search and actions" />
            <Shortcut keys={["/"]} label="Search this page" />
            <Shortcut keys={["?"]} label="This sheet" />
          </ShortcutGroup>
          <ShortcutGroup title="In a list">
            <Shortcut keys={["j"]} label="Next row" />
            <Shortcut keys={["k"]} label="Previous row" />
            <Shortcut keys={["Enter"]} label="Open the row" />
          </ShortcutGroup>
          <ShortcutGroup title="Go to" className="sm:col-span-2">
            <div className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
              {Object.entries(GO).map(([key, target]) => (
                <Shortcut key={key} keys={["g", key]} label={target.label} />
              ))}
            </div>
          </ShortcutGroup>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function ShortcutGroup({
  title,
  className,
  children,
}: {
  title: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <section className={className}>
      <h3 className="mb-2 text-xs font-medium text-muted-foreground">{title}</h3>
      <div className="flex flex-col gap-2">{children}</div>
    </section>
  );
}

function Shortcut({ keys, label }: { keys: string[]; label: string }) {
  return (
    <div className="flex items-center justify-between gap-3 text-sm">
      <span className="text-foreground">{label}</span>
      <KbdGroup>
        {keys.map((key, index) => (
          <Kbd key={`${key}-${index}`}>{key}</Kbd>
        ))}
      </KbdGroup>
    </div>
  );
}
