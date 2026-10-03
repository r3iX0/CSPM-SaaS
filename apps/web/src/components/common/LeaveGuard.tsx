import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { useT } from "@/i18n";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

/**
 * Asks before an edit nobody saved is thrown away (DECISIONS.md §207).
 *
 * Rendered beside the form it guards, with `dirty` while the form differs from
 * what was saved.
 *
 * React Router's own `useBlocker` needs a data router, and this app has none
 * (`App.tsx`), so the guard works at the two places a person actually leaves
 * from. Closing or reloading the tab is the browser's `beforeunload`, which
 * shows the browser's own question. Following a link inside the app is caught
 * on the way down: a capturing listener on the document runs before React's
 * listener at the root, so a `Link` never hears a click this stops, and the
 * dialog asks instead. "Discard and leave" then navigates to where the link
 * pointed.
 *
 * What it does not catch is the browser's Back button, which reaches no click
 * and which `popstate` reports only after the history has already moved.
 */
export function LeaveGuard({ dirty }: { dirty: boolean }) {
  const t = useT();
  const navigate = useNavigate();
  const [pending, setPending] = useState<string | null>(null);

  useEffect(() => {
    if (!dirty) return;

    function onBeforeUnload(event: BeforeUnloadEvent) {
      event.preventDefault();
    }

    function onClick(event: MouseEvent) {
      // A click that is not a plain navigation in this tab is left alone: a
      // new tab keeps this one, and its edit with it.
      if (event.defaultPrevented || event.button !== 0) return;
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      const anchor = (event.target as Element | null)?.closest?.("a[href]");
      if (!(anchor instanceof HTMLAnchorElement)) return;
      if (anchor.target && anchor.target !== "_self") return;
      if (anchor.hasAttribute("download")) return;

      const url = new URL(anchor.href, window.location.href);
      if (url.origin !== window.location.origin) return;
      // Same page: a jump to a heading leaves the edit where it is.
      if (url.pathname === window.location.pathname && url.search === window.location.search) {
        return;
      }

      event.preventDefault();
      event.stopPropagation();
      setPending(`${url.pathname}${url.search}${url.hash}`);
    }

    window.addEventListener("beforeunload", onBeforeUnload);
    document.addEventListener("click", onClick, true);
    return () => {
      window.removeEventListener("beforeunload", onBeforeUnload);
      document.removeEventListener("click", onClick, true);
    };
  }, [dirty]);

  return (
    <AlertDialog
      open={pending !== null}
      onOpenChange={(open) => {
        if (!open) setPending(null);
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{t.settings.leaveTitle}</AlertDialogTitle>
          <AlertDialogDescription>{t.settings.leaveDetail}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>{t.settings.leaveStay}</AlertDialogCancel>
          <AlertDialogAction
            variant="destructive"
            onClick={() => {
              const to = pending;
              setPending(null);
              if (to) void navigate(to);
            }}
          >
            {t.settings.leaveGo}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
