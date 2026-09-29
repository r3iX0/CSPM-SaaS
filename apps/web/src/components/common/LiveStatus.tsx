import { useEffect, useRef, useState } from "react";

/**
 * How long a message must hold before it is said. A search that filters on
 * every key would otherwise queue a count per letter typed; this says the one
 * the reader stopped on.
 */
export const SETTLE_MS = 400;

/**
 * Says a change aloud that is otherwise only drawn (WCAG 4.1.3).
 *
 * Filtering a list redraws the table and the count under it while focus stays
 * in the search box or on the filter, so a screen reader heard nothing: no sign
 * the filter applied, or that it left nothing. The same held for a form whose
 * success is a panel drawn below it. This is a polite status region, mounted
 * always (a region that arrives with its text is not reliably announced), that
 * takes the `message` once it has held for `SETTLE_MS`.
 *
 * `null` means there is nothing to say yet -- loading, or failed -- and keeps
 * what was said last. With `quietFirst`, the first message is taken as the
 * starting point rather than said: a list's count on arrival is the page
 * loading, which the focused heading has already announced (DECISIONS.md
 * section 165).
 */
export function LiveStatus({
  message,
  quietFirst = false,
}: {
  message: string | null;
  quietFirst?: boolean;
}) {
  const [spoken, setSpoken] = useState("");
  // What the region last held, or would have on arrival: repeating it would
  // change nothing a screen reader can hear.
  const said = useRef<string | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (message === null) return;
    if (!started.current) {
      started.current = true;
      if (quietFirst) {
        said.current = message;
        return;
      }
    }
    if (message === said.current) return;
    const timer = window.setTimeout(() => {
      said.current = message;
      setSpoken(message);
    }, SETTLE_MS);
    return () => window.clearTimeout(timer);
  }, [message, quietFirst]);

  return (
    <p role="status" className="sr-only">
      {spoken}
    </p>
  );
}
