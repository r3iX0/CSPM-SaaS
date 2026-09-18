/**
 * A live dot with a sentence, for the two steps that wait on somebody else.
 *
 * A pulse rather than a spinner. A spinner says "this request is in flight",
 * which is not what is happening: nothing is loading, the page is listening for
 * a grant that somebody else has to give, and re-reading the connection every
 * few seconds while it does. The pulse is the convention for exactly that -- a
 * live channel -- and the second line says the part a spinner never could:
 * that the reader does not have to stay and watch it.
 *
 * Only rendered while waiting is still a plausible explanation. Once a
 * deployment has stalled this is replaced rather than kept company: a live
 * indicator that never resolves claims progress that is not happening, and
 * gives no way to tell a colleague who has not got round to it from a
 * deployment that failed outright.
 */
export function WaitingNote({ text, detail }: { text: string; detail?: string }) {
  return (
    <div
      role="status"
      className="flex items-start gap-3 rounded-lg border border-dashed border-border px-4 py-3"
    >
      <span className="relative mt-1.5 flex size-2 shrink-0" aria-hidden>
        <span className="absolute inline-flex size-full animate-ping rounded-full bg-foreground/40" />
        <span className="relative inline-flex size-2 rounded-full bg-foreground/70" />
      </span>
      <span className="min-w-0">
        <span className="block text-sm font-medium text-foreground">{text}</span>
        {detail && (
          <span className="mt-0.5 block text-xs leading-relaxed text-muted-foreground">
            {detail}
          </span>
        )}
      </span>
    </div>
  );
}
