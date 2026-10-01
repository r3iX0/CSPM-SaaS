import { Link } from "react-router-dom";

import type { ChangeEvent } from "@/lib/types";
import { useT } from "@/i18n";
import { changeDirection } from "@/lib/changes";
import { stagger } from "@/lib/motion";
import { buttonVariants } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, formatDate, label } from "@/lib/format";

/**
 * What moved, in the week the rest of this page cannot see.
 *
 * Every other panel is a photograph of now. This is the only one that answers
 * the question somebody actually asks after a week of other people's
 * deployments, and it is deliberately short: five rows and a way through.
 *
 * A movement is coloured only when it *is* one. An attribute that changed into
 * UNKNOWN is a loss of knowledge, not an improvement -- colouring it green
 * would be the one lie this product exists to refuse -- so it is neutral, as is
 * an asset disappearing. Something new is marked in the brand, which means
 * "look here", not "this is bad". Each pill says its word, so none of it rests
 * on colour.
 */
export function RecentChanges({
  events,
  loading,
}: {
  events: ChangeEvent[] | undefined;
  loading: boolean;
}) {
  const t = useT();
  const rows = Array.isArray(events) ? events.slice(0, 5) : [];

  return (
    <section
      aria-labelledby="recent-changes"
      className="flex flex-col overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <header className="flex items-start justify-between gap-4 px-5 py-4">
        <h2 id="recent-changes" className="text-body font-semibold">
          What moved this week
        </h2>
        <Link
          to="/changes"
          className={cn(buttonVariants({ variant: "outline", size: "sm" }), "shrink-0")}
        >
          All changes
        </Link>
      </header>

      <div className="flex-1 border-t">
        {loading && (
          <div className="flex flex-col gap-3 px-5 py-4">
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-4 w-2/3" />
            <Skeleton className="h-4 w-1/2" />
          </div>
        )}

        {!loading && rows.length === 0 && (
          <p className="px-5 py-5 text-body leading-relaxed text-muted-foreground">
            {t.changes.empty}. A quiet week, not a gap in the record.
          </p>
        )}

        {!loading && rows.length > 0 && (
          <ul className="divide-y">
            {rows.map((event, index) => (
              <ChangeLine key={event.id} event={event} index={index} />
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

const PILL = {
  new: "border-primary-border bg-primary-soft text-foreground",
  worse: "border-critical-border bg-critical-bg text-critical",
  better: "border-ok-border bg-ok-bg text-ok",
  neutral: "border-border bg-muted text-muted-foreground",
} as const;

function ChangeLine({ event, index }: { event: ChangeEvent; index: number }) {
  const t = useT();
  const attribute = event.change.endsWith("_CHANGED");
  const moved = attribute ? changeDirection(event.previous_value, event.current_value) : "neutral";

  const [word, tone] =
    event.change === "APPEARED"
      ? (["New", PILL.new] as const)
      : event.change === "DISAPPEARED"
        ? (["Gone", PILL.neutral] as const)
        : moved === "worse"
          ? (["Worse", PILL.worse] as const)
          : moved === "better"
            ? (["Better", PILL.better] as const)
            : (["Changed", PILL.neutral] as const);

  return (
    <li
      className="flex items-center gap-3 px-5 py-3 [animation:cg-rise_260ms_ease-out_both]"
      style={stagger(index)}
    >
      <p className="min-w-0 flex-1 truncate text-body">
        <Link to={`/assets/${event.asset.id}`} className="font-medium hover:underline">
          {event.asset.name}
        </Link>
        <span className="text-muted-foreground">
          {" — "}
          {t.changes.kind[event.change]}
          {attribute && event.previous_value && event.current_value && (
            <>
              {": "}
              {label(event.previous_value)} → {label(event.current_value)}
            </>
          )}
        </span>
      </p>
      <span className="shrink-0 text-caption text-muted-foreground tabular-nums">
        {formatDate(event.observed_at)}
      </span>
      <span
        className={cn(
          "inline-flex shrink-0 rounded-full border px-2 py-px text-caption font-medium",
          tone,
        )}
      >
        {word}
      </span>
    </li>
  );
}
