import { Link } from "react-router-dom";
import { TriangleAlertIcon } from "lucide-react";

import { useT } from "@/i18n";
import { groupCauses } from "@/lib/collectionErrors";
import { HelpPopover } from "@/components/common/HelpPopover";
import { buttonVariants } from "@/components/ui/button";

/**
 * What the score is not charging for, in one strip.
 *
 * Two panels' worth of caveat — an assessment-coverage card and a "1 category
 * could not be collected" box — collapse into this, and it is **promoted above
 * the ranking** rather than left below it (docs/UI_REDESIGN.md §4.1). That
 * position is the argument: a reader who acts on a ranked list without knowing
 * a third of the estate was unreadable is acting on a ranking of the readable
 * third.
 *
 * It renders nothing when there is nothing to say. A caveat that is always on
 * screen is a caveat nobody reads.
 */
export function BlindSpots({
  ratio,
  gaps,
  unclassified,
  classified,
}: {
  /** Share of checks that reached a verdict. `null` before anything ran. */
  ratio: number | null;
  /** Collection failures from the latest scan, as `[category, reason]`. */
  gaps: [string, string][];
  unclassified: number;
  classified: number;
}) {
  const t = useT();

  const percent = ratio === null ? null : Math.round(ratio * 100);
  // One sentence per distinct cause: a single missing admin consent fails
  // several evidence keys with the same nine-hundred-character message.
  const causes = gaps.flatMap(([, reason]) => groupCauses(reason));
  const consentRefused = causes.some((cause) =>
    /consent|Directory\.Read|permission/i.test(cause.message),
  );
  const total = unclassified + classified;

  if (gaps.length === 0 && unclassified === 0) return null;

  return (
    <section
      aria-label={t.dashboard.blindSpots}
      className="flex flex-wrap items-start justify-between gap-4 rounded-xl border border-medium-border bg-medium-bg/30 px-5 py-4"
    >
      <div className="flex min-w-0 gap-3">
        <TriangleAlertIcon className="mt-0.5 size-4 shrink-0 text-medium" aria-hidden />
        <div className="min-w-0">
          <p className="text-[13px] font-medium text-foreground">
            {percent === null
              ? t.dashboard.blindSpotUnscored
              : t.dashboard.blindSpotTitle.replace("{percent}", `${percent}%`)}
          </p>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            {gaps.length > 0 && (
              <>
                {causes[0]?.message
                  ? `${causes[0].message.slice(0, 120)}${causes[0].message.length > 120 ? "…" : ""}`
                  : t.dashboard.blindSpotCollectors}
                {unclassified > 0 && ", and "}
              </>
            )}
            {unclassified > 0 && (
              <>
                <span className="font-mono">{unclassified}</span> of{" "}
                <span className="font-mono">{total}</span>{" "}
                {t.dashboard.blindSpotUnclassified}
              </>
            )}
            <HelpPopover label="What the score is charged for">
              {t.dashboard.blindSpotHelp}
            </HelpPopover>
          </p>
        </div>
      </div>

      {/* Two actions, and each one is the fix for one half of the sentence. */}
      <div className="flex shrink-0 flex-wrap gap-2">
        {consentRefused && (
          <Link
            to="/connections"
            className={buttonVariants({ variant: "outline", size: "sm" })}
          >
            {t.dashboard.grantConsent}
          </Link>
        )}
        {unclassified > 0 && (
          <Link
            to="/settings"
            className={buttonVariants({ variant: "outline", size: "sm" })}
          >
            {t.dashboard.classifySubscriptions}
          </Link>
        )}
      </div>
    </section>
  );
}
