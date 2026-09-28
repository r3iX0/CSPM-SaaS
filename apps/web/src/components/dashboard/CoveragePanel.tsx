import { useState } from "react";
import { Link } from "react-router-dom";
import { ClockIcon } from "lucide-react";

import type { Dashboard } from "@/lib/types";
import { groupCauses } from "@/lib/collectionErrors";
import { Donut } from "@/components/charts/Donut";
import type { Slice } from "@/components/charts/DonutLegend";
import { buttonVariants } from "@/components/ui/button";
import { cn, label } from "@/lib/format";

type Category = NonNullable<Dashboard["coverage"]["categories"]>[number];

/**
 * How much of the environment the numbers above were actually formed from.
 *
 * Most security products hide this. A coverage figure is an admission that the
 * scan did not see everything, and the temptation is to report the score and
 * let the reader assume it was complete — which is how a customer ends up
 * trusting an 84 computed over the half of their estate CloudGuard could read.
 *
 * Four separate facts, and they are not interchangeable: what fraction of
 * checks reached a verdict, which categories of evidence could not be read,
 * how old the readings are, and how much of the estate CloudGuard could not
 * classify. A fully covered estate can be three weeks stale, and a fresh
 * reading can cover half of one.
 *
 * The last of those is the one the score used to quietly spend. Missing
 * evidence never becomes a finding, so it never reached the number; missing
 * *context* did, because the risk formula ranks an unknown criticality just
 * under High so an unlabelled asset never sorts below a labelled one. That
 * caution belongs to the ordering. Charging a posture number for it told a
 * customer their estate was worse when the honest sentence was that CloudGuard
 * could not tell — so it is stated here, as work they can do, instead.
 *
 * The percentage is never phrased as security. 94% coverage is not 94% secure;
 * it is the share of checks that reached *any* verdict, pass or fail.
 */
export function CoveragePanel({
  ratio,
  unknown,
  conclusive,
  categories = [],
  context,
  gaps = [],
  freshness,
}: {
  ratio: number | null;
  unknown: number;
  conclusive: number;
  categories?: Category[];
  context?: { unclassified: number; classified: number; ratio: number };
  gaps?: [string, string][];
  freshness?: { readings: number; stale_hours: number | null; unusable: number } | null;
}) {
  const pct = ratio === null ? null : Math.round(ratio * 100);
  const complete = unknown === 0 && gaps.length === 0;

  return (
    <section
      aria-labelledby="assessment-coverage"
      className="overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <div className="flex flex-wrap items-start justify-between gap-x-8 gap-y-4 px-5 py-4">
        <div className="min-w-0">
          <h2 id="assessment-coverage" className="text-[13.5px] font-semibold">
            Assessment coverage
          </h2>
          <p className="mt-1 max-w-xl text-xs leading-relaxed text-muted-foreground">
            {complete
              ? "Every applicable check reached a verdict from evidence Cleave could read."
              : "Share of checks that reached a verdict — not a security score. What can't be read reports no verdict, never a pass."}
          </p>
        </div>

        <div className="flex items-center gap-5">
          {freshness && freshness.readings > 0 && (
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <ClockIcon className="size-3.5 shrink-0" aria-hidden />
              <span>
                oldest reading{" "}
                <span className="font-medium text-foreground">
                  {formatAge(freshness.stale_hours)}
                </span>
                {freshness.unusable > 0 && (
                  <>
                    {" · "}
                    <span className="font-medium text-medium">
                      {freshness.unusable} unusable
                    </span>
                  </>
                )}
              </span>
            </div>
          )}

          {/* A ring, because this genuinely is a whole divided in two: checks
              that reached a verdict, and checks that could not. The percentage
              in the middle is the same number the sentence uses. */}
          {pct !== null && (
            <div className="flex items-center gap-3">
              <Donut
                slices={verdictSlices(conclusive, unknown)}
                centerValue={`${pct}%`}
                centerLabel=""
                ariaLabel={`${conclusive} checks reached a verdict, ${unknown} did not`}
                className="size-16 shrink-0"
                valueClassName="text-[14.5px]"
              />
              <span className="text-xs text-muted-foreground">
                of <span className="tabular-nums">{conclusive + unknown}</span> checks verdicted
              </span>
            </div>
          )}
        </div>
      </div>

      {categories.length > 0 && (
        <ul className="flex flex-wrap gap-x-5 gap-y-2 border-t px-5 py-3">
          {categories.map((category) => (
            <CategoryChip key={category.name} category={category} />
          ))}
        </ul>
      )}

      {context && context.unclassified > 0 && (
        <div className="border-t border-dashed px-5 py-3">
          <p className="text-xs leading-relaxed text-muted-foreground">
            <span className="font-medium text-foreground">
              {context.unclassified} of{" "}
              {context.unclassified + context.classified} open risks
            </span>{" "}
            sit on assets Cleave could not classify. They are ranked as
            though they matter, so nothing important hides behind a missing
            label — but the score is only charged for what was established.{" "}
            <Link
              to="/settings"
              className="font-medium text-foreground underline underline-offset-2"
            >
              Tell Cleave what these subscriptions hold
            </Link>{" "}
            and the number will move to match.
          </p>
        </div>
      )}

      {gaps.length > 0 && (
        <div className="flex flex-col gap-2.5 border-t border-dashed border-medium-border bg-medium-bg px-5 py-4">
          <p className="text-xs font-medium text-medium">
            {gaps.length} {gaps.length === 1 ? "category" : "categories"} could not
            be collected
          </p>
          <ul className="flex flex-col gap-2.5">
            {gaps.map(([category, reason]) => (
              <li key={category} className="text-xs leading-relaxed">
                <span className="font-medium capitalize">{label(category)}</span>
                <ul className="mt-1 flex flex-col gap-1.5">
                  {groupCauses(reason).map((cause) => (
                    <GapCause
                      key={cause.message}
                      keys={cause.keys}
                      message={cause.message}
                    />
                  ))}
                </ul>
              </li>
            ))}
          </ul>
          <Link
            to="/scans"
            className={cn(
              buttonVariants({ variant: "outline", size: "sm" }),
              "self-start",
            )}
          >
            View scan detail
          </Link>
        </div>
      )}
    </section>
  );
}

/**
 * One category of evidence, and whether the scan got all of it.
 *
 * PARTIAL counts as incomplete rather than as read: a truncated listing cannot
 * support "none of them are public", which is the same rule the engine applies
 * one layer up. The state is written out beside the name, and the incomplete
 * one is in the caution tone as well, so it does not rest on colour.
 */
function CategoryChip({ category }: { category: Category }) {
  const clean = category.incomplete === 0;

  return (
    <li className={cn("text-xs", clean ? "text-muted-foreground" : "font-medium text-medium")}>
      <span>{label(category.name)}</span>
      <span>
        {" · "}
        {clean
          ? "complete"
          : `${category.incomplete} of ${category.readings} reading${
              category.readings === 1 ? "" : "s"
            } incomplete`}
      </span>
    </li>
  );
}

/**
 * One cause, and everything it stopped.
 *
 * The provider reports a failure per evidence key, and a single missing admin
 * consent fails several of them with the same nine-hundred-character sentence.
 * Identical causes are stated once with the keys they cost named beside them,
 * and the provider's own words are kept — clipped, with the rest one click
 * away. Kept rather than paraphrased: this is the text an administrator will
 * search for, and a summary of an Azure error is not an Azure error.
 */
function GapCause({ keys, message }: { keys: string[]; message: string }) {
  const [expanded, setExpanded] = useState(false);
  const long = message.length > 180;

  return (
    <li>
      {keys.length > 0 && (
        <span className="font-medium text-foreground">{keys.join(", ")}</span>
      )}
      <span className="text-muted-foreground">
        {keys.length > 0 && " — "}
        {long && !expanded ? `${message.slice(0, 180).trimEnd()}…` : message}
      </span>
      {long && (
        <button
          type="button"
          onClick={() => setExpanded((value) => !value)}
          className="ml-1.5 whitespace-nowrap underline underline-offset-2 transition-colors hover:text-foreground"
        >
          {expanded ? "Show less" : "Show the whole message"}
        </button>
      )}
    </li>
  );
}

/**
 * The two things a check can be: answered, or not.
 *
 * Two slices and no third, because "unknown" is not a middle state between pass
 * and fail — it is the absence of a verdict, and the whole point of the panel
 * is that it is never counted as either.
 */
function verdictSlices(conclusive: number, unknown: number): Slice[] {
  return [
    {
      key: "conclusive",
      label: "Reached a verdict",
      value: conclusive,
      tone: "var(--sev-ok)",
    },
    {
      key: "unknown",
      label: "No verdict",
      value: unknown,
      tone: "var(--sev-unknown)",
    },
  ].filter((slice) => slice.value > 0);
}

function formatAge(hours: number | null): string {
  if (hours === null) return "—";
  if (hours < 1) return "under an hour old";
  if (hours < 48) return `${Math.round(hours)} hours old`;
  return `${Math.round(hours / 24)} days old`;
}
