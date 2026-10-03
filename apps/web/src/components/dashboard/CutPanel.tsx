import { Link } from "react-router-dom";
import { ScissorsIcon } from "lucide-react";

import type { ChokePoint } from "@/lib/types";
import { GraphLink } from "@/components/graph/GraphLink";
import { buttonVariants } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/format";
import { useT } from "@/i18n";
import { InfoTip } from "@/components/common/InfoTip";

/**
 * The one change that closes the most routes.
 *
 * Every other panel on the overview is about faults seen one at a time; this
 * is the one that says several of them line up, and what a reader does with
 * that is cut a single link. So it names the link -- with its evidence, the
 * role or the port -- and how many routes cutting it closes, out of how many
 * there are, and opens the attack-path page's Simulate tab with the cut
 * already in the plan (§141), where what it closes is answered by the server
 * rather than taken on this panel's word.
 *
 * The count is the link's own `severs`: what cutting it alone would close.
 * Never a sum across links -- two cuts can close together what neither closes
 * alone, which is why a plan is simulated whole.
 */
export function CutPanel({
  chokes,
  loading,
  failed,
}: {
  chokes: ChokePoint[] | undefined;
  loading: boolean;
  failed: boolean;
}) {
  const t = useT();
  const choke = Array.isArray(chokes) ? chokes[0] : undefined;

  return (
    <section
      aria-labelledby="link-to-cut"
      data-graph-source=""
      className="flex flex-col overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <header className="px-5 py-4">
        <div className="flex items-center gap-1">
          <h2 id="link-to-cut" className="text-body font-semibold">
            The link to cut
          </h2>
          <InfoTip label={t.dashboard.cutExplainLabel}>{t.dashboard.cutExplain}</InfoTip>
        </div>
      </header>

      <div className="flex flex-1 flex-col gap-4 border-t px-5 py-4">
        {loading && <Skeleton className="h-20 w-full" />}

        {!loading && failed && (
          <p className="text-body leading-relaxed text-muted-foreground">
            Routes could not be read just now. Nothing about your environment has changed.
          </p>
        )}

        {!loading && !failed && !choke && (
          // Never an all-clear. What counts as sensitive is declared per
          // subscription, so an estate that has classified nothing produces
          // no routes at all -- a gap in what Cleave was told, not a clean
          // environment.
          <p className="text-body leading-relaxed text-muted-foreground">
            No route from an internet-facing asset to a sensitive one. What counts as sensitive is
            something you declare —{" "}
            <Link to="/settings/context" className="underline underline-offset-2">
              declare what a subscription is worth
            </Link>
            .
          </p>
        )}

        {!loading && !failed && choke && (
          <>
            <div className="rounded-lg border border-primary-border bg-primary-soft px-4 py-3">
              <p className="font-mono text-meta break-words">{choke.detail}</p>
              <p className="mt-1.5 text-body">
                Cutting this link closes{" "}
                <span className="font-semibold tabular-nums">{choke.severs}</span> of{" "}
                <span className="tabular-nums">{choke.total_routes}</span>{" "}
                {choke.total_routes === 1 ? "route" : "routes"}.
              </p>
            </div>
            <GraphLink
              to={{
                kind: "cut",
                source: choke.source.id,
                relationship: choke.relationship,
                target: choke.target.id,
              }}
              className={cn(buttonVariants({ variant: "outline", size: "sm" }), "self-start")}
            >
              <ScissorsIcon data-icon="inline-start" strokeWidth={1.5} />
              Simulate this cut
            </GraphLink>
          </>
        )}
      </div>
    </section>
  );
}
