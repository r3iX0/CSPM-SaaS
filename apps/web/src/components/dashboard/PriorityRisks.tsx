import { Link } from "react-router-dom";
import { GRAPH_ICON } from "@/lib/icons";

import type { Dashboard } from "@/lib/types";
import { ScoreTile } from "@/components/security/ScoreTile";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { GraphLink } from "@/components/graph/GraphLink";
import type { GraphTarget } from "@/components/graph/graphQueries";
import { buttonVariants } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { stagger } from "@/lib/motion";
import { cn } from "@/lib/format";

type Risk = Dashboard["top_risks"][number];

const GraphIcon = GRAPH_ICON;

/**
 * What to go and deal with, ranked by what it would cost rather than by how
 * loudly it fired.
 *
 * The ranking is the product's whole argument, and a list that showed only
 * titles and numbers asked the reader to take it on trust: why does a HIGH
 * outrank the CRITICAL beneath it? So each row carries the terms the score was
 * actually built from — internet exposure, data sensitivity, asset criticality
 * — which are the same components the risk detail page shows the arithmetic
 * for. A rank is then a reason rather than an assertion.
 *
 * A row leads with a severity-tinted mark instead of an ordinal. The rank is
 * already the reading order, and the tint carries the one thing a reader scans
 * for down a list of five; a scenario keeps its own mark, because it groups
 * findings that are already counted individually and a reader who does not know
 * that will go looking for a misconfiguration that exists on no single asset.
 */
export function PriorityRisks({ risks }: { risks: Risk[] }) {
  return (
    <Card
      role="region"
      aria-labelledby="priority-risks"
      className="gap-0 py-0 [--card-spacing:--spacing(5)]"
    >
      <CardHeader className="py-4">
        <CardTitle id="priority-risks" className="text-body font-semibold">
          Priority risks
        </CardTitle>
        <CardDescription className="mt-1 text-xs">
          Ranked by what each would cost this business, not by how many alerts
          fired.
        </CardDescription>
        <CardAction>
          <Link
            to="/risks"
            className={cn(buttonVariants({ variant: "outline", size: "sm" }), "shrink-0")}
          >
            All risks
          </Link>
        </CardAction>
      </CardHeader>

      {risks.length === 0 ? (
        <CardContent className="border-t py-8">
          <p className="text-center text-sm text-muted-foreground">
            Nothing is currently ranked as a risk. Every check that reached a
            verdict passed — the coverage note above says how much of the estate
            that covers.
          </p>
        </CardContent>
      ) : (
        <ol className="border-t">
          {risks.map((risk, index) => (
            <li
              key={risk.id}
              data-graph-source=""
              className="flex items-center border-b [animation:cg-rise_260ms_ease-out_both] last:border-0"
              style={stagger(index)}
            >
              <Link
                to={`/risks/${risk.id}`}
                className="flex min-w-0 flex-1 items-center gap-3 py-3 pr-3 pl-5 transition-colors hover:bg-muted/60 focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring-inset focus-visible:ring-inset"
              >
                <ScoreTile score={Number(risk.risk_score)} level={risk.risk_level} />

                <div className="min-w-0 flex-1">
                  <p className="truncate text-body font-medium">{risk.title}</p>
                  <RiskContext risk={risk} />
                </div>

                <SeverityBadge level={risk.risk_level} className="shrink-0" />
              </Link>
              <RiskGraphLink risk={risk} />
            </li>
          ))}
        </ol>
      )}
    </Card>
  );
}

/**
 * The way from a ranked risk to the graph it sits in, beside the row rather
 * than inside it: the row still opens the risk, which says why it ranks where
 * it does, and this opens where it is — a route traced on the attack-path
 * page, an asset centred on its connections (DECISIONS.md §139).
 *
 * A risk grouped across several assets has no one place to open, and keeps an
 * empty slot of the same width so the badges down the list stay in a column.
 */
function RiskGraphLink({ risk }: { risk: Risk }) {
  const target: GraphTarget | null = risk.route
    ? { kind: "route", entryId: risk.route.entry_id, targetId: risk.route.target_id }
    : risk.asset_id
      ? { kind: "asset", assetId: risk.asset_id }
      : null;
  const slot = "mr-3 ml-1 shrink-0";
  if (!target) return <span className={cn("size-7", slot)} aria-hidden />;

  const action = target.kind === "route" ? "Trace among attack paths" : "Open in the graph";
  return (
    <GraphLink
      to={target}
      aria-label={`${action}: ${risk.title}`}
      title={action}
      className={cn(
        buttonVariants({ variant: "ghost", size: "icon-sm" }),
        slot,
        "text-muted-foreground",
      )}
    >
      <GraphIcon aria-hidden />
    </GraphLink>
  );
}

/**
 * Why this one outranks the next.
 *
 * Only the components that raise a score are named, and only when they are
 * high enough to be the reason — listing "exposure: LOW" beside a critical risk
 * would spend a line saying nothing. UNKNOWN is stated rather than skipped: not
 * knowing whether an asset is exposed is itself part of why a risk ranks where
 * it does. A scenario says so first, because it groups findings that are
 * already counted one by one.
 */
function RiskContext({ risk }: { risk: Risk }) {
  const facts = [
    { label: "Internet-facing", level: risk.internet_exposure },
    { label: "Sensitive data", level: risk.data_sensitivity },
    { label: "Business-critical", level: risk.asset_criticality },
  ]
    .filter(
      (fact) =>
        fact.level === "CRITICAL" || fact.level === "HIGH" || fact.level === "UNKNOWN",
    )
    .map((fact) => (fact.level === "UNKNOWN" ? `${fact.label}: not known` : fact.label));

  if (risk.kind === "ATTACK_PATH" && facts.length === 0) {
    return (
      <p className="mt-0.5 truncate text-caption text-muted-foreground">
        Scenario — findings already counted individually below
      </p>
    );
  }

  const parts = risk.kind === "ATTACK_PATH" ? ["Scenario", ...facts] : facts;
  if (parts.length === 0) return null;

  return (
    // The separator is drawn, not written: it is punctuation for the eye, and
    // a screen reader already hears the items as a list.
    <ul className="mt-0.5 flex min-w-0 flex-wrap items-center text-caption text-muted-foreground [&>li+li]:before:mx-1 [&>li+li]:before:content-['·']">
      {parts.map((part) => (
        <li key={part} className="whitespace-nowrap">
          {part}
        </li>
      ))}
    </ul>
  );
}
