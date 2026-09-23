import type { ReactNode } from "react";
import { PlusIcon, ScissorsIcon, XIcon } from "lucide-react";

import type { ChokePoint, MappedRoute, RouteMap, Simulation } from "@/lib/types";
import { cn } from "@/lib/format";
import { useT } from "@/i18n";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { CopyButton } from "@/components/common/CopyButton";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import type { Hop } from "./RouteMapCanvas";
import { hopKey } from "./routeKeys";

/** How many rows a list in the panel shows before counting the rest. */
const SHOWN = 6;

export type SimulationState = "checking" | "error" | "ready";

const keyOf = (link: Hop) => hopKey(link.source, link.relationship, link.target);

const chokeHop = (choke: ChokePoint): Hop => ({
  source: choke.source.id,
  relationship: choke.relationship,
  target: choke.target.id,
});

/**
 * The simulate tab beside the route map: a plan of cuts, and what it does.
 *
 * **A plan, not a toggle.** What somebody takes to a change window is several
 * changes, and several changes do not add up: two network hops into the same
 * identity each close nothing, because each is the other's way round, and
 * together close everything behind them. So the answer comes from the server
 * for the plan as a whole (`POST /attack-paths/simulate`), never from summing
 * the numbers drawn on the lines -- and where the whole closes more than its
 * parts, the panel says so, because that is the one thing nobody could have
 * read off the drawing (DECISIONS.md §141).
 *
 * **Each change is weighed against the rest.** "Closes 3 alone" is what the
 * line says; "3 close only with it" is what the plan says. A change the rest
 * of the plan already covers is an afternoon's work for nothing, and is marked
 * so it can be left out.
 *
 * **What to add next is ranked with the plan made.** With nothing planned the
 * tab starts from the estate's choke points -- the links holding several
 * routes up at once, which used to be a card above the drawing. Once a plan
 * removes a link, a hop that had a way round may be the only way left, and the
 * suggestions are re-ranked over what remains.
 */
export function SimulationPanel({
  map,
  plan,
  result,
  state,
  maxCuts,
  onRetry,
  onAdd,
  onRemove,
  onClear,
  onTrace,
}: {
  map: RouteMap;
  plan: Hop[];
  result: Simulation | undefined;
  state: SimulationState;
  maxCuts: number;
  onRetry: () => void;
  onAdd: (link: Hop) => void;
  onRemove: (link: Hop) => void;
  onClear: () => void;
  onTrace: (key: string) => void;
}) {
  const planned = new Set(plan.map(keyOf));
  const full = plan.length >= maxCuts;
  const edges = new Map(map.edges.map((edge) => [keyOf(edge), edge]));
  const weighed = new Map((result?.cuts ?? []).map((cut) => [keyOf(cut), cut]));
  const missing = new Set((result?.missing ?? []).map(keyOf));
  const routes = new Map(map.routes.map((route) => [route.key, route]));

  // With nothing planned, the estate's own choke points are the place to
  // start; with a plan, what is worth cutting in the estate the plan leaves.
  const suggestions = (plan.length === 0 ? map.choke_points : (result?.next ?? [])).filter(
    (choke) => !planned.has(keyOf(chokeHop(choke))),
  );

  if (plan.length === 0) {
    return (
      <div className="flex flex-col gap-4 overflow-y-auto p-3">
        <div className="flex flex-col gap-1">
          <h3 className="text-sm font-medium">Try a change before you make it</h3>
          <p className="text-xs leading-relaxed text-muted-foreground">
            Press a line on the drawing to add it to a plan, or start from one of the
            changes below. Add everything you would change together: the plan is checked
            as a whole, because two changes can close routes neither closes alone.
            Nothing in your cloud changes.
          </p>
        </div>
        <Suggestions
          title="The changes that close the most"
          help="Each holds several routes up at once, and is usually not the fix any single route would suggest: the shared link tends to sit in the middle, while each route's own cheapest break is at its start."
          chokes={suggestions}
          full={full}
          onAdd={onAdd}
        />
      </div>
    );
  }

  const closed = result?.closed ?? [];
  const together = new Set(result?.together ?? []);
  const checking = state === "checking";

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <Outcome
        before={result?.before ?? null}
        closed={result ? closed.length : null}
        after={result?.after}
        together={together.size}
        checking={checking}
      />

      <div
        aria-busy={checking}
        className={cn(
          "flex flex-col gap-4 overflow-y-auto p-3 transition-opacity",
          checking && result && "opacity-60",
        )}
      >
        {state === "error" && (
          <Alert variant="destructive">
            <AlertDescription className="flex flex-wrap items-center justify-between gap-2">
              CloudGuard could not check this plan.
              <Button variant="outline" size="sm" onClick={onRetry}>
                Try again
              </Button>
            </AlertDescription>
          </Alert>
        )}

        <section aria-labelledby="plan-title" className="flex flex-col gap-2">
          <div className="flex items-center justify-between gap-2">
            <h3 id="plan-title" className="text-xs font-medium">
              The plan{" "}
              <span className="font-normal tabular-nums text-muted-foreground">
                {plan.length} of {maxCuts}
              </span>
            </h3>
            <Button variant="ghost" size="sm" onClick={onClear}>
              Clear
            </Button>
          </div>
          <ol className="flex flex-col gap-2">
            {plan.map((link) => {
              const key = keyOf(link);
              const cut = weighed.get(key);
              const gone = missing.has(key);
              const detail = cut?.detail ?? edges.get(key)?.detail ?? key;
              return (
                <li
                  key={key}
                  className={cn(
                    "rounded-lg border px-3 py-2",
                    gone ? "border-dashed border-border" : "border-ok-border",
                  )}
                >
                  <div className="flex items-start gap-2">
                    <ScissorsIcon className="mt-0.5 size-3.5 shrink-0 text-ok" aria-hidden />
                    <p className="min-w-0 flex-1 font-mono text-xs break-words">{detail}</p>
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      aria-label={`Take out of the plan: ${detail}`}
                      onClick={() => onRemove(link)}
                    >
                      <XIcon />
                    </Button>
                  </div>
                  <CutWeight
                    gone={gone}
                    alone={cut?.alone}
                    neededFor={cut?.needed_for}
                    alongside={plan.length > 1}
                  />
                </li>
              );
            })}
          </ol>
          {result && result.cuts.length > 0 && (
            <div className="self-start">
              <CopyButton
                variant="outline"
                label="Copy the plan"
                text={planText(result)}
              />
            </div>
          )}
        </section>

        {result && result.after > 0 && (
          <Suggestions
            title="Worth adding next"
            help="Ranked over what this plan leaves: a link with a way round the plan has cut can rank here where it did not before."
            chokes={suggestions}
            full={full}
            onAdd={onAdd}
          />
        )}

        {result && result.remaining.length > 0 && (
          <RouteList title="Still open" count={result.remaining.length}>
            {result.remaining.slice(0, SHOWN).map((left) => (
              <OpenRoute
                key={left.key}
                route={routes.get(left.key)}
                hops={left.hops}
                onTrace={() => onTrace(left.key)}
              />
            ))}
          </RouteList>
        )}

        {closed.length > 0 && (
          <RouteList title="Closed" count={closed.length}>
            {closed.slice(0, SHOWN).map((route) => (
              <li key={route.key} className="flex items-center gap-1.5 px-1 text-xs">
                <SeverityBadge level={route.data_sensitivity} size="sm" />
                <span className="min-w-0 flex-1 truncate text-muted-foreground">
                  {route.entry} → {route.target}
                </span>
                {together.has(route.key) && (
                  <span className="shrink-0 text-[11px] text-ok">only together</span>
                )}
              </li>
            ))}
          </RouteList>
        )}
      </div>
    </div>
  );
}

/**
 * The answer, at the top where it is read first: how many routes close out of
 * how many, and whether any close only because the cuts are made together.
 */
function Outcome({
  before,
  closed,
  after,
  together,
  checking,
}: {
  before: number | null;
  closed: number | null;
  after: number | undefined;
  together: number;
  checking: boolean;
}) {
  const share = closed !== null && before ? closed / before : 0;
  return (
    <div className="flex shrink-0 flex-col gap-2 border-b border-border p-3">
      <div className="flex items-baseline justify-between gap-2">
        <p className="text-xs text-muted-foreground" aria-live="polite">
          {closed === null || before === null ? (
            "Checking the plan…"
          ) : (
            <>
              <span className="text-lg font-semibold tabular-nums text-foreground">
                {closed}
              </span>{" "}
              of {before} {before === 1 ? "route closes" : "routes close"}
            </>
          )}
        </p>
        {checking && <Spinner className="size-3.5 text-muted-foreground" />}
      </div>
      <div aria-hidden className="h-1.5 overflow-hidden rounded-full bg-muted">
        <div
          className="h-full rounded-full bg-ok transition-[width] duration-300 motion-reduce:transition-none"
          style={{ width: `${share * 100}%` }}
        />
      </div>
      {after !== undefined && (
        <p className="text-xs text-muted-foreground">
          {after === 0
            ? "No route is left from anything exposed to anything sensitive."
            : `${after} still ${after === 1 ? "runs" : "run"}. Checked over every route, not only those drawn.`}
        </p>
      )}
      {together > 0 && (
        <p className="rounded-md border border-ok-border bg-ok-bg px-2.5 py-1.5 text-xs text-foreground">
          {together === 1 ? "One route closes" : `${together} routes close`} only because
          these changes are made together — no one of them closes{" "}
          {together === 1 ? "it" : "them"} alone.
        </p>
      )}
      <p className="text-[11px] text-muted-foreground">
        A simulation. Nothing in your cloud has changed.
      </p>
    </div>
  );
}

/** What one change in the plan does alone, and what the plan needs it for. */
function CutWeight({
  gone,
  alone,
  neededFor,
  alongside,
}: {
  gone: boolean;
  alone: number | undefined;
  neededFor: number | undefined;
  alongside: boolean;
}) {
  if (gone) {
    return (
      <p className="mt-1 text-xs text-muted-foreground">
        Not in the latest reading — it may already have been removed. Left out of the
        check.
      </p>
    );
  }
  if (alone === undefined || neededFor === undefined) {
    return <p className="mt-1 text-xs text-muted-foreground">Checking…</p>;
  }
  return (
    <div className="mt-1 flex flex-col gap-0.5 text-xs text-muted-foreground">
      <p>
        Closes <span className="tabular-nums text-foreground">{alone}</span> alone
        {alongside && (
          <>
            {" · "}
            <span className="tabular-nums text-foreground">{neededFor}</span>{" "}
            {neededFor === 1 ? "closes" : "close"} only with it
          </>
        )}
      </p>
      {alongside && neededFor === 0 && (
        <p className="text-medium">
          The rest of the plan already closes everything this would. You can leave it out.
        </p>
      )}
      {!alongside && alone === 0 && (
        <p>Every route through it has another way round. Add that way to the plan too.</p>
      )}
    </div>
  );
}

function Suggestions({
  title,
  help,
  chokes,
  full,
  onAdd,
}: {
  title: string;
  help?: string;
  chokes: ChokePoint[];
  full: boolean;
  onAdd: (link: Hop) => void;
}) {
  const t = useT();
  if (chokes.length === 0) return null;
  return (
    <section className="flex flex-col gap-2">
      <div>
        <h3 className="text-xs font-medium">{title}</h3>
        {help && (
          <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{help}</p>
        )}
      </div>
      <ul className="flex flex-col gap-2">
        {chokes.map((choke) => (
          <li
            key={keyOf(chokeHop(choke))}
            className="flex items-start gap-2 rounded-lg border border-border px-3 py-2"
          >
            <div className="min-w-0 flex-1">
              <p className="font-mono text-xs break-words">{choke.detail}</p>
              <p className="mt-1 text-xs text-muted-foreground">
                Closes <span className="tabular-nums text-foreground">{choke.severs}</span>{" "}
                of {choke.total_routes}
              </p>
              {/* Where it sits on more than it closes, said: a customer told four
                  close who then sees two remain stops believing the next number. */}
              {choke.on_routes > choke.severs && (
                <p className="mt-0.5 text-xs text-muted-foreground">
                  {t.attackPaths.chokeSitsOn.replace("{on}", String(choke.on_routes))}
                </p>
              )}
              {/* Named, not just counted: the count is a claim, these its working. */}
              <ul className="mt-1.5 flex flex-col gap-0.5">
                {choke.closes.slice(0, 3).map((route) => (
                  <li
                    key={`${route.entry}->${route.target}`}
                    className="flex items-center gap-1.5 text-xs text-muted-foreground"
                  >
                    <SeverityBadge level={route.data_sensitivity} size="sm" />
                    <span className="min-w-0 truncate">
                      {route.entry} → {route.target}
                    </span>
                  </li>
                ))}
                {choke.closes.length > 3 && (
                  <li className="text-xs text-muted-foreground">
                    and {choke.closes.length - 3} more
                  </li>
                )}
              </ul>
            </div>
            <Button
              variant="outline"
              size="icon-sm"
              aria-label={`Add to the plan: ${choke.detail}`}
              disabled={full}
              onClick={() => onAdd(chokeHop(choke))}
            >
              <PlusIcon />
            </Button>
          </li>
        ))}
      </ul>
    </section>
  );
}

function RouteList({
  title,
  count,
  children,
}: {
  title: string;
  count: number;
  children: ReactNode;
}) {
  return (
    <section className="flex flex-col gap-1.5">
      <h3 className="text-xs font-medium">
        {title}{" "}
        <span className="font-normal tabular-nums text-muted-foreground">{count}</span>
      </h3>
      <ul className="flex flex-col gap-1">{children}</ul>
      {count > SHOWN && (
        <p className="px-1 text-xs text-muted-foreground">and {count - SHOWN} more</p>
      )}
    </section>
  );
}

/**
 * A route the plan leaves open. Where it now runs longer, it goes round a cut,
 * and that is said: a longer route is the plan partly working, not failing.
 */
function OpenRoute({
  route,
  hops,
  onTrace,
}: {
  route: MappedRoute | undefined;
  hops: number;
  onTrace: () => void;
}) {
  if (!route) {
    return (
      <li className="px-1 text-xs text-muted-foreground">
        A route the drawing leaves off ({hops} hops)
      </li>
    );
  }
  const longer = hops > route.hops;
  return (
    <li>
      <button
        type="button"
        onClick={onTrace}
        className="flex w-full items-center gap-1.5 rounded-md px-1 py-0.5 text-left text-xs hover:bg-muted/60 focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
      >
        <SeverityBadge level={route.target.data_sensitivity} size="sm" />
        <span className="min-w-0 flex-1 truncate">
          {route.entry.name} → {route.target.name}
        </span>
        <span className="shrink-0 tabular-nums text-muted-foreground">
          {longer ? `${route.hops} → ${hops} hops` : `${hops} hops`}
        </span>
      </button>
    </li>
  );
}

/** The plan as text for a change ticket: what closes, then the changes. */
function planText(result: Simulation): string {
  return [
    `${result.closed.length} of ${result.before} attack paths close; ${result.after} remain.`,
    "",
    ...result.cuts.map(
      (cut) =>
        `- ${cut.detail} (closes ${cut.alone} alone; ${cut.needed_for} close only with it)`,
    ),
  ].join("\n");
}
