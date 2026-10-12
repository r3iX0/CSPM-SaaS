import { useEffect, useRef, type KeyboardEvent } from "react";
import { Link } from "react-router-dom";
import { m } from "motion/react";
import {
  ArrowLeftIcon,
  ChevronDownIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  ChevronUpIcon,
  MapIcon,
  RadarIcon,
  ScissorsIcon,
} from "lucide-react";

import type {
  AttackPathStep,
  MappedRoute,
  RouteMapEdge,
  RouteMapNode,
  RoutePattern,
} from "@/lib/types";
import { useT } from "@/i18n";
import { cn } from "@/lib/format";
import { HowToFix } from "@/components/graph/HowToFix";
import { Named } from "@/components/graph/Named";
import { routeSentence } from "@/components/graph/routeSentence";
import { FACTOR_ICONS } from "@/lib/icons";
import { DURATION, EASE_OUT, layoutSpring } from "@/lib/motion";
import { ResourceTypeLabel } from "@/components/security/IconLabel";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Button } from "@/components/ui/button";
import { Kbd } from "@/components/ui/kbd";
import { OpenInGraph } from "./OpenInGraph";
import { hopKey } from "./routeKeys";
import { mapHref, placeName } from "./routeOrder";

/**
 * One route, read in the panel beside the drawing (DECISIONS.md §142).
 *
 * It replaces two readings of the same route that never agreed: a step bar
 * across the top of the drawing that showed one hop, and a spine in the panel
 * that showed every hop and could not be stepped along. Now the route is one
 * line of stops and links. The stops are always shown -- what each asset is,
 * where it sits, what is open on it -- because they are short and they are
 * what a reader asks "where am I" about. The links are what is walked: the one
 * being read opens to say what it is, what cutting it would close across the
 * estate, and lets it go into the plan without leaving the route.
 *
 * Up and down walk the links, left and right move between routes in the
 * order the list shows them, Escape goes back to the list.
 *
 * **Walking it is one highlight moving (§260).** The read link used to open
 * where it sat, with its facts, its numbers, the cut and how to make it, so
 * every step reflowed the list under the reader's eye. Now every row keeps its
 * height, a highlight slides to the read link, and what it says is in a dock
 * at the foot of the panel that cross-fades as the hop changes.
 */
export function RouteNavigator({
  route,
  nodes,
  edges,
  hop,
  onHop,
  position,
  onRoute,
  pattern,
  isPlanned,
  onPlan,
  planVerdict,
  focusOnOpen,
  onBack,
}: {
  route: MappedRoute;
  nodes: ReadonlyMap<string, RouteMapNode>;
  /** Every drawn link, by `hopKey`, for what cutting one would close. */
  edges: ReadonlyMap<string, RouteMapEdge>;
  hop: number;
  onHop: (hop: number) => void;
  /** Where this route is in the list as it is narrowed; null when the list does not hold it. */
  position: { index: number; count: number } | null;
  onRoute: (delta: -1 | 1) => void;
  pattern?: RoutePattern;
  isPlanned: (step: AttackPathStep) => boolean;
  onPlan: (step: AttackPathStep) => void;
  /** What the simulated plan does to this route, once the server has said. */
  planVerdict: "closed" | "open" | null;
  /** Move focus to the route's name when it opens: true when somebody chose it here. */
  focusOnOpen: boolean;
  onBack: () => void;
}) {
  const t = useT();
  const count = route.steps.length;
  const heading = useRef<HTMLHeadingElement>(null);
  const region = useRef<HTMLDivElement>(null);

  // The cursor carries the focus while the reader is in here, and a hop read
  // from the drawing is scrolled to without taking the focus from it. Not on
  // opening, which the page's own arrival scroll owns.
  const opened = useRef(false);
  useEffect(() => {
    if (!opened.current) {
      opened.current = true;
      return;
    }
    // Found by its mark rather than a ref handed from row to row: an object
    // ref is attached to the new row and then cleared by the old one
    // detaching, whichever comes later in the list, and the focus was lost.
    const now = region.current?.querySelector<HTMLButtonElement>('[aria-current="step"]');
    if (region.current?.contains(document.activeElement)) {
      now?.focus();
    } else {
      now?.scrollIntoView?.({ block: "nearest" });
    }
  }, [hop]);
  useEffect(() => {
    if (focusOnOpen) heading.current?.focus({ preventScroll: true });
    // Only a new route moves the focus to its name.
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only a new route moves the focus.
  }, [route.key]);

  const edgeOf = (step: AttackPathStep) =>
    edges.get(hopKey(step.source_id, step.relationship, step.target_id));
  const cheapest = route.steps.findIndex(
    (step) =>
      route.cheapest_break?.source_id === step.source_id &&
      route.cheapest_break?.target_id === step.target_id &&
      route.cheapest_break?.relationship === step.relationship,
  );
  // The earliest removable link is where the server says to cut; the link
  // closing the most routes across the estate is often another one, and the
  // difference is worth a look before choosing.
  const closing = route.steps.map((step) => {
    const edge = edgeOf(step);
    return edge?.closes.includes(route.key) ? edge.severs : 0;
  });
  const most = Math.max(0, ...closing);
  const leverage = most > 1 ? closing.indexOf(most) : -1;

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
    if (event.key === "ArrowUp" && hop > 0) onHop(hop - 1);
    else if (event.key === "ArrowDown" && hop < count - 1) onHop(hop + 1);
    else if (event.key === "ArrowLeft" && position && position.index > 0) onRoute(-1);
    else if (event.key === "ArrowRight" && position && position.index < position.count - 1)
      onRoute(1);
    else if (event.key === "Escape") onBack();
    else return;
    event.preventDefault();
  }

  const stations = [route.entry.id, ...route.steps.map((step) => step.target_id)];
  const names = [route.entry.name, ...route.steps.map((step) => step.target)];
  const placeKey = (node: RouteMapNode | undefined) =>
    node ? `${node.scope_id}|${(node.group ?? "").toLowerCase()}` : null;
  const reading = route.steps[hop];

  return (
    <div
      ref={region}
      role="group"
      aria-label={t.attackPaths.navigatorLabel(route.entry.name, route.target.name)}
      onKeyDown={onKeyDown}
      className="flex min-h-0 flex-1 flex-col"
    >
      <div className="flex shrink-0 items-center gap-1 border-b border-border px-2 py-1.5">
        <Button variant="ghost" size="sm" onClick={onBack}>
          <ArrowLeftIcon data-icon="inline-start" />
          {t.attackPaths.clearTrace}
        </Button>
        {position && (
          <div className="ml-auto flex items-center gap-0.5">
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label={t.attackPaths.previousRoute}
              disabled={position.index === 0}
              onClick={() => onRoute(-1)}
            >
              <ChevronLeftIcon />
            </Button>
            <span className="px-1 text-caption tabular-nums text-muted-foreground">
              {t.attackPaths.routeOf(position.index + 1, position.count)}
            </span>
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label={t.attackPaths.nextRoute}
              disabled={position.index === position.count - 1}
              onClick={() => onRoute(1)}
            >
              <ChevronRightIcon />
            </Button>
          </div>
        )}
      </div>

      {/* What the route is, said once and kept short: its two ends, one
          sentence, and what is known about it as pills (§260). */}
      <div className="flex shrink-0 flex-col gap-1.5 border-b border-border px-3 py-3">
        <p className="text-caption font-medium text-muted-foreground">{t.attackPaths.route}</p>
        <h3
          ref={heading}
          tabIndex={-1}
          className="text-title font-semibold tracking-tight outline-none"
        >
          {route.entry.name} <span className="font-normal text-muted-foreground">→</span>{" "}
          {route.target.name}
        </h3>
        <p className="line-clamp-2 text-meta leading-relaxed text-muted-foreground [@media(max-height:760px)]:line-clamp-1">
          {routeSentence(route)}
        </p>
        <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
          <SeverityBadge level={route.target.data_sensitivity} size="sm" />
          <span className="rounded-full bg-foreground/8 px-2 text-caption text-muted-foreground tabular-nums">
            {count} {count === 1 ? t.attackPaths.oneHop : t.attackPaths.hops}
          </span>
          {planVerdict && (
            <span
              className={cn(
                "flex items-center gap-1 rounded-full px-2 text-caption",
                planVerdict === "closed"
                  ? "bg-ok-bg text-ok"
                  : "bg-foreground/8 text-muted-foreground",
              )}
            >
              <ScissorsIcon className="size-3" aria-hidden />
              {planVerdict === "closed" ? t.attackPaths.planCloses : t.attackPaths.planLeavesOpen}
            </span>
          )}
          {route.risk ? (
            <Link
              to={`/risks/${route.risk.id}`}
              className="flex items-center gap-1 rounded-full bg-foreground/8 px-2 text-caption text-muted-foreground hover:text-foreground focus-ring"
            >
              <RadarIcon className="size-3" aria-hidden />
              {t.attackPaths.trackedAsRisk}
            </Link>
          ) : (
            <span className="text-caption text-muted-foreground">{t.attackPaths.notARisk}</span>
          )}
          <span className="ml-auto text-caption">
            <OpenInGraph entryId={route.entry.id} traceKey={route.key} compact />
          </span>
        </div>
        {pattern && (
          <p className="text-caption text-muted-foreground">
            {t.attackPaths.onePattern(pattern.description)}
          </p>
        )}
      </div>

      {/* One live region for the walk: a region mounted with its words is
          not reliably read, so the hop is said here as it changes. */}
      <p aria-live="polite" className="sr-only">
        {reading && t.attackPaths.hopOf(hop + 1, count, reading.detail || reading.description)}
      </p>

      {/* The route, stop by stop. Every row keeps its height whichever hop is
          read -- what the read hop says is in the dock below -- so walking it
          moves one highlight, not the list (§260). */}
      <ol
        aria-label={t.attackPaths.hopsLabel}
        className="flex min-h-20 flex-1 flex-col overflow-y-auto px-2 py-2"
      >
        {stations.map((id, index) => {
          const node = nodes.get(id);
          const previous = index > 0 ? nodes.get(stations[index - 1]) : undefined;
          const step = route.steps[index];
          return (
            <li key={`${id}|${index}`} className="flex flex-col">
              <Station
                name={names[index]}
                node={node}
                kind={index === 0 ? "entry" : index === count ? "target" : "between"}
                route={route}
                // Said where the route arrives in a place, not at every stop in it.
                showPlace={index === 0 || placeKey(node) !== placeKey(previous)}
              />
              {step && (
                <HopRow
                  step={step}
                  index={index}
                  count={count}
                  reading={index === hop}
                  cheapest={index === cheapest}
                  leverage={index === leverage}
                  planned={isPlanned(step)}
                  onRead={() => onHop(index)}
                />
              )}
            </li>
          );
        })}
      </ol>

      {reading && (
        <HopDock
          step={reading}
          index={hop}
          count={count}
          route={route}
          edge={edgeOf(reading)}
          cheapest={hop === cheapest}
          leverage={hop === leverage ? most : null}
          planned={isPlanned(reading)}
          onHop={onHop}
          onPlan={() => onPlan(reading)}
        />
      )}

      <div className="hidden shrink-0 items-center gap-1.5 border-t border-border px-3 py-1.5 text-caption whitespace-nowrap text-muted-foreground lg:flex">
        <Kbd>↑</Kbd>
        <Kbd>↓</Kbd>
        {t.attackPaths.keysHops}
        <span aria-hidden>·</span>
        <Kbd>←</Kbd>
        <Kbd>→</Kbd>
        {t.attackPaths.keysRoutes}
        <span aria-hidden>·</span>
        <Kbd>Esc</Kbd>
        {t.attackPaths.keysBack}
      </div>
    </div>
  );
}

/** A stop on the route: its name first, then what it is and what is open on it. */
function Station({
  name,
  node,
  kind,
  route,
  showPlace,
}: {
  name: string;
  node: RouteMapNode | undefined;
  kind: "entry" | "between" | "target";
  route: MappedRoute;
  showPlace: boolean;
}) {
  const t = useT();
  const type =
    node?.resource_type ??
    (kind === "entry"
      ? route.entry.resource_type
      : kind === "target"
        ? route.target.resource_type
        : null);
  const ExposureIcon = FACTOR_ICONS.exposure;
  const SensitivityIcon = FACTOR_ICONS.dataSensitivity;

  return (
    <div className="flex gap-2.5 px-1 py-1">
      <div className="flex w-5 shrink-0 justify-center pt-1.5" aria-hidden>
        <span
          className={cn(
            "size-2.5 rounded-full border-2 bg-background",
            kind === "between" ? "border-muted-foreground/70" : "border-primary",
          )}
        />
      </div>
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex min-w-0 items-center gap-2">
          {node?.asset_id ? (
            <Link
              to={`/assets/${node.asset_id}`}
              className="min-w-0 truncate text-body font-semibold underline-offset-4 hover:underline focus-ring"
            >
              {name}
            </Link>
          ) : (
            <span className="min-w-0 truncate text-body font-semibold">{name}</span>
          )}
          {type && (
            <ResourceTypeLabel
              type={type}
              className="shrink-0 truncate text-caption text-muted-foreground"
            />
          )}
          <span className="ml-auto flex shrink-0 items-center gap-1">
            {kind === "entry" && (
              <span
                className="flex items-center gap-0.5"
                title={`${t.attackPaths.exposure}: ${route.entry.public_exposure.toLowerCase()}`}
              >
                <ExposureIcon className="size-3 text-high" aria-hidden />
                <SeverityBadge level={route.entry.public_exposure} size="sm" />
              </span>
            )}
            {kind === "target" && (
              <span
                className="flex items-center gap-0.5"
                title={`${t.attackPaths.sensitivity}: ${route.target.data_sensitivity.toLowerCase()}`}
              >
                <SensitivityIcon className="size-3 text-high" aria-hidden />
                <SeverityBadge level={route.target.data_sensitivity} size="sm" />
              </span>
            )}
            {node &&
              node.findings.open > 0 &&
              (node.asset_id ? (
                <Link
                  to={`/assets/${node.asset_id}?tab=findings`}
                  className="rounded-md bg-foreground/8 px-1.5 text-caption tabular-nums text-muted-foreground hover:text-foreground focus-ring"
                  title={t.attackPaths.openFindings(node.findings.open)}
                  aria-label={t.attackPaths.openFindings(node.findings.open)}
                >
                  {node.findings.open}
                </Link>
              ) : (
                <span
                  className="rounded-md bg-foreground/8 px-1.5 text-caption tabular-nums text-muted-foreground"
                  title={t.attackPaths.openFindings(node.findings.open)}
                >
                  {node.findings.open}
                  <span className="sr-only"> {t.attackPaths.openFindings(node.findings.open)}</span>
                </span>
              ))}
          </span>
        </div>
        {showPlace && node && (
          <p className="flex min-w-0 items-center gap-1 text-caption text-muted-foreground">
            <MapIcon className="size-3 shrink-0" aria-hidden />
            {kind === "entry" ? t.attackPaths.placeIn : t.attackPaths.placeEnters}
            <Link
              to={mapHref(node)}
              className="truncate underline underline-offset-4 hover:text-foreground focus-ring"
            >
              {placeName(node)}
            </Link>
          </p>
        )}
      </div>
    </div>
  );
}

/**
 * A link between two stops, one line whichever hop is read: the read one is
 * marked by a highlight that slides to it (`layoutId`), so stepping along the
 * route moves one thing rather than reflowing the list (§260).
 */
function HopRow({
  step,
  index,
  count,
  reading,
  cheapest,
  leverage,
  planned,
  onRead,
}: {
  step: AttackPathStep;
  index: number;
  count: number;
  reading: boolean;
  cheapest: boolean;
  /** Whether it closes the most of any link on this route. */
  leverage: boolean;
  planned: boolean;
  onRead: () => void;
}) {
  const t = useT();
  return (
    <div className="flex gap-2.5 pl-1">
      <div className="flex w-5 shrink-0 justify-center" aria-hidden>
        <span
          className={cn(
            "w-px",
            cheapest ? "border-l border-dashed border-ok" : "bg-border",
            reading && "w-0.5 bg-primary",
          )}
        />
      </div>
      <button
        type="button"
        onClick={onRead}
        aria-current={reading ? "step" : undefined}
        aria-label={t.attackPaths.hopOf(index + 1, count, step.detail || step.description)}
        className={cn(
          "relative isolate my-0.5 flex min-w-0 flex-1 items-center gap-2 rounded-lg px-2 py-1.5 text-left text-meta transition-colors",
          "focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring",
          reading ? "text-foreground" : "text-muted-foreground hover:bg-foreground/5",
        )}
      >
        {reading && (
          <m.span
            layoutId="route-hop-cursor"
            transition={layoutSpring}
            aria-hidden
            className="absolute inset-0 -z-10 rounded-lg bg-primary-soft ring-1 ring-primary/40"
          />
        )}
        <span
          aria-hidden
          className={cn(
            "flex size-4 shrink-0 items-center justify-center rounded-full text-micro font-semibold tabular-nums",
            reading ? "bg-primary text-primary-foreground" : "bg-foreground/8",
          )}
        >
          {index + 1}
        </span>
        <span className="min-w-0 flex-1 truncate">{step.description}</span>
        <span className="flex shrink-0 items-center gap-1" aria-hidden>
          {leverage && <span className="size-1.5 rounded-full bg-foreground" />}
          {(cheapest || planned) && (
            <ScissorsIcon className={cn("size-3", planned ? "text-ok" : "text-ok/70")} />
          )}
        </span>
      </button>
    </div>
  );
}

/**
 * The hop being read, in one place at the foot of the panel: what the link
 * is, what cutting it would close across the estate, and the cut itself.
 * It changes in place as the hop does -- a cross-fade, not a reflow -- and
 * steps along the route from its own arrows (§260).
 */
function HopDock({
  step,
  index,
  count,
  route,
  edge,
  cheapest,
  leverage,
  planned,
  onHop,
  onPlan,
}: {
  step: AttackPathStep;
  index: number;
  count: number;
  route: MappedRoute;
  edge: RouteMapEdge | undefined;
  cheapest: boolean;
  /** How many routes it closes, when it closes the most of any link on this route. */
  leverage: number | null;
  planned: boolean;
  onHop: (hop: number) => void;
  onPlan: () => void;
}) {
  const t = useT();
  // Containment is where a resource lives; nobody can remove it.
  const removable = step.relationship !== "contains";

  return (
    <div className="flex max-h-[38%] min-h-28 shrink flex-col border-t border-border bg-foreground/[0.025]">
      <div className="flex items-center gap-1 px-3 pt-2.5">
        <p className="text-caption font-medium text-muted-foreground tabular-nums">
          {t.attackPaths.hopLabel(index + 1, count)}
        </p>
        <span className="ml-auto flex items-center gap-0.5">
          <Button
            variant="ghost"
            size="icon-xs"
            aria-label={t.attackPaths.previousHop}
            disabled={index === 0}
            onClick={() => onHop(index - 1)}
          >
            <ChevronUpIcon />
          </Button>
          <Button
            variant="ghost"
            size="icon-xs"
            aria-label={t.attackPaths.nextHop}
            disabled={index === count - 1}
            onClick={() => onHop(index + 1)}
          >
            <ChevronDownIcon />
          </Button>
        </span>
      </div>
      <m.div
        key={`${route.key}|${index}`}
        initial={{ opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: DURATION.quick / 1000, ease: EASE_OUT }}
        className="flex min-h-0 flex-col gap-2 overflow-y-auto px-3 pt-1 pb-3"
      >
        <p className="text-body text-muted-foreground">
          <Named text={step.detail || step.description} names={[step.source, step.target]} />
        </p>
        {(cheapest || leverage !== null || step.facts.length > 0) && (
          <ul className="flex flex-wrap gap-1" aria-label={t.attackPaths.factsLabel}>
            {cheapest && (
              <li className="rounded-full bg-ok-bg px-2 text-caption text-ok">
                {t.attackPaths.earliestCut}
              </li>
            )}
            {leverage !== null && (
              <li className="rounded-full bg-foreground/8 px-2 text-caption text-foreground">
                {t.attackPaths.closesMost(leverage)}
              </li>
            )}
            {step.facts.map((fact) => (
              <li
                key={fact}
                className="rounded-full bg-foreground/8 px-2 text-caption text-muted-foreground"
              >
                {fact}
              </li>
            ))}
          </ul>
        )}
        <p className="text-meta leading-relaxed text-muted-foreground">
          {severance(t, removable, route.key, edge)}
        </p>
        {removable && (
          <div className="flex flex-wrap items-start gap-2">
            {edge && (
              <Button variant={planned ? "secondary" : "default"} size="sm" onClick={onPlan}>
                <ScissorsIcon data-icon="inline-start" />
                {planned ? t.attackPaths.takeOutOfPlan : t.attackPaths.addToPlan}
              </Button>
            )}
            <HowToFix
              link={{
                source: step.source_id,
                relationship: step.relationship,
                target: step.target_id,
              }}
            />
          </div>
        )}
      </m.div>
    </div>
  );
}

/**
 * What cutting one link does, from the numbers on the line. "Closes this
 * route" is said only when the server's `closes` names it: a link the route
 * has a way round is not a cut for it, whatever it does elsewhere.
 */
function severance(
  t: ReturnType<typeof useT>,
  removable: boolean,
  routeKey: string,
  edge: RouteMapEdge | undefined,
): string {
  if (!removable) return t.attackPaths.cannotRemove;
  if (!edge) return t.attackPaths.notDrawn;
  const closesThis = edge.closes.includes(routeKey);
  const base = closesThis
    ? t.attackPaths.closesThis(edge.severs - 1)
    : t.attackPaths.wayRound(edge.severs);
  return edge.on_routes > edge.severs ? `${base} ${t.attackPaths.sitsOn(edge.on_routes)}` : base;
}
