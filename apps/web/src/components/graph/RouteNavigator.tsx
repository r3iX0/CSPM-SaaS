import { useEffect, useRef, type KeyboardEvent, type Ref } from "react";
import { Link } from "react-router-dom";
import {
  ArrowLeftIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  MapIcon,
  RadarIcon,
  ScissorsIcon,
} from "lucide-react";

import type {
  AttackPathStep,
  MappedRoute,
  Risk,
  RouteMapEdge,
  RouteMapNode,
  RoutePattern,
} from "@/lib/types";
import { useT } from "@/i18n";
import { cn } from "@/lib/format";
import { FACTOR_ICONS, RISK_KIND_ICONS } from "@/lib/icons";
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
  risk,
  trackingKnown,
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
  risk?: Risk;
  trackingKnown: boolean;
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
  const current = useRef<HTMLButtonElement>(null);

  // The cursor carries the focus while the reader is in here, and a hop read
  // from the drawing is scrolled to without taking the focus from it. Not on
  // opening, which the page's own arrival scroll owns.
  const opened = useRef(false);
  useEffect(() => {
    if (!opened.current) {
      opened.current = true;
      return;
    }
    if (region.current?.contains(document.activeElement)) {
      current.current?.focus();
    } else {
      current.current?.scrollIntoView?.({ block: "nearest" });
    }
  }, [hop]);
  useEffect(() => {
    if (focusOnOpen) heading.current?.focus({ preventScroll: true });
    // Only a new route moves the focus to its name.
    // eslint-disable-next-line react-hooks/exhaustive-deps
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

  return (
    <div
      ref={region}
      role="group"
      aria-label={t.attackPaths.navigatorLabel(route.entry.name, route.target.name)}
      onKeyDown={onKeyDown}
      className="flex min-h-0 flex-1 flex-col"
    >
      <div className="flex shrink-0 items-center gap-1 border-b border-border p-2">
        <Button variant="ghost" size="sm" onClick={onBack}>
          <ArrowLeftIcon data-icon="inline-start" />
          {t.attackPaths.clearTrace}
        </Button>
        {position && (
          <div className="ml-auto flex items-center gap-1">
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label={t.attackPaths.previousRoute}
              disabled={position.index === 0}
              onClick={() => onRoute(-1)}
            >
              <ChevronLeftIcon />
            </Button>
            <span className="text-xs tabular-nums text-muted-foreground">
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

      <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-3">
        <div>
          <p className="text-[11px] font-medium text-muted-foreground">{t.attackPaths.route}</p>
          <h3 ref={heading} tabIndex={-1} className="text-sm font-medium outline-none">
            {route.entry.name} <span className="text-muted-foreground">→</span>{" "}
            {route.target.name}
          </h3>
          {pattern && (
            <p className="mt-0.5 text-xs text-muted-foreground">
              {t.attackPaths.onePattern(pattern.description)}
            </p>
          )}
          {planVerdict && (
            <p
              className={cn(
                "mt-1.5 flex items-center gap-1 text-xs",
                planVerdict === "closed" ? "text-ok" : "text-muted-foreground",
              )}
            >
              <ScissorsIcon className="size-3.5" aria-hidden />
              {planVerdict === "closed" ? t.attackPaths.planCloses : t.attackPaths.planLeavesOpen}
            </p>
          )}
        </div>

        {/* One live region for the walk: a region mounted with its words is
            not reliably read, so the hop is said here as it changes. */}
        <p aria-live="polite" className="sr-only">
          {route.steps[hop] &&
            t.attackPaths.hopOf(
              hop + 1,
              count,
              route.steps[hop].detail || route.steps[hop].description,
            )}
        </p>

        <ol aria-label={t.attackPaths.hopsLabel} className="flex flex-col">
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
                  <HopLink
                    step={step}
                    index={index}
                    count={count}
                    route={route}
                    edge={edgeOf(step)}
                    reading={index === hop}
                    cheapest={index === cheapest}
                    leverage={index === leverage ? most : null}
                    planned={isPlanned(step)}
                    onRead={() => onHop(index)}
                    onPlan={() => onPlan(step)}
                    buttonRef={index === hop ? current : undefined}
                  />
                )}
              </li>
            );
          })}
        </ol>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <OpenInGraph entryId={route.entry.id} traceKey={route.key} />
          {risk ? (
            <Link
              to={`/risks/${risk.id}`}
              className="flex items-center gap-1.5 text-xs text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
            >
              <RadarIcon className="size-3.5" aria-hidden />
              {t.attackPaths.trackedAsRisk}
            </Link>
          ) : (
            trackingKnown && (
              <span className="text-xs text-muted-foreground">{t.attackPaths.notARisk}</span>
            )
          )}
        </div>
      </div>

      <p className="hidden shrink-0 items-center gap-1.5 border-t border-border px-3 py-1.5 text-[11px] text-muted-foreground lg:flex">
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
      </p>
    </div>
  );
}

/** A stop on the route: what it is, where, and what is open on it. */
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
  const FindingIcon = RISK_KIND_ICONS.FINDING;
  const ExposureIcon = FACTOR_ICONS.exposure;
  const SensitivityIcon = FACTOR_ICONS.dataSensitivity;

  return (
    <div className="flex gap-3">
      <div className="flex w-6 shrink-0 justify-center pt-1" aria-hidden>
        <span
          className={cn(
            "size-3 rounded-full border-2 bg-background",
            kind === "between" ? "border-muted-foreground" : "border-foreground",
          )}
        />
      </div>
      <div className="flex min-w-0 flex-1 flex-col gap-1 pb-1">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          {node?.asset_id ? (
            <Link
              to={`/assets/${node.asset_id}`}
              className="min-w-0 truncate text-sm font-medium underline-offset-4 hover:underline"
            >
              {name}
            </Link>
          ) : (
            <span className="min-w-0 truncate text-sm font-medium">{name}</span>
          )}
          {type && <ResourceTypeLabel type={type} className="text-xs text-muted-foreground" />}
        </div>
        {(kind !== "between" || (node && node.findings.open > 0)) && (
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
            {kind === "entry" && (
              <span className="flex items-center gap-1">
                <ExposureIcon className="size-3.5" aria-hidden />
                {t.attackPaths.exposure}
                <SeverityBadge level={route.entry.public_exposure} size="sm" />
              </span>
            )}
            {kind === "target" && (
              <span className="flex items-center gap-1">
                <SensitivityIcon className="size-3.5" aria-hidden />
                {t.attackPaths.sensitivity}
                <SeverityBadge level={route.target.data_sensitivity} size="sm" />
              </span>
            )}
            {node && node.findings.open > 0 && (
              <span className="flex items-center gap-1">
                <FindingIcon className="size-3.5" aria-hidden />
                {node.asset_id ? (
                  <Link
                    to={`/assets/${node.asset_id}?tab=findings`}
                    className="underline-offset-4 hover:text-foreground hover:underline"
                  >
                    {t.attackPaths.openFindings(node.findings.open)}
                  </Link>
                ) : (
                  t.attackPaths.openFindings(node.findings.open)
                )}
              </span>
            )}
          </div>
        )}
        {showPlace && node && (
          <p className="flex items-center gap-1 text-xs text-muted-foreground">
            <MapIcon className="size-3.5 shrink-0" aria-hidden />
            {kind === "entry" ? t.attackPaths.placeIn : t.attackPaths.placeEnters}
            <Link to={mapHref(node)} className="underline underline-offset-4 hover:text-foreground">
              {placeName(node)}
            </Link>
          </p>
        )}
      </div>
    </div>
  );
}

/** A link between two stops: one line, or opened when it is the one being read. */
function HopLink({
  step,
  index,
  count,
  route,
  edge,
  reading,
  cheapest,
  leverage,
  planned,
  onRead,
  onPlan,
  buttonRef,
}: {
  step: AttackPathStep;
  index: number;
  count: number;
  route: MappedRoute;
  edge: RouteMapEdge | undefined;
  reading: boolean;
  cheapest: boolean;
  /** How many routes it closes, when it closes the most of any link on this route. */
  leverage: number | null;
  planned: boolean;
  onRead: () => void;
  onPlan: () => void;
  buttonRef?: Ref<HTMLButtonElement>;
}) {
  const t = useT();
  // Containment is where a resource lives; nobody can remove it.
  const removable = step.relationship !== "contains";

  return (
    <div className="flex gap-3">
      <div className="relative flex w-6 shrink-0 justify-center" aria-hidden>
        <span
          className={cn(
            "absolute inset-y-0",
            reading
              ? "w-0.5 bg-primary"
              : cheapest
                ? "border-l border-dashed border-ok-border"
                : "w-px bg-border",
          )}
        />
        <span
          className={cn(
            "relative mt-1.5 flex size-5 items-center justify-center rounded-full border text-[10px] font-medium",
            reading
              ? "border-primary bg-primary text-primary-foreground"
              : cheapest
                ? "border-ok-border bg-ok-bg text-ok"
                : "border-border bg-background text-muted-foreground",
          )}
        >
          {cheapest && !reading ? <ScissorsIcon className="size-3" /> : index + 1}
        </span>
      </div>
      <div className="min-w-0 flex-1 py-1">
        <button
          ref={buttonRef}
          type="button"
          onClick={onRead}
          aria-current={reading ? "step" : undefined}
          aria-label={t.attackPaths.hopOf(index + 1, count, step.detail || step.description)}
          className={cn(
            "-mx-1.5 w-[calc(100%+0.75rem)] rounded-md px-1.5 py-1 text-left text-xs transition-colors hover:bg-muted/60 focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
            reading ? "bg-muted text-sm font-medium text-foreground" : "text-muted-foreground",
          )}
        >
          {reading ? step.detail || step.description : step.description}
        </button>
        {(cheapest || leverage !== null) && (
          <div className="mt-1 flex flex-wrap gap-1.5">
            {cheapest && (
              <span className="rounded-full border border-ok-border bg-ok-bg px-1.5 text-[11px] text-ok">
                {t.attackPaths.earliestCut}
              </span>
            )}
            {leverage !== null && (
              <span className="rounded-full border border-border px-1.5 text-[11px] text-foreground">
                {t.attackPaths.closesMost(leverage)}
              </span>
            )}
          </div>
        )}
        {reading && (
          <div className="mt-2 flex flex-col gap-2">
            {step.facts.length > 0 && (
              <ul className="flex flex-wrap gap-1" aria-label={t.attackPaths.factsLabel}>
                {step.facts.map((fact) => (
                  <li
                    key={fact}
                    className="rounded-md border border-border bg-background px-1.5 py-0.5 text-[11px]"
                  >
                    {fact}
                  </li>
                ))}
              </ul>
            )}
            <p className="text-xs leading-relaxed text-muted-foreground">
              {severance(t, removable, route.key, edge)}
            </p>
            {removable && edge && (
              <div>
                <Button variant={planned ? "secondary" : "outline"} size="xs" onClick={onPlan}>
                  <ScissorsIcon data-icon="inline-start" />
                  {planned ? t.attackPaths.takeOutOfPlan : t.attackPaths.addToPlan}
                </Button>
              </div>
            )}
          </div>
        )}
      </div>
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
