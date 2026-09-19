import { useId, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { TriangleAlertIcon } from "lucide-react";

import type { DashboardRegion, Severity } from "@/lib/types";
import { WORLD_GRID, WORLD_LAND } from "@/lib/geo/worldDots";
import { NO_REGION, regionInfo, regionLabel, type RegionInfo } from "@/lib/geo/regions";
import { FACT_ICONS } from "@/lib/icons";
import { ProviderMark } from "@/components/security/ProviderMark";
import { cn } from "@/lib/format";

const ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

/**
 * Classes per worst open severity, `NONE` being nothing open. Written out in
 * full rather than built from the level's name, because Tailwind only emits a
 * class it can find spelled in the source.
 */
const TONE: Record<Severity | "NONE", { fill: string; text: string; dot: string }> = {
  CRITICAL: { fill: "fill-critical", text: "text-critical", dot: "bg-critical" },
  HIGH: { fill: "fill-high", text: "text-high", dot: "bg-high" },
  MEDIUM: { fill: "fill-medium", text: "text-medium", dot: "bg-medium" },
  LOW: { fill: "fill-low", text: "text-low", dot: "bg-low" },
  NONE: { fill: "fill-ok", text: "text-ok", dot: "bg-ok" },
};

/** How many regions the list names before handing over to the asset list. */
const LISTED = 6;

const worst = (region: DashboardRegion): Severity | "NONE" =>
  ORDER.find((level) => (region.by_severity[level] ?? 0) > 0) ?? "NONE";

/**
 * The land, as horizontal runs of grid cells.
 *
 * Built once per module rather than per render: it is the same world every
 * time. Runs rather than a path per cell, because a mask of a few hundred
 * rectangles is a small attribute and a path of ~2,700 dots is a large one;
 * the dots come from a pattern the runs reveal.
 */
const LAND_RUNS = (() => {
  let d = "";
  WORLD_LAND.forEach((hex, y) => {
    const bits = [...hex]
      .map((digit) => Number.parseInt(digit, 16).toString(2).padStart(4, "0"))
      .join("")
      .slice(0, WORLD_GRID.columns);
    let start = -1;
    for (let x = 0; x <= bits.length; x += 1) {
      const land = bits[x] === "1";
      if (land && start < 0) start = x;
      if (!land && start >= 0) {
        d += `M${start} ${y}h${x - start}v1h${start - x}z`;
        start = -1;
      }
    }
  });
  return d;
})();

/** A coordinate onto the grid: equirectangular, one unit a cell. */
function project({ lat, lon }: RegionInfo): { x: number; y: number } {
  return {
    x: (lon - WORLD_GRID.west) / WORLD_GRID.step,
    y: (WORLD_GRID.north - lat) / WORLD_GRID.step,
  };
}

const href = (region: string | null) =>
  `/assets?region=${encodeURIComponent(region ?? NO_REGION)}`;

type Placed = DashboardRegion & { region: string };

/**
 * Where the estate runs, and where what is wrong with it runs (DECISIONS.md §113).
 *
 * On this page because of the second half. An inventory of regions is a fact
 * about the estate and the page carries no inventory as a headline; a region
 * holding the only critical finding, or one the last scan could not read, is a
 * fact about the posture. So every dot is coloured by the worst thing open
 * there and sized — gently — by how much runs there, and the list beside it is
 * ranked the way the API ranks it: one critical outranks any number of lows.
 *
 * The map is a picture and the list is the content. The SVG is hidden from
 * assistive technology and out of the tab order; every region it draws is a
 * row in the list, which is what a keyboard reaches and a screen reader reads
 * — the same split the estate map makes (§112). Clicking a dot is a
 * convenience for a mouse, not the only way in.
 *
 * Three things are refused. A region CloudGuard has no coordinates for is
 * listed by its code and not drawn, because a dot in the wrong place is worse
 * than none. Everything tied to no region is a line under the list, never a
 * point on the map — "global" is not somewhere. And a region the last scan
 * could not read is ringed and said to be unread, because a region with
 * nothing open that nobody looked at is not a clean region.
 */
export function RegionPanel({ regions }: { regions: DashboardRegion[] }) {
  const navigate = useNavigate();
  const patternId = useId();
  const maskId = useId();
  const [active, setActive] = useState<string | null>(null);

  const placed = regions.filter((region): region is Placed => region.region !== null);
  const unplaced = regions.find((region) => region.region === null);
  if (placed.length === 0) return null;

  const drawn = placed.flatMap((region) => {
    const info = regionInfo(region.region);
    return info ? [{ region, info }] : [];
  });
  const largest = Math.max(1, ...placed.map((region) => region.assets));
  const providers = new Set(regions.map((region) => region.provider).filter(Boolean));
  const unread = placed.filter((region) => region.unread > 0);
  const assets = placed.reduce((sum, region) => sum + region.assets, 0);
  const withFindings = placed.filter((region) => region.open_findings > 0);
  const listed = placed.slice(0, LISTED);
  const key = (region: DashboardRegion) => `${region.provider}:${region.region}`;

  return (
    <section
      aria-labelledby="estate-regions"
      className="overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10"
    >
      <div className="px-5 pt-4">
        <h2 id="estate-regions" className="flex items-center gap-2 text-sm font-semibold">
          <FACT_ICONS.region className="size-4 text-muted-foreground" aria-hidden />
          Where it runs
        </h2>
        <p className="mt-0.5 max-w-2xl text-xs leading-relaxed text-muted-foreground">
          {assets} {assets === 1 ? "asset" : "assets"} in {placed.length}{" "}
          {placed.length === 1 ? "region" : "regions"}
          {withFindings.length > 0
            ? `, with open findings in ${withFindings.length}. The worst is ${regionLabel(
                withFindings[0].region,
              )}.`
            : ", and nothing open in any of them."}
          {unread.length > 0 &&
            ` ${unread.length} ${
              unread.length === 1 ? "region" : "regions"
            } could not be fully read — nothing open there is not the same as nothing wrong.`}
        </p>
      </div>

      <div className="flex flex-col gap-4 px-5 pb-4 pt-3 lg:flex-row lg:items-start">
        <svg
          viewBox={`0 0 ${WORLD_GRID.columns} ${WORLD_GRID.rows}`}
          className="w-full min-w-0 lg:flex-[3]"
          aria-hidden
          focusable="false"
          data-testid="region-map"
        >
          <defs>
            <pattern id={patternId} width="1" height="1" patternUnits="userSpaceOnUse">
              <circle cx="0.5" cy="0.5" r="0.3" className="fill-foreground/20" />
            </pattern>
            <mask id={maskId}>
              <path d={LAND_RUNS} fill="white" />
            </mask>
          </defs>
          <rect
            width={WORLD_GRID.columns}
            height={WORLD_GRID.rows}
            fill={`url(#${patternId})`}
            mask={`url(#${maskId})`}
          />

          {/* Largest first, so a small region is drawn over a big neighbour
              rather than hidden under it. */}
          {[...drawn]
            .sort((a, b) => b.region.assets - a.region.assets)
            .map(({ region, info }) => {
              const { x, y } = project(info);
              const radius = 1 + 1.6 * Math.sqrt(region.assets / largest);
              const on = active === key(region);
              // A clean region is drawn quietly. Size says how much runs there,
              // and on a page about what is wrong the biggest estate with
              // nothing open must not be the loudest mark on the map.
              const clean = region.open_findings === 0 && region.unread === 0;
              return (
                <g
                  key={key(region)}
                  className={cn("cursor-pointer", TONE[worst(region)].fill)}
                  onClick={() => navigate(href(region.region))}
                  onMouseEnter={() => setActive(key(region))}
                  onMouseLeave={() => setActive(null)}
                  data-region={region.region}
                >
                  {(!clean || on) && (
                    <circle cx={x} cy={y} r={radius + 1.4} opacity={on ? 0.3 : 0.12} />
                  )}
                  <circle
                    cx={x}
                    cy={y}
                    r={radius}
                    opacity={clean ? 0.5 : 1}
                    className="stroke-card"
                    strokeWidth={0.35}
                  />
                  {region.unread > 0 && (
                    <circle
                      cx={x}
                      cy={y}
                      r={radius + 0.9}
                      fill="none"
                      className="stroke-medium"
                      strokeWidth={0.3}
                      strokeDasharray="0.6 0.5"
                    />
                  )}
                </g>
              );
            })}
        </svg>

        <div className="flex min-w-0 flex-col lg:flex-[2]">
          <ol className="flex flex-col">
            {listed.map((region) => (
              <RegionRow
                key={key(region)}
                region={region}
                showProvider={providers.size > 1}
                active={active === key(region)}
                onActive={(on) => setActive(on ? key(region) : null)}
              />
            ))}
          </ol>
          {placed.length > LISTED && (
            <Link
              to="/assets"
              className="mt-1 px-2 text-xs text-muted-foreground underline-offset-2 hover:underline"
            >
              and {placed.length - LISTED} more{" "}
              {placed.length - LISTED === 1 ? "region" : "regions"} in the asset list
            </Link>
          )}
          {unplaced && (unplaced.assets > 0 || unplaced.open_findings > 0) && (
            <Link
              to={href(null)}
              className="mt-2 border-t border-dashed px-2 pt-2 text-xs text-muted-foreground hover:text-foreground"
            >
              <span className="font-medium text-foreground">
                {unplaced.assets} {unplaced.assets === 1 ? "asset" : "assets"}
              </span>{" "}
              not tied to a region — the directory, and anything the provider calls global
              {unplaced.open_findings > 0 && (
                <>
                  {", "}
                  <span className={cn("font-medium", TONE[worst(unplaced)].text)}>
                    {unplaced.open_findings} open
                  </span>
                </>
              )}
            </Link>
          )}
        </div>
      </div>
    </section>
  );
}

function RegionRow({
  region,
  showProvider,
  active,
  onActive,
}: {
  region: Placed;
  showProvider: boolean;
  active: boolean;
  onActive: (on: boolean) => void;
}) {
  const info = regionInfo(region.region);
  const tone = TONE[worst(region)];
  // AWS names carry their place already -- "Asia Pacific (Sydney)" -- and
  // saying Sydney twice costs the row the width it needs on a phone.
  const place = info ? (info.name.includes(info.place) ? null : info.place) : null;
  return (
    <li>
      <Link
        to={href(region.region)}
        onMouseEnter={() => onActive(true)}
        onMouseLeave={() => onActive(false)}
        onFocus={() => onActive(true)}
        onBlur={() => onActive(false)}
        className={cn(
          "flex items-center gap-3 rounded-md px-2 py-1.5 text-xs transition-colors hover:bg-muted/60",
          active && "bg-muted/60",
        )}
      >
        <span className={cn("size-2 shrink-0 rounded-full", tone.dot)} aria-hidden />
        {showProvider && <ProviderMark provider={region.provider} className="size-3.5" />}
        {/* Two lines, so the name keeps the width on a phone: what it is
            called, then where it is and what runs there. */}
        <span className="flex min-w-0 flex-1 flex-col">
          <span className="truncate font-medium">{info?.name ?? region.region}</span>
          <span className="flex min-w-0 items-center gap-1.5 text-muted-foreground">
            <span className="truncate">
              {(place || !info) && `${place ?? "location not known to CloudGuard"} · `}
              <span className="tabular-nums">
                {region.assets} {region.assets === 1 ? "asset" : "assets"}
              </span>
            </span>
            {region.unread > 0 && (
              <span className="flex shrink-0 items-center gap-1 text-medium">
                <TriangleAlertIcon className="size-3" aria-hidden />
                {region.unread} unread
              </span>
            )}
          </span>
        </span>
        <span className={cn("shrink-0 text-right font-medium tabular-nums", tone.text)}>
          {region.open_findings > 0 ? `${region.open_findings} open` : "nothing open"}
        </span>
      </Link>
    </li>
  );
}
