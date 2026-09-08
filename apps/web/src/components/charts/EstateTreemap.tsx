import { useNavigate } from "react-router-dom";
import { Treemap } from "recharts";

import type { AssetScopeNode } from "@/lib/types";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/ui/chart";
import { DURATION, usePrefersReducedMotion } from "@/lib/motion";

type Cell = {
  name: string;
  size: number;
  findings: number;
  scope: string;
  group: string | null;
};

/**
 * The estate at a glance: every resource group sized by what it holds and
 * tinted by what is wrong in it.
 *
 * The one place in this product where area is the right encoding. A tree names
 * the parts and a table ranks them; neither answers "is my problem concentrated
 * or spread out", and that question decides whether a customer sends one team
 * or six.
 *
 * **Tint is sequential, not categorical.** One hue, light to dark, mapped to
 * open findings per asset — a *rate*, not a total, so a large group is not
 * darker merely for being large. A group with nothing wrong is left as plain
 * surface rather than given a colour of its own, because "nothing here" should
 * recede.
 *
 * Labels are drawn only where a cell is big enough to hold one; everything else
 * is reachable by hover and by keyboard through the tree beside it, which is
 * why this is presentation rather than the only way in.
 */
export function EstateTreemap({
  scopes,
  className,
}: {
  scopes: AssetScopeNode[];
  className?: string;
}) {
  const navigate = useNavigate();
  const reduced = usePrefersReducedMotion();

  const cells: Cell[] = scopes.flatMap((scope) =>
    scope.groups
      .filter((group) => group.asset_count > 0)
      .map((group) => ({
        name: group.name ?? `${scope.name} (direct)`,
        size: group.asset_count,
        findings: group.open_findings,
        scope: scope.id,
        group: group.name,
      })),
  );

  if (cells.length === 0) return null;

  const worstRate = Math.max(
    ...cells.map((cell) => cell.findings / Math.max(cell.size, 1)),
    0.0001,
  );

  return (
    <div className={className}>
      {/* An empty config: this chart colours its own cells by finding rate,
          which is a scale rather than a set of named series, so there is
          nothing for the primitive to key a swatch off. It is here for the
          tooltip chrome and the container. */}
      <ChartContainer config={{}} className="aspect-auto size-full">
        <Treemap
          data={cells}
          dataKey="size"
          stroke="var(--card)"
          isAnimationActive={!reduced}
          animationDuration={DURATION.chart}
          content={
            <TreemapCell
              worstRate={worstRate}
              onOpen={(cell) => {
                const params = new URLSearchParams({ subscription_id: cell.scope });
                if (cell.group) params.set("resource_group", cell.group);
                navigate(`/assets?${params.toString()}`);
              }}
            />
          }
        >
          <ChartTooltip
            cursor={false}
            content={
              <ChartTooltipContent
                hideIndicator
                labelKey="name"
                formatter={(_value, _name, item) => {
                  const cell = item?.payload as Cell | undefined;
                  if (!cell) return null;
                  return (
                    <div className="grid gap-0.5">
                      <span className="font-medium">{cell.name}</span>
                      <span className="text-muted-foreground">
                        {cell.size} asset{cell.size === 1 ? "" : "s"} ·{" "}
                        {cell.findings} open finding
                        {cell.findings === 1 ? "" : "s"}
                      </span>
                    </div>
                  );
                }}
              />
            }
          />
        </Treemap>
      </ChartContainer>
    </div>
  );
}

/**
 * One cell. Recharts hands it geometry; everything about how it should look is
 * decided here so the colour rule lives in one place.
 */
function TreemapCell(props: {
  worstRate: number;
  onOpen: (cell: Cell) => void;
  // Supplied by Recharts at render time.
  x?: number;
  y?: number;
  width?: number;
  height?: number;
  payload?: Cell;
  name?: string;
}) {
  const { x = 0, y = 0, width = 0, height = 0, worstRate, onOpen } = props;
  const cell = props.payload;
  if (!cell) return null;

  const rate = cell.findings / Math.max(cell.size, 1);
  // 0 stays as the plain surface; everything else scales between a faint tint
  // and the full status colour of the worst group in the estate.
  const intensity = cell.findings === 0 ? 0 : 0.15 + (rate / worstRate) * 0.55;

  const roomForLabel = width > 64 && height > 28;

  return (
    <g
      role="button"
      tabIndex={-1}
      onClick={() => onOpen(cell)}
      className="cursor-pointer"
    >
      <rect
        x={x}
        y={y}
        width={width}
        height={height}
        rx={3}
        fill={
          cell.findings === 0
            ? "var(--muted)"
            : `color-mix(in oklab, var(--sev-critical) ${Math.round(intensity * 100)}%, var(--card))`
        }
        stroke="var(--card)"
        strokeWidth={2}
      />
      {roomForLabel && (
        <>
          <text
            x={x + 8}
            y={y + 16}
            fill="var(--foreground)"
            fontSize={11}
            className="pointer-events-none"
          >
            {truncate(cell.name, Math.floor(width / 7))}
          </text>
          <text
            x={x + 8}
            y={y + 29}
            fill="var(--muted-foreground)"
            fontSize={10}
            className="pointer-events-none"
          >
            {cell.size} · {cell.findings} open
          </text>
        </>
      )}
    </g>
  );
}

function truncate(value: string, max: number): string {
  if (max <= 1) return "";
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}
