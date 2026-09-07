import { Fragment, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ChevronRightIcon } from "lucide-react";

import type { Level, Risk } from "@/lib/types";
import { useT } from "@/i18n";
import { RiskScore } from "@/components/security/SecurityScore";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { StatusPill } from "@/components/security/StatusPill";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/format";

/**
 * The ranking, as a table.
 *
 * It was a card feed: eleven full-width cards, each with a five-line
 * paragraph, three of them byte-identical because three identities failed the
 * same check (docs/UI_REDESIGN.md §4.2). A ranking is a comparison, and a
 * comparison wants one line per row with the compared value in the same column
 * every time. The paragraph moves to the drawer, where it is shown for one
 * risk rather than for eleven at once.
 *
 * Every text cell is one line and clips. A row that wraps breaks the scan down
 * the score column, which is the only reason the reader is here.
 */
export function RiskTable({
  risks,
  selectedId,
  grouped,
  onSelect,
}: {
  risks: Risk[];
  selectedId?: string;
  /** Whether rows failing the same check collapse into one. */
  grouped: boolean;
  onSelect: (risk: Risk) => void;
}) {
  const groups = useMemo(() => groupRisks(risks, grouped), [risks, grouped]);
  const [open, setOpen] = useState<Record<string, boolean>>({});

  return (
    <Table className="min-w-[560px]">
      <TableHeader>
        <TableRow>
          <TableHead>Risk</TableHead>
          <TableHead className="w-[150px]">Exposure</TableHead>
          <TableHead className="w-[56px] text-right">Score</TableHead>
          <TableHead className="w-[84px]">Status</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {groups.map((group) => {
          const lead = group.risks[0];
          const duplicated = group.risks.length > 1;
          const expanded = open[group.key] ?? false;

          return (
            <Fragment key={group.key}>
              <Row
                risk={lead}
                selected={lead.id === selectedId}
                onSelect={() => onSelect(lead)}
                count={duplicated ? group.risks.length : undefined}
                expanded={duplicated ? expanded : undefined}
                onToggle={
                  duplicated
                    ? () =>
                        setOpen((state) => ({
                          ...state,
                          [group.key]: !expanded,
                        }))
                    : undefined
                }
              />

              {/* The children carry the asset, which is the only thing that
                  differs between them, and the reason the parent row cannot
                  simply be one of them. */}
              {duplicated &&
                expanded &&
                group.risks.map((risk) => (
                  <Row
                    key={risk.id}
                    risk={risk}
                    selected={risk.id === selectedId}
                    onSelect={() => onSelect(risk)}
                    child
                  />
                ))}
            </Fragment>
          );
        })}
      </TableBody>
    </Table>
  );
}

function Row({
  risk,
  selected,
  onSelect,
  count,
  expanded,
  onToggle,
  child = false,
}: {
  risk: Risk;
  selected: boolean;
  onSelect: () => void;
  count?: number;
  expanded?: boolean;
  onToggle?: () => void;
  child?: boolean;
}) {
  const t = useT();

  return (
    <TableRow
      data-state={selected ? "selected" : undefined}
      onClick={onSelect}
      className={cn(
        "cursor-pointer",
        // Never a full border: a ring around one row in a dense table reads as
        // a second grid.
        selected &&
          "bg-primary/[0.06] shadow-[inset_2px_0_0_var(--color-primary)] hover:bg-primary/[0.06]",
      )}
    >
      <TableCell className="max-w-0">
        <div className={cn("flex items-center gap-2", child && "pl-6")}>
          {onToggle && (
            <button
              type="button"
              aria-label={expanded ? "Collapse duplicates" : "Expand duplicates"}
              aria-expanded={expanded}
              onClick={(event) => {
                event.stopPropagation();
                onToggle();
              }}
              className="shrink-0 rounded text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
            >
              <ChevronRightIcon
                className={cn(
                  "size-4 transition-transform",
                  expanded && "rotate-90",
                )}
                aria-hidden
              />
            </button>
          )}

          <span className="min-w-0 flex-1">
            <span className="flex items-center gap-2">
              {/* A link, not only a click handler on the row: the ranking is
                  navigated with a keyboard as often as with a mouse, and a row
                  that only answers to a click cannot be tabbed to, opened in a
                  new tab, or read out as a destination. */}
              <Link
                to={`/risks/${risk.id}`}
                onClick={(event) => event.stopPropagation()}
                className={cn(
                  "truncate text-[13px] font-medium text-foreground underline-offset-4 hover:underline",
                  child && "font-mono font-normal",
                )}
              >
                {child ? assetOf(risk) : risk.title}
              </Link>
              {count !== undefined && (
                <span className="shrink-0 font-mono text-[11px] text-meta-foreground">
                  {`×${count}`}
                </span>
              )}
            </span>
            <span className="mt-0.5 block truncate text-xs text-meta-foreground">
              {child ? t.risks.sameCheck : risk.description}
            </span>
          </span>
        </div>
      </TableCell>

      <TableCell>
        <ExposureChips risk={risk} />
      </TableCell>

      <TableCell className="text-right">
        <RiskScore score={Number(risk.risk_score)} />
      </TableCell>

      <TableCell>
        <StatusPill status={risk.status} />
      </TableCell>
    </TableRow>
  );
}

/**
 * What makes this worse than the same misconfiguration somewhere quiet.
 *
 * A dashed "exposure unknown" rather than nothing at all: an asset nobody
 * classified is not an asset with nothing on it, and a blank cell is exactly
 * the reading that makes a missing declaration look like an all-clear.
 */
function ExposureChips({ risk }: { risk: Risk }) {
  const t = useT();
  const raised: { key: string; label: string; level: Level }[] = [];

  if (isRaised(risk.internet_exposure))
    raised.push({
      key: "net",
      label: t.risks.internetFacing,
      level: "CRITICAL",
    });
  if (isRaised(risk.data_sensitivity))
    raised.push({ key: "data", label: t.risks.sensitiveData, level: "HIGH" });
  if (isRaised(risk.asset_criticality))
    raised.push({
      key: "crit",
      label: t.risks.businessCritical,
      level: "HIGH",
    });

  if (raised.length === 0) {
    return (
      <SeverityBadge level="UNKNOWN" size="sm">
        {t.risks.exposureUnknown}
      </SeverityBadge>
    );
  }

  return (
    <div className="flex flex-wrap gap-1">
      {raised.map((chip) => (
        <SeverityBadge key={chip.key} level={chip.level} size="sm">
          {chip.label}
        </SeverityBadge>
      ))}
    </div>
  );
}

const isRaised = (level: Level) => level === "CRITICAL" || level === "HIGH";

/** The one thing a duplicate row does not share with its siblings. */
function assetOf(risk: Risk): string {
  const [, asset] = risk.title.split(" — ");
  return asset ?? risk.title;
}

/**
 * Rows failing the same check, as one row.
 *
 * Grouped on the check rather than on the whole title, because the title
 * carries the asset: "Role assignment permits every action" against three
 * object ids is three strings for one mistake with one fix.
 *
 * Grouping happens over the page the reader is looking at, not over the
 * estate. The API pages the ranking, so a count claiming to be estate-wide
 * would be a number this component cannot know.
 */
function groupRisks(risks: Risk[], grouped: boolean) {
  if (!grouped) {
    return risks.map((risk) => ({ key: risk.id, risks: [risk] }));
  }

  const groups: { key: string; risks: Risk[] }[] = [];
  const index = new Map<string, number>();

  for (const risk of risks) {
    // A scenario is one route and never a duplicate of another: two routes
    // that read alike still start and end somewhere different.
    const key = risk.kind === "FINDING" ? checkOf(risk) : risk.id;
    const at = index.get(key);
    if (at === undefined) {
      index.set(key, groups.length);
      groups.push({ key, risks: [risk] });
    } else {
      groups[at].risks.push(risk);
    }
  }

  return groups;
}

/** The rule half of a finding risk's title, without the asset it names. */
function checkOf(risk: Risk): string {
  const [check] = risk.title.split(" — ");
  return `${check} ${risk.description}`;
}
