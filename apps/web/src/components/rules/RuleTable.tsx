import type { Rule } from "@/lib/types";
import { useT } from "@/i18n";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn, formatEffort, resourceTypeLabel } from "@/lib/format";

/**
 * The catalogue, as a table.
 *
 * It was ninety cards, each carrying its description, its exploitability, its
 * effort and a button that unfolded a rationale and four fix formats. A
 * catalogue is read by comparing entries — what is this severity, what does it
 * apply to, what does it cost to fix — and a card feed makes every one of those
 * a scroll. The document half moves into the drawer beside the table, the same
 * shape the risks ranking took (docs/UI_REDESIGN.md §4.2).
 *
 * A withdrawn rule is dashed and named rather than greyed away: it has stopped
 * running, and its severity describes what it used to check.
 */
export function RuleTable({
  rules,
  selectedId,
  onSelect,
}: {
  rules: Rule[];
  selectedId?: string;
  onSelect: (rule: Rule) => void;
}) {
  const t = useT();

  return (
    <Table className="min-w-[780px]">
      <TableHeader>
        <TableRow>
          <TableHead>{t.rules.checkColumn}</TableHead>
          <TableHead className="w-[96px]">{t.common.severity}</TableHead>
          <TableHead className="w-[168px]">{t.rules.appliesToColumn}</TableHead>
          <TableHead className="w-[178px]">{t.rules.idColumn}</TableHead>
          <TableHead className="w-[84px] text-right">
            {t.rules.effortColumn}
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rules.map((rule) => (
          <TableRow
            key={rule.rule_id}
            onClick={() => onSelect(rule)}
            data-state={rule.rule_id === selectedId ? "selected" : undefined}
            className={cn(
              "cursor-pointer",
              rule.rule_id === selectedId &&
                "bg-primary/[0.06] shadow-[inset_2px_0_0_var(--color-primary)] hover:bg-primary/[0.06]",
            )}
          >
            <TableCell className="max-w-0">
              <span className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={(event) => {
                    event.stopPropagation();
                    onSelect(rule);
                  }}
                  className="truncate text-left text-[13px] font-medium text-foreground underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
                >
                  {rule.name}
                </button>
                {!rule.enabled && (
                  <span className="shrink-0 rounded-md border border-dashed border-unknown-border bg-unknown-bg px-1.5 py-0.5 text-[11px] text-unknown">
                    {t.rules.withdrawn}
                  </span>
                )}
                {/* A tenant-wide rule is about the directory rather than any
                    one resource, which is why nothing in the asset list
                    carries it. */}
                {rule.scope === "aggregate" && (
                  <span className="shrink-0 rounded-md bg-secondary px-1.5 py-0.5 text-[11px] text-muted-foreground">
                    {t.rules.tenantWide}
                  </span>
                )}
              </span>
              <span className="mt-0.5 block truncate text-xs text-meta-foreground">
                {rule.description}
              </span>
            </TableCell>

            <TableCell>
              <SeverityBadge level={rule.severity} />
            </TableCell>

            <TableCell className="max-w-0">
              <span className="block truncate text-xs text-muted-foreground">
                {rule.applies_to.length > 0
                  ? rule.applies_to.map(resourceTypeLabel).join(", ")
                  : t.rules.appliesToDirectory}
              </span>
            </TableCell>

            <TableCell className="max-w-0">
              <span className="block truncate font-mono text-xs text-meta-foreground">
                {rule.rule_id}
              </span>
            </TableCell>

            <TableCell className="text-right text-xs text-muted-foreground">
              {formatEffort(rule.estimated_effort_minutes)}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
