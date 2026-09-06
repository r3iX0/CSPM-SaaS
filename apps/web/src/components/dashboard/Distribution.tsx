import { useState } from "react";

import { useT } from "@/i18n";
import { HelpPopover } from "@/components/common/HelpPopover";
import { StackedBar } from "@/components/charts/StackedBar";
import { cn, label as labelOf } from "@/lib/format";

const LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

const TONE: Record<string, string> = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
};

/**
 * One panel where there were three.
 *
 * Severity mix, a one-segment donut for "where findings stand", and risk bands
 * were three drawings of the same eleven findings, stacked (docs/UI_REDESIGN.md
 * §0). Two of them are genuinely different readings of that set and one was a
 * circle, so what survives is the pair — and the toggle names which reading is
 * on screen instead of leaving the reader to infer it from two charts that
 * disagree.
 *
 * The distinction is the product's whole argument: **as judged** is what the
 * rule concluded in the abstract, **on the asset** is what that means here,
 * once exposure, data sensitivity and business criticality are weighed. A
 * MEDIUM on an internet-facing store holding customer data outranks a HIGH on
 * an empty dev box, and only one of these two views can show that.
 */
export function Distribution({
  bySeverity,
  riskBands,
}: {
  bySeverity: Record<string, number>;
  riskBands: Record<string, number>;
}) {
  const t = useT();
  const [view, setView] = useState<"asset" | "judged">("asset");

  const counts = view === "asset" ? riskBands : bySeverity;
  const total = LEVELS.reduce((sum, level) => sum + (counts[level] ?? 0), 0);

  return (
    <section
      aria-labelledby="distribution"
      className="flex flex-col gap-4 rounded-xl border bg-card px-5 py-4"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2
          id="distribution"
          className="flex items-center gap-1 text-sm font-semibold"
        >
          {t.dashboard.distribution}
          <HelpPopover label="Which reading this is">
            {view === "asset"
              ? t.dashboard.onTheAssetHelp
              : t.dashboard.asJudgedHelp}
          </HelpPopover>
        </h2>

        {/* Not a filter: both readings are of the same set, and the toggle
            says which of the two is on screen. */}
        <div
          role="group"
          aria-label={t.dashboard.distribution}
          className="flex items-center rounded-lg border p-0.5 text-xs"
        >
          <Toggle
            on={view === "asset"}
            onClick={() => setView("asset")}
            label={t.dashboard.onTheAsset}
          />
          <Toggle
            on={view === "judged"}
            onClick={() => setView("judged")}
            label={t.dashboard.asJudged}
          />
        </div>
      </div>

      {total === 0 ? (
        <p className="text-[13px] text-muted-foreground">
          {t.dashboard.nothingOpen}
        </p>
      ) : (
        <StackedBar
          ariaLabel={
            view === "asset" ? t.dashboard.onTheAsset : t.dashboard.asJudged
          }
          segments={LEVELS.map((level) => ({
            key: level,
            label: labelOf(level),
            value: counts[level] ?? 0,
            tone: TONE[level],
          }))}
        />
      )}

    </section>
  );
}

function Toggle({
  on,
  onClick,
  label,
}: {
  on: boolean;
  onClick: () => void;
  label: string;
}) {
  return (
    <button
      type="button"
      aria-pressed={on}
      onClick={onClick}
      className={cn(
        "rounded-md px-2.5 py-1 transition-colors",
        "focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50",
        on ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground",
      )}
    >
      {label}
    </button>
  );
}
