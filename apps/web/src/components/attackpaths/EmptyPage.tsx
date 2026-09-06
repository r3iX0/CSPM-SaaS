import { Link } from "react-router-dom";
import { CheckIcon, XIcon } from "lucide-react";

import type { AttackPathMeta, Scan } from "@/lib/types";
import { useT } from "@/i18n";
import { HelpPopover } from "@/components/common/HelpPopover";
import { buttonVariants } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { cn, formatDateTime } from "@/lib/format";

/**
 * The empty state is the page.
 *
 * Most new tenants have no attack path, and for two of the three reasons that
 * is not good news: nothing classified as sensitive means CloudGuard does not
 * know what would cost the customer anything, which is a gap in what it was
 * told rather than a clean environment (docs/UI_REDESIGN.md §4.5).
 *
 * So the reader is shown *which precondition is missing* rather than told in a
 * paragraph. A route needs three things — a reading, somewhere to start, and
 * something worth reaching — and the strip says which of the three CloudGuard
 * has. The sentence that used to carry this argument is still the body text; it
 * is now the answer to a question the strip has already asked.
 */
export function AttackPathsEmpty({
  meta,
  scan,
}: {
  meta: AttackPathMeta;
  /** The latest scan, for the one precondition the graph cannot report on. */
  scan: Scan | null | undefined;
}) {
  const t = useT();

  const scanned = Boolean(scan?.completed_at);
  const hasEntry = meta.entry_points > 0;
  const hasTargets = meta.sensitive_targets > 0;

  const state = !scanned
    ? "no-scan"
    : !hasTargets
      ? "no-targets"
      : !hasEntry
        ? "no-entry"
        : "no-paths";

  const copy = {
    "no-scan": {
      title: t.attackPaths.emptyNoScan,
      detail: t.attackPaths.emptyNoScanDetail,
      action: { label: t.dashboard.runFirstScan, to: "/scans" },
    },
    "no-targets": {
      title: t.attackPaths.emptyNoTargets,
      detail: t.attackPaths.emptyNoTargetsDetail,
      action: { label: t.attackPaths.classifyAssets, to: "/settings" },
    },
    "no-entry": {
      title: t.attackPaths.emptyNoEntry,
      detail: t.attackPaths.emptyNoEntryDetail,
      action: { label: t.attackPaths.seeAssets, to: "/assets" },
    },
    "no-paths": {
      title: t.attackPaths.emptyNoPaths,
      detail: t.attackPaths.emptyNoPathsDetail,
      action: { label: t.attackPaths.seeAssets, to: "/assets" },
    },
  }[state];

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardContent className="flex flex-wrap gap-x-10 gap-y-4 divide-border">
          <Precondition
            met={scanned}
            label={t.attackPaths.preScan}
            detail={
              scan?.completed_at
                ? `${formatDateTime(scan.completed_at)} · ${scan.resource_count} ${t.attackPaths.assetsRead}`
                : t.attackPaths.preScanMissing
            }
          />
          <Precondition
            met={hasEntry}
            label={t.attackPaths.preEntry}
            detail={`${meta.entry_points} ${t.attackPaths.reachableFromInternet}`}
          />
          <Precondition
            met={hasTargets}
            label={t.attackPaths.preTargets}
            detail={`${meta.sensitive_targets} ${t.attackPaths.carryAClassification}`}
          />
        </CardContent>
      </Card>

      <Card>
        <CardContent className="flex flex-col items-center gap-6 py-8 text-center">
          <RouteDiagram
            entry={hasEntry}
            route={state === "no-paths"}
            target={hasTargets}
            entryCount={meta.entry_points}
            targetCount={meta.sensitive_targets}
          />

          <div className="max-w-xl">
            <h2 className="text-lg font-semibold text-foreground">{copy.title}</h2>
            <p className="mt-2 text-[13px] leading-relaxed text-muted-foreground">
              {copy.detail}
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-2">
            <Link to={copy.action.to} className={buttonVariants()}>
              {copy.action.label}
            </Link>
            <HelpPopover
              label="How paths are built"
              title={t.attackPaths.howPathsAreBuilt}
              align="center"
            >
              {t.attackPaths.intro}
            </HelpPopover>
          </div>
        </CardContent>
      </Card>

      <ExamplePath />
    </div>
  );
}

/** One of the three things a route needs, and whether this estate has it. */
function Precondition({
  met,
  label,
  detail,
}: {
  met: boolean;
  label: string;
  detail: string;
}) {
  return (
    <div className="flex min-w-0 items-start gap-2.5">
      <span
        className={cn(
          "mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full",
          met ? "bg-ok-bg text-ok" : "bg-medium-bg text-medium",
        )}
        aria-hidden
      >
        {met ? <CheckIcon className="size-3" /> : <XIcon className="size-3" />}
      </span>
      <span className="min-w-0">
        <span className="block text-[13px] font-medium text-foreground">
          {label}
        </span>
        <span className="block text-xs text-meta-foreground">{detail}</span>
      </span>
    </div>
  );
}

/**
 * The shape of the thing that is missing.
 *
 * Three nodes, and the one the estate cannot supply is amber and dashed —
 * which is the same treatment UNKNOWN carries everywhere else in the product,
 * so it reads as "not established" rather than as "broken".
 */
function RouteDiagram({
  entry,
  route,
  target,
  entryCount,
  targetCount,
}: {
  entry: boolean;
  route: boolean;
  target: boolean;
  entryCount: number;
  targetCount: number;
}) {
  const t = useT();

  return (
    <div className="flex items-start gap-3" aria-hidden>
      <Node
        met={entry}
        label={`${entryCount} ${entryCount === 1 ? t.attackPaths.entryPoint : t.attackPaths.entryPoints}`}
        detail={entry ? t.attackPaths.found : t.attackPaths.noneFound}
      />
      <Connector />
      <Node
        met={route}
        label={t.attackPaths.theRoute}
        detail={route ? t.attackPaths.found : t.attackPaths.nothingToTrace}
        tone="neutral"
      />
      <Connector />
      <Node
        met={target}
        label={`${targetCount} ${targetCount === 1 ? t.attackPaths.target : t.attackPaths.targets}`}
        detail={target ? t.attackPaths.found : t.attackPaths.nothingSensitive}
      />
    </div>
  );
}

function Node({
  met,
  label,
  detail,
  tone = "amber",
}: {
  met: boolean;
  label: string;
  detail: string;
  tone?: "amber" | "neutral";
}) {
  return (
    <div className="flex w-24 flex-col items-center gap-2">
      <span
        className={cn(
          "flex size-12 items-center justify-center rounded-full border",
          met && "border-primary text-primary",
          !met && tone === "amber" && "border-dashed border-medium text-medium",
          !met && tone === "neutral" && "border-dashed border-border text-meta-foreground",
        )}
      >
        <span className="size-3 rounded-sm border border-current" />
      </span>
      <span className="text-[11px] font-medium text-foreground">{label}</span>
      <span className="-mt-1.5 text-[10px] text-meta-foreground">{detail}</span>
    </div>
  );
}

function Connector() {
  return (
    <span
      className="mt-6 h-px w-10 border-t border-dashed border-border"
      aria-hidden
    />
  );
}

/**
 * What this page becomes, clearly labelled as not being this estate.
 *
 * A screen that is empty for a good reason still has to say what it is for.
 * The label is load-bearing: an example route rendered in the product's own
 * style, on a page about the reader's environment, is a claim about their
 * environment unless it says otherwise.
 */
function ExamplePath() {
  const t = useT();

  const hops = [
    { title: "Internet → jump box", asset: "vm-bastion-01" },
    { title: "Managed identity, over-privileged", asset: "mi-app-prod" },
    { title: "Storage holding PII", asset: "sa-customer-data" },
  ];

  return (
    <Card>
      <CardContent className="flex flex-col gap-3">
        <p className="text-[11px] font-medium uppercase tracking-[0.12em] text-meta-foreground">
          {t.attackPaths.whatYouWouldSee}{" "}
          <span className="normal-case tracking-normal text-medium">
            {t.attackPaths.exampleNotYours}
          </span>
        </p>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-3 rounded-lg border border-dashed px-4 py-3">
          {hops.map((hop, index) => (
            <div key={hop.asset} className="flex min-w-0 items-center gap-4">
              {index > 0 && (
                <span className="text-meta-foreground" aria-hidden>
                  →
                </span>
              )}
              <span className="min-w-0">
                <span className="block truncate text-[13px] text-muted-foreground">
                  {hop.title}
                </span>
                <span className="block truncate font-mono text-[11px] text-meta-foreground">
                  {hop.asset}
                </span>
              </span>
            </div>
          ))}
          <span className="ml-auto shrink-0 text-right">
            <span className="block font-mono text-xl font-medium text-meta-foreground">
              {hops.length}
            </span>
            <span className="block text-[10px] uppercase tracking-[0.12em] text-meta-foreground">
              {t.attackPaths.hops}
            </span>
          </span>
        </div>

        <p className="text-xs text-muted-foreground">
          {t.attackPaths.exampleNote}
        </p>
      </CardContent>
    </Card>
  );
}
