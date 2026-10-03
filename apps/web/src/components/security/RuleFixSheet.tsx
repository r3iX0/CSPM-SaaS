import { useState } from "react";
import { useQueries, useQuery } from "@tanstack/react-query";
import { CheckIcon, WrenchIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { Finding, FindingDetail, RemediationTask } from "@/lib/types";
import { useT } from "@/i18n";
import {
  isOpenTask,
  useMarkAllDone,
  useTrackAll,
  workState,
  worstSeverity,
} from "@/lib/remediation";
import { placeholderValues } from "@/lib/remediationFill";
import { useIsDemo } from "@/lib/useDemo";
import { cn, resourceTypeLabel } from "@/lib/format";
import { RemediationPanel } from "@/components/security/RemediationPanel";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Spinner } from "@/components/ui/spinner";

/** One task of a rule's fix, with the finding it is about. */
export interface RuleFixMember {
  task: RemediationTask;
  finding: FindingDetail;
}

/**
 * One rule's fix, applied to every asset it is on (DECISIONS.md §203).
 *
 * The steps, the Terraform and the policy are the same for every asset, so
 * they are said once; the commands differ only in the names in them, so the
 * CLI is one script with each asset's commands under its name. The work is
 * done together too: mark every open task done at once -- the worker then
 * scans each subscription once for all of them (§18) -- and track the rule's
 * other open findings that nobody has tracked yet. Each asset still opens its
 * own fix, where its Terraform can be checked against an uploaded file and
 * its rescan followed.
 */
export function RuleFixSheet({
  ruleId,
  members,
  onClose,
  onOpenFinding,
}: {
  ruleId: string | null;
  members: readonly RuleFixMember[];
  onClose: () => void;
  onOpenFinding: (findingId: string) => void;
}) {
  // The last rule shown, kept while the sheet animates out (as `FixSheet`).
  const [shown, setShown] = useState(ruleId);
  if (ruleId !== null && ruleId !== shown) setShown(ruleId);

  return (
    <Sheet
      open={ruleId !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <SheetContent className="gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-2xl">
        {shown !== null && (
          <RuleFixBody key={shown} ruleId={shown} members={members} onOpenFinding={onOpenFinding} />
        )}
      </SheetContent>
    </Sheet>
  );
}

function RuleFixBody({
  ruleId,
  members,
  onOpenFinding,
}: {
  ruleId: string;
  members: readonly RuleFixMember[];
  onOpenFinding: (findingId: string) => void;
}) {
  const t = useT();
  const isDemo = useIsDemo();
  const markAll = useMarkAllDone();
  const trackAll = useTrackAll();

  const lead = members[0]?.finding;
  const open = members.filter((member) => isOpenTask(member.task));
  const hasCli = (lead?.remediation_spec?.cli?.length ?? 0) > 0;

  // Each asset's provider id fills its commands, under the asset page's key.
  const assets = useQueries({
    queries: members.map(({ finding }) => ({
      queryKey: ["asset", finding.resource?.id],
      queryFn: () =>
        api
          .get<{ provider_resource_id: string }>(`/api/v1/assets/${finding.resource?.id}`)
          .then((r) => r.data),
      enabled: hasCli && Boolean(finding.resource),
      retry: false,
      staleTime: 60_000,
    })),
  });

  // The rule's open findings nobody has tracked, offered to the same work.
  const untracked = useQuery({
    queryKey: ["findings", "rule", ruleId, "open"],
    queryFn: () =>
      api
        .get<Finding[]>(
          `/api/v1/findings?status=OPEN&rule_id=${encodeURIComponent(ruleId)}&limit=500&offset=0`,
        )
        .then((r) => r.data),
    enabled: !isDemo,
    retry: false,
  });
  const tracked = new Set(members.map((member) => member.finding.id));
  const toTrack = (Array.isArray(untracked.data) ? untracked.data : []).filter(
    (finding) => !tracked.has(finding.id),
  );

  if (!lead) {
    return (
      <div className="p-6 pr-12">
        <SheetTitle>{t.remediation.ruleEmpty}</SheetTitle>
      </div>
    );
  }

  const batch = members.flatMap(({ finding }, index) =>
    finding.resource
      ? [
          {
            resourceName: finding.resource.name,
            values: placeholderValues(finding.resource, assets[index]?.data?.provider_resource_id),
          },
        ]
      : [],
  );
  const effort = open.reduce((sum, member) => sum + member.task.estimated_effort_minutes, 0);
  // The findings' own severity, as every other badge on a finding says it;
  // the task's priority orders the queue and is not a second severity (§208).
  const severity = worstSeverity(members.map((member) => member.finding.severity));

  return (
    <>
      <SheetHeader className="gap-2 border-b px-6 pt-6 pr-12 pb-4">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge level={severity} />
          <span className="font-mono text-caption text-muted-foreground">{ruleId}</span>
        </div>
        <SheetTitle className="text-heading font-semibold">
          {lead.rule_name ?? lead.title}
        </SheetTitle>
        <SheetDescription>{t.remediation.groupCount(members.length, open.length)}</SheetDescription>
      </SheetHeader>

      {/* Cards keep their height and the body scrolls (as `FixSheet`, §208). */}
      <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto p-6 *:shrink-0">
        <section aria-labelledby="rule-fix-assets">
          <h3 id="rule-fix-assets" className="text-caption font-medium text-muted-foreground">
            {t.remediation.groupAssetsHeading}
          </h3>
          <ul className="mt-2 divide-y rounded-lg border">
            {members.map(({ task, finding }) => (
              <li key={task.id} className="flex items-center justify-between gap-3 px-3 py-2">
                <button
                  type="button"
                  onClick={() => onOpenFinding(finding.id)}
                  className={cn(
                    "min-w-0 truncate rounded-sm text-left text-body outline-none hover:underline focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring",
                    !isOpenTask(task) && "text-muted-foreground",
                  )}
                >
                  {finding.resource
                    ? `${finding.resource.name} · ${resourceTypeLabel(finding.resource.resource_type)}`
                    : t.remediation.tenantWide}
                </button>
                <span className="shrink-0 text-caption text-muted-foreground">
                  {t.remediation.work[workState(task, finding)]}
                </span>
              </li>
            ))}
          </ul>
        </section>

        <RemediationPanel
          remediation={lead.remediation}
          spec={lead.remediation_spec}
          effortMinutes={effort || undefined}
          batch={batch}
          footer={
            <div className="flex flex-col gap-4">
              {open.length > 0 && (
                <div className="flex flex-col gap-2">
                  {!isDemo && (
                    <Button
                      variant="secondary"
                      className="w-fit"
                      disabled={markAll.isPending}
                      onClick={() => markAll.mutate(open.map((member) => member.task.id))}
                    >
                      {markAll.isPending ? (
                        <Spinner data-icon="inline-start" />
                      ) : (
                        <CheckIcon data-icon="inline-start" aria-hidden />
                      )}
                      {t.remediation.markAllDone(open.length)}
                    </Button>
                  )}
                  <p className="text-xs text-muted-foreground">{t.remediation.doneNote}</p>
                </div>
              )}
              {!isDemo && toTrack.length > 0 && (
                <div className="flex flex-wrap items-center gap-3">
                  <Button
                    variant="outline"
                    disabled={trackAll.isPending}
                    onClick={() => trackAll.mutate(toTrack.map((finding) => finding.id))}
                  >
                    {trackAll.isPending ? (
                      <Spinner data-icon="inline-start" />
                    ) : (
                      <WrenchIcon data-icon="inline-start" aria-hidden />
                    )}
                    {t.remediation.trackRest(toTrack.length)}
                  </Button>
                  <p className="text-xs text-muted-foreground">
                    {t.remediation.trackRestNote(toTrack.length)}
                  </p>
                </div>
              )}
            </div>
          }
        />
      </div>
    </>
  );
}
