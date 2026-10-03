import { Link } from "react-router-dom";
import { ArrowRightIcon, WrenchIcon } from "lucide-react";

import type { FindingDetail } from "@/lib/types";
import { useT } from "@/i18n";
import { fixPath, isTrackable, taskFor, useRemediationQueue, useTrack } from "@/lib/remediation";
import { useIsDemo } from "@/lib/useDemo";
import { Button, buttonVariants } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDate, formatEffort } from "@/lib/format";

/**
 * What the fix is, in a paragraph, and the way to it.
 *
 * The full fix -- every form of it, tracking, marking done, verifying -- is
 * read on the remediation page (DECISIONS.md §202). Here it is what a reader
 * needs to decide whether to go there: the effort, the first paragraph of the
 * steps, which forms the full fix comes in, and where the work stands. A
 * reader who came for the attack paths no longer scrolls past a page of CLI to
 * reach them.
 *
 * Tracking is the one piece of the work offered here as well. Reading the fix
 * is a click away, but deciding to do it is not a reason to leave the page:
 * with the button only in the sheet, a reader on the finding saw no way to
 * queue it at all (DECISIONS.md §205).
 */
export function FixSummary({ finding }: { finding: FindingDetail }) {
  const t = useT();
  const isDemo = useIsDemo();
  const tasks = useRemediationQueue();
  const task = taskFor(tasks.data, finding.id);
  const track = useTrack();
  // Once the queue has answered, so a tracked finding never flashes the button.
  const canTrack = tasks.isSuccess && !task && isTrackable(finding.status) && !isDemo;
  const spec = finding.remediation_spec;

  // Only the forms this rule actually has, as the sheet's tabs are (§202).
  const forms = [
    (spec?.cli?.length ?? 0) > 0 && "CLI",
    (spec?.terraform?.length ?? 0) > 0 && "Terraform",
    spec?.azure_policy && "Policy",
  ].filter((form): form is string => typeof form === "string");

  // The prose opens with what to do; what follows is how and why.
  const lead = finding.remediation.split(/\n\s*\n/)[0]?.trim() ?? "";

  const verification = finding.verification
    ? t.remediation.verification[finding.verification.status]
    : null;
  const progress = task
    ? task.status === "DONE"
      ? t.remediation.doneOn(formatDate(task.completed_at))
      : t.remediation.trackedSince(formatDate(task.created_at))
    : null;
  const facts = [
    forms.length > 0 ? t.remediation.forms(forms.join(", ")) : null,
    verification ?? progress,
  ].filter((fact): fact is string => fact !== null);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recommended fix</CardTitle>
        <CardDescription>
          {finding.estimated_effort_minutes
            ? `Estimated effort: ${formatEffort(finding.estimated_effort_minutes)}`
            : "What to change, and how to confirm it took"}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {lead && <p className="text-sm leading-relaxed text-foreground">{lead}</p>}
        <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
          <p className="text-xs text-muted-foreground">{facts.join(" · ")}</p>
          <div className="flex flex-wrap items-center gap-2">
            {canTrack && (
              <Button
                variant="outline"
                disabled={track.isPending}
                onClick={() => track.mutate(finding.id)}
              >
                {track.isPending ? (
                  <Spinner data-icon="inline-start" />
                ) : (
                  <WrenchIcon data-icon="inline-start" aria-hidden />
                )}
                {t.remediation.trackThisFix}
              </Button>
            )}
            <Link to={fixPath(finding.id)} className={buttonVariants({ variant: "secondary" })}>
              {t.remediation.openFix}
              <ArrowRightIcon data-icon="inline-end" aria-hidden />
            </Link>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
