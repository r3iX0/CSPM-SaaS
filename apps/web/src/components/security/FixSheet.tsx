import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRightIcon, RotateCcwIcon } from "lucide-react";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import type { FindingDetail, FindingProvenance } from "@/lib/types";
import { useT } from "@/i18n";
import { placeholderValues } from "@/lib/remediationFill";
import { useIsDemo } from "@/lib/useDemo";
import { resourceTypeLabel } from "@/lib/format";
import { ErrorState } from "@/components/common/states";
import { FixVerification } from "@/components/security/FixVerification";
import { RemediationPanel } from "@/components/security/RemediationPanel";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { StatusPill } from "@/components/security/StatusPill";
import { TrackFix } from "@/components/security/TrackFix";
import { VerificationPanel } from "@/components/security/VerificationPanel";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";

/**
 * A finding's fix, read in full and worked from the queue.
 *
 * The finding page answers what is wrong and why it matters; this answers how
 * to fix it and whether the fix took (DECISIONS.md §202). The fix is read in
 * full here and nowhere else: the steps and every form of them, marking the
 * work done, proving it with a rescan, and what the verification concluded.
 * Tracking is offered here too, under the title, and on the finding's card
 * beside the way here (§205).
 *
 * Keyed by finding, not by task, so a fix is read before anybody commits to
 * doing it -- an untracked finding opens here with "Track this fix" in its
 * header, and the demo, which refuses every write, still reads every fix.
 */
export function FixSheet({
  findingId,
  onClose,
}: {
  findingId: string | null;
  onClose: () => void;
}) {
  // The last finding shown, kept while the sheet animates out so its contents
  // do not vanish under the closing motion.
  const [shown, setShown] = useState(findingId);
  if (findingId !== null && findingId !== shown) setShown(findingId);

  return (
    <Sheet
      open={findingId !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <SheetContent className="gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-2xl">
        {shown !== null && <FixSheetBody key={shown} findingId={shown} />}
      </SheetContent>
    </Sheet>
  );
}

function FixSheetBody({ findingId }: { findingId: string }) {
  const t = useT();
  const queryClient = useQueryClient();
  const isDemo = useIsDemo();
  // The scan a "verify" queued, followed here until it concludes.
  const [verifyScanId, setVerifyScanId] = useState<string | null>(null);

  // Under the finding page's own key, which the queue's rows have already
  // filled (DECISIONS.md §29): opening a row's fix costs no request.
  const finding = useQuery({
    queryKey: ["finding", findingId],
    queryFn: () => api.get<FindingDetail>(`/api/v1/findings/${findingId}`).then((r) => r.data),
    staleTime: 60_000,
    retry: false,
  });
  const data = finding.data;

  // The provider id fills the command's placeholders; asked for only when
  // there is a command to fill, under the asset page's own key.
  const asset = useQuery({
    queryKey: ["asset", data?.resource?.id],
    queryFn: () =>
      api
        .get<{ provider_resource_id: string }>(`/api/v1/assets/${data?.resource?.id}`)
        .then((r) => r.data),
    enabled: Boolean(data?.resource && (data.remediation_spec?.cli?.length ?? 0) > 0),
    retry: false,
    staleTime: 60_000,
  });

  // Names the reading a verified rescan made; asked for only once one runs.
  const provenance = useQuery({
    queryKey: ["finding-provenance", findingId],
    queryFn: () =>
      api.get<FindingProvenance>(`/api/v1/findings/${findingId}/provenance`).then((r) => r.data),
    enabled: verifyScanId !== null,
    retry: false,
  });

  const rescan = useMutation({
    mutationFn: () =>
      api.post<{ message: string; scan_id: string }>(`/api/v1/findings/${findingId}/rescan`),
    // No toast: the verification below follows this scan and says what it
    // found, which a toast that vanished in four seconds could not.
    onSuccess: ({ data: queued }) => {
      setVerifyScanId(queued.scan_id);
      void queryClient.invalidateQueries({ queryKey: ["finding", findingId] });
      void queryClient.invalidateQueries({ queryKey: ["findings"] });
      void queryClient.invalidateQueries({ queryKey: ["remediation"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (err) =>
      toast.error("Could not start a rescan", {
        description: err instanceof ApiError ? err.message : "The API rejected the request.",
      }),
  });

  if (finding.isLoading) {
    return (
      <div className="flex flex-col gap-3 p-6">
        <SheetTitle className="sr-only">{t.common.loading}</SheetTitle>
        <Skeleton className="h-5 w-2/3" />
        <Skeleton className="h-4 w-1/3" />
        <Skeleton className="mt-4 h-64 w-full" />
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-6 pr-12">
        <SheetTitle className="sr-only">{t.remediation.fixFailed}</SheetTitle>
        <ErrorState
          title={t.remediation.fixFailed}
          detail="Cleave could not reach its own API, or the finding no longer exists."
          onRetry={() => void finding.refetch()}
        />
      </div>
    );
  }

  // Proving the fix is offered where the fix is, on an asset (§98, §187).
  const canVerify = data.status !== "RESOLVED" && Boolean(data.resource) && !isDemo;

  return (
    <>
      <SheetHeader className="gap-2 border-b px-6 pt-6 pr-12 pb-4">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge level={data.severity} />
          <StatusPill status={data.status} />
        </div>
        <SheetTitle className="text-heading font-semibold">{data.title}</SheetTitle>
        <SheetDescription>
          {data.resource
            ? `${data.resource.name} · ${resourceTypeLabel(data.resource.resource_type)}`
            : t.remediation.tenantWide}
        </SheetDescription>
        <Link
          to={`/findings/${data.id}`}
          className="inline-flex w-fit items-center gap-1 rounded-sm text-body text-foreground underline underline-offset-2 outline-none focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring"
        >
          {t.remediation.openFinding}
          <ArrowRightIcon className="size-3.5" aria-hidden />
        </Link>
        {/* The work heads the fix, not its foot: below the steps, the CLI and
            the Terraform it was a scroll nobody made (§205). */}
        <TrackFix
          findingId={data.id}
          status={data.status}
          effortMinutes={data.estimated_effort_minutes}
        />
      </SheetHeader>

      <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto p-6">
        {verifyScanId && (
          <FixVerification
            scanId={verifyScanId}
            findingId={data.id}
            findingStatus={data.status}
            resourceName={data.resource?.name ?? null}
            evidence={provenance.data?.evidence}
            retrying={rescan.isPending}
            onRetry={() => rescan.mutate()}
            onClose={() => setVerifyScanId(null)}
          />
        )}

        {/* Did it work -- only once somebody has claimed it did. */}
        {data.verification && <VerificationPanel verification={data.verification} />}

        <RemediationPanel
          remediation={data.remediation}
          spec={data.remediation_spec}
          effortMinutes={data.estimated_effort_minutes}
          findingId={data.id}
          fill={
            data.resource
              ? {
                  values: placeholderValues(data.resource, asset.data?.provider_resource_id),
                  resourceName: data.resource.name,
                }
              : undefined
          }
          footer={
            // The end of the fix, where the fix is: applying it and proving
            // it are one motion, not two places (§98).
            canVerify ? (
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-muted/30 px-4 py-3">
                <p className="text-sm text-foreground">Applied the fix?</p>
                <Button
                  size="sm"
                  onClick={() => rescan.mutate()}
                  disabled={rescan.isPending || verifyScanId !== null}
                >
                  {rescan.isPending ? (
                    <Spinner data-icon="inline-start" />
                  ) : (
                    <RotateCcwIcon data-icon="inline-start" aria-hidden />
                  )}
                  Verify it now
                </Button>
              </div>
            ) : undefined
          }
        />
      </div>
    </>
  );
}
