import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { ScanDetail } from "@/lib/types";
import { useT } from "@/i18n";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";

/**
 * Deleting a scan is two different acts, so it asks which.
 *
 * The record is an execution log. The findings it raised are statements about
 * the environment, which is why `findings.scan_id` is ON DELETE SET NULL --
 * history can be pruned without discarding what was found. Purging is for a run
 * whose results the user considers wrong, and never touches resolved findings:
 * each is the evidence that a fix was verified.
 *
 * Both options are spelled out with their consequence rather than offered as
 * "delete" and a checkbox. This is the one destructive action in the product
 * that can remove security findings, and the count of what would go is read
 * from the API rather than described in the abstract.
 *
 * **An alert dialog rather than a panel under the scan.** In place it competed
 * with the card it was deleting -- a red block whose buttons sat a few pixels
 * from the ordinary ones -- and on a page listing twenty runs it moved
 * everything below it. As an `alertdialog` it takes focus, it cannot be
 * dismissed by a click on the backdrop, and the two consequences are the only
 * things on screen while the choice is being made.
 */
export function DeleteScanConfirm({
  scanId,
  open,
  busy,
  onConfirm,
  onCancel,
}: {
  scanId: string;
  open: boolean;
  busy: boolean;
  onConfirm: (purge: boolean) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const detail = useQuery({
    queryKey: ["scan-detail", scanId],
    queryFn: () => api.get<ScanDetail>(`/api/v1/scans/${scanId}/detail`).then((r) => r.data),
    // Only while the choice is being made: the count of purgeable findings is
    // the one fact this dialog adds, and a scans page listing twenty runs must
    // not ask for it twenty times.
    enabled: open,
  });
  const purgeable = detail.data?.purgeable_finding_count ?? 0;

  return (
    <AlertDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) onCancel();
      }}
    >
      <AlertDialogContent className="sm:max-w-lg">
        <AlertDialogHeader>
          <AlertDialogTitle className="text-critical">
            {t.scans.deleteTitle}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {t.scans.deleteIntro}
          </AlertDialogDescription>
        </AlertDialogHeader>

        {/* The two acts, each under its own consequence. Neither is
            `AlertDialogAction`: that slot is for one confirmation, and this
            dialog's whole point is that there are two different deletions and
            the reader has to choose which one they mean. */}
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1">
            <Button
              variant="secondary"
              className="self-start"
              onClick={() => onConfirm(false)}
              disabled={busy}
            >
              {t.scans.deleteRecordOnly}
            </Button>
            <p className="text-xs leading-relaxed text-muted-foreground">
              {t.scans.deleteRecordOnlyDetail}
            </p>
          </div>
          <div className="flex flex-col gap-1">
            <Button
              variant="destructive"
              className="self-start"
              onClick={() => onConfirm(true)}
              disabled={busy}
            >
              {t.scans.deleteWithFindings}
              {purgeable > 0 && ` (${purgeable})`}
            </Button>
            <p className="text-xs leading-relaxed text-muted-foreground">
              {t.scans.deleteWithFindingsDetail}
            </p>
          </div>
        </div>

        <AlertDialogFooter>
          <AlertDialogCancel variant="ghost" disabled={busy}>
            {t.findings.cancel}
          </AlertDialogCancel>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
