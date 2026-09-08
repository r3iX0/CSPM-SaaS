import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { Revocation, RevocationCheck } from "@/lib/types";
import { useT } from "@/i18n";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { CodeBlock } from "@/components/common/CodeBlock";

/**
 * Removing a connection, and the revocation it does not perform.
 *
 * CloudGuard cannot revoke its own access: the grant lives in the customer's
 * tenant and nothing here holds a credential that could withdraw it. So the
 * commands are generated for the customer to run, and "check" asks Azure
 * whether they did -- an answer, not an assurance.
 *
 * **An alert dialog rather than a panel inside the row.** The confirmation is long --
 * three commands, an explanation of why CloudGuard cannot run them, and a probe
 * -- and expanded in place it pushed the rest of the connection off screen,
 * so a reader deciding whether to delete an environment was scrolling a page
 * whose other half had moved. It is also the one irreversible action in the
 * product, which is the case an *alert* dialog exists for rather than a plain
 * one: it announces itself as `alertdialog`, it cannot be dismissed by a click
 * on the backdrop, and "Keep it" is where focus starts. A stray click outside a
 * regular dialog is a harmless miss; here it would be the same gesture that
 * deletes an environment.
 *
 * Controlled by the caller rather than owning its own trigger. The row already
 * holds the button, and a dialog that opened itself would leave the row unable
 * to say whether the deletion it is running was confirmed here.
 */
export function RemoveConfirm({
  connectionId,
  open,
  busy,
  onOpenChange,
  onConfirm,
}: {
  connectionId: string;
  open: boolean;
  busy: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: () => void;
}) {
  const t = useT();
  const [checked, setChecked] = useState<RevocationCheck | null>(null);

  const revocation = useQuery({
    queryKey: ["connection-revocation", connectionId],
    queryFn: () =>
      api
        .get<Revocation>(`/api/v1/cloud-connections/${connectionId}/revocation`)
        .then((r) => r.data),
    // Only while the dialog is open. The component now stays mounted with the
    // row, and a connections page listing six environments would otherwise ask
    // six times for commands nobody has asked to see.
    enabled: open,
  });

  const check = useMutation({
    mutationFn: () =>
      api.post<RevocationCheck>(
        `/api/v1/cloud-connections/${connectionId}/check-revoked`,
      ),
    onSuccess: ({ data }) => setChecked(data),
  });

  const steps = revocation.data?.steps ?? [];

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent className="sm:max-w-lg">
        <AlertDialogHeader>
          <AlertDialogTitle className="text-critical">
            {t.connection.removeTitle}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {t.connection.removeDetail}
          </AlertDialogDescription>
        </AlertDialogHeader>

        {/* Revocation sits inside the removal confirmation on purpose. It is the
            only moment the customer is thinking about ending this, and once the
            connection is deleted the principal id and scope needed to write
            these commands are gone with it.

            Bounded and scrolled rather than allowed to grow: three commands on
            a laptop already reach past the fold, and a dialog taller than the
            viewport hides its own footer -- which here is the button that
            confirms an irreversible deletion. */}
        {steps.length > 0 && (
          <div className="flex max-h-[50vh] flex-col gap-3 overflow-y-auto rounded-lg border p-3">
            <div className="flex flex-col gap-1">
              <p className="text-sm font-medium text-foreground">
                {t.connection.revokeTitle}
              </p>
              <p className="text-xs leading-relaxed text-muted-foreground">
                {t.connection.revokeIntro}
              </p>
            </div>

            <ol className="flex flex-col gap-3">
              {steps.map((step) => (
                <li key={step.title} className="flex flex-col gap-1">
                  <p className="text-xs font-medium text-foreground">{step.title}</p>
                  <p className="text-xs leading-relaxed text-muted-foreground">
                    {step.detail}
                  </p>
                  <CodeBlock
                    code={step.command}
                    className="px-2.5 py-1.5"
                    label={`Copy: ${step.title}`}
                  />
                </li>
              ))}
            </ol>

            {revocation.data && (
              <p className="text-xs leading-relaxed text-muted-foreground">
                {revocation.data.why_manual}
              </p>
            )}

            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant="secondary"
                size="sm"
                onClick={() => check.mutate()}
                disabled={check.isPending}
              >
                {check.isPending ? t.connection.checking : t.connection.checkRevoked}
              </Button>
              {checked && (
                <span
                  className={
                    checked.revoked
                      ? "text-xs font-medium text-ok"
                      : "text-xs font-medium text-high"
                  }
                >
                  {checked.revoked ? t.connection.accessGone : t.connection.stillHasAccess}
                </span>
              )}
            </div>
            {checked && (
              <p className="text-xs leading-relaxed text-muted-foreground">
                {checked.detail}
              </p>
            )}
          </div>
        )}

        <AlertDialogFooter>
          {/* "Keep it" is the close, so Escape does the same thing the button
              does -- and the destructive action is never the one a stray
              keypress reaches. */}
          <AlertDialogCancel variant="secondary">
            {t.connection.keep}
          </AlertDialogCancel>
          <AlertDialogAction
            variant="destructive"
            onClick={onConfirm}
            disabled={busy}
          >
            {busy ? t.connection.removing : t.connection.remove}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
