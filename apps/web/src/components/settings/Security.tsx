import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  confirmSecondFactor,
  listSecondFactors,
  removeSecondFactor,
  SECOND_FACTORS_KEY,
  startSecondFactor,
  type PendingSecondFactor,
  type SecondFactor,
} from "@/lib/supabase";
import { formatDate } from "@/lib/format";
import { useT } from "@/i18n";
import { CODE_LENGTH, CodeField } from "@/components/auth/CodeField";
import { CopyButton } from "@/components/common/CopyButton";
import { SettingsSection } from "@/components/settings/SettingsSection";
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
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";

/**
 * The reader's own two-factor authentication (DECISIONS.md §217).
 *
 * An authenticator app is added and removed with Supabase directly, as signing
 * in is: the API never sees the key or a code, and only learns that a factor
 * exists when it refuses a session that skipped it. One app per account, which
 * is all the sign-in prompt asks for.
 */
export function SecuritySection() {
  const t = useT();
  const factors = useQuery({ queryKey: SECOND_FACTORS_KEY, queryFn: listSecondFactors });
  const factor = factors.data?.[0];

  return (
    <SettingsSection id="security" title={t.secondFactor.title} description={t.secondFactor.help}>
      <div className="rounded-xl bg-card p-5 ring-1 ring-foreground/10">
        {factors.isPending ? (
          <Skeleton className="h-12 w-full" />
        ) : factors.error ? (
          <p role="alert" className="text-body text-muted-foreground">
            {t.secondFactor.failed}
          </p>
        ) : factor ? (
          <FactorOn factor={factor} />
        ) : (
          <FactorOff />
        )}
      </div>
    </SettingsSection>
  );
}

function FactorOn({ factor }: { factor: SecondFactor }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);

  const remove = useMutation({
    mutationFn: () => removeSecondFactor(factor.id),
    onSuccess: () => {
      setConfirming(false);
      toast.success(t.secondFactor.turnedOff);
      void queryClient.invalidateQueries({ queryKey: SECOND_FACTORS_KEY });
    },
    onError: () => toast.error(t.secondFactor.failed),
  });

  return (
    <div className="flex flex-wrap items-center justify-between gap-4">
      <div className="min-w-0">
        <p className="flex items-center gap-2 text-body font-medium text-foreground">
          {t.secondFactor.app}
          <Badge variant="secondary">{t.secondFactor.on}</Badge>
        </p>
        <p className="mt-1 text-meta text-muted-foreground">
          {t.secondFactor.addedOn(formatDate(factor.createdAt))}
        </p>
      </div>
      <Button variant="outline" size="sm" onClick={() => setConfirming(true)}>
        {t.secondFactor.remove}
      </Button>

      <AlertDialog open={confirming} onOpenChange={setConfirming}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.secondFactor.removeTitle}</AlertDialogTitle>
            <AlertDialogDescription>{t.secondFactor.removeDetail}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t.secondFactor.cancel}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={remove.isPending}
              onClick={() => remove.mutate()}
            >
              {remove.isPending ? t.secondFactor.removing : t.secondFactor.remove}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function FactorOff() {
  const t = useT();
  const [pending, setPending] = useState<PendingSecondFactor | null>(null);

  const start = useMutation({
    mutationFn: startSecondFactor,
    onSuccess: setPending,
    onError: () => toast.error(t.secondFactor.failed),
  });

  if (pending) return <Enrolment pending={pending} onDone={() => setPending(null)} />;

  return (
    <div className="flex flex-wrap items-center justify-between gap-4">
      <div className="min-w-0">
        <p className="flex items-center gap-2 text-body font-medium text-foreground">
          {t.secondFactor.app}
          <Badge variant="outline">{t.secondFactor.off}</Badge>
        </p>
        <p className="mt-1 text-meta text-muted-foreground">{t.secondFactor.offDetail}</p>
      </div>
      <Button size="sm" disabled={start.isPending} onClick={() => start.mutate()}>
        {t.secondFactor.setUp}
      </Button>
    </div>
  );
}

/**
 * Scan, then prove the scan worked with the first code. Until that code is
 * checked the app is not a factor: closing here leaves sign-in as it was, and
 * Cancel removes the half-added app rather than leaving it on the account.
 */
function Enrolment({ pending, onDone }: { pending: PendingSecondFactor; onDone: () => void }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [code, setCode] = useState("");

  const confirm = useMutation({
    mutationFn: () => confirmSecondFactor(pending.id, code),
    onSuccess: () => {
      toast.success(t.secondFactor.turnedOn);
      void queryClient.invalidateQueries({ queryKey: SECOND_FACTORS_KEY });
      onDone();
    },
    onError: () => setCode(""),
  });

  // Dropped from the account if it can be; if not, the next set-up clears it.
  const cancel = useMutation({
    mutationFn: () => removeSecondFactor(pending.id),
    onSettled: onDone,
  });

  function submit(event: React.FormEvent) {
    event.preventDefault();
    if (confirm.isPending || code.length !== CODE_LENGTH) return;
    confirm.mutate();
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-5">
      <div>
        <p className="text-body text-foreground">{t.secondFactor.scanStep}</p>
        {/* White behind the code in either theme: a scanner reads dark on light. */}
        <img
          src={pending.qrCode}
          alt={t.secondFactor.qrAlt}
          className="mt-3 size-44 rounded-lg bg-white p-2"
        />
        <p className="mt-3 text-meta text-muted-foreground">{t.secondFactor.secretLabel}</p>
        <div className="mt-1.5 flex flex-wrap items-center gap-2">
          <code className="rounded-md bg-muted px-2 py-1 font-mono text-meta break-all text-foreground">
            {pending.secret}
          </code>
          <CopyButton text={pending.secret} label={t.secondFactor.copySecret} variant="outline" />
        </div>
      </div>

      <div className="flex flex-col gap-2">
        <CodeField
          id="second-factor-setup-code"
          label={t.secondFactor.confirmStep}
          value={code}
          onChange={setCode}
        />
        {confirm.error && (
          <p role="alert" className="text-meta text-critical">
            {t.secondFactor.wrongCode}
          </p>
        )}
      </div>

      <div className="flex gap-2">
        <Button type="submit" size="sm" disabled={confirm.isPending}>
          {confirm.isPending ? t.secondFactor.turningOn : t.secondFactor.turnOn}
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          disabled={cancel.isPending}
          onClick={() => cancel.mutate()}
        >
          {t.secondFactor.cancel}
        </Button>
      </div>
    </form>
  );
}
