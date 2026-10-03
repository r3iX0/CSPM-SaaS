import { useEffect, useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import type { CloudAccount, ContextDeclaration } from "@/lib/types";
import { useT } from "@/i18n";
import { formatDateTime } from "@/lib/format";
import {
  DECLARABLE_LEVELS,
  DECLARATIONS_KEY,
  NOT_DECLARED,
  levelLabel,
} from "@/lib/contextDeclarations";
import { LeaveGuard } from "@/components/common/LeaveGuard";
import { OptionCard } from "@/components/settings/OptionCard";
import { Alert, AlertDescription } from "@/components/ui/alert";
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
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { RadioGroup } from "@/components/ui/radio-group";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";

interface Draft {
  environment: string;
  criticality: string;
  sensitivity: string;
  note: string;
}

function draftOf(declaration: ContextDeclaration | null): Draft {
  return {
    environment: declaration?.environment ?? "",
    criticality: declaration?.criticality ?? NOT_DECLARED,
    sensitivity: declaration?.data_sensitivity ?? NOT_DECLARED,
    note: declaration?.note ?? "",
  };
}

function sameDraft(a: Draft, b: Draft): boolean {
  return (
    a.environment === b.environment &&
    a.criticality === b.criticality &&
    a.sensitivity === b.sensitivity &&
    a.note === b.note
  );
}

/**
 * One subscription's declaration, read and edited in a sheet (DECISIONS.md §207).
 *
 * Opened from the table on the Risk context page, with the subscription in the
 * URL (`?account=`), so a link can open it. Saved as a whole statement rather
 * than field by field, because that is what the API stores: a field left
 * unset is not "unknown" -- it is a claim withdrawn, and CloudGuard goes back
 * to working it out for itself.
 *
 * Each level is offered with what it means, because the risk engine multiplies
 * by it and "High" alone does not say what makes a subscription high. Closing
 * the sheet with an edit unsaved asks first.
 */
export function ContextSheet({
  account,
  declaration,
  writable,
  onClose,
}: {
  /** The subscription the sheet is open on; null closes it. */
  account: CloudAccount | null;
  declaration: ContextDeclaration | null;
  writable: boolean;
  onClose: () => void;
}) {
  const t = useT();
  // Whether the open form holds an edit, so Escape, the backdrop and Cancel
  // can all ask before discarding it. A ref, because only a close reads it.
  const dirty = useRef(false);
  const [confirmClose, setConfirmClose] = useState(false);
  const requestClose = () => {
    if (dirty.current) setConfirmClose(true);
    else onClose();
  };

  return (
    <>
      <Sheet
        open={account !== null}
        onOpenChange={(open) => {
          if (!open) requestClose();
        }}
      >
        {account && (
          // Keyed on what was declared too, so a save elsewhere reseeds the form.
          <SheetBody
            key={`${account.id}:${declaration?.declared_at ?? ""}`}
            account={account}
            declaration={declaration}
            writable={writable}
            onDirtyChange={(value) => {
              dirty.current = value;
            }}
            onCancel={requestClose}
            onDone={() => {
              dirty.current = false;
              onClose();
            }}
          />
        )}
      </Sheet>

      <AlertDialog open={confirmClose} onOpenChange={setConfirmClose}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.settings.leaveTitle}</AlertDialogTitle>
            <AlertDialogDescription>{t.settings.leaveDetail}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t.settings.leaveStay}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => {
                setConfirmClose(false);
                dirty.current = false;
                onClose();
              }}
            >
              {t.settings.discard}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

function SheetBody({
  account,
  declaration,
  writable,
  onDirtyChange,
  onCancel,
  onDone,
}: {
  account: CloudAccount;
  declaration: ContextDeclaration | null;
  writable: boolean;
  onDirtyChange: (dirty: boolean) => void;
  onCancel: () => void;
  /** After a save or a withdrawal: closes without asking. */
  onDone: () => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [initial] = useState(() => draftOf(declaration));
  const [draft, setDraft] = useState(initial);
  const [error, setError] = useState<string | null>(null);
  const dirty = writable && !sameDraft(draft, initial);
  useEffect(() => onDirtyChange(dirty), [dirty, onDirtyChange]);

  const settle = (saved: ContextDeclaration | null) => {
    queryClient.setQueryData<ContextDeclaration[]>(DECLARATIONS_KEY, (current) => [
      ...(current ?? []).filter((row) => row.cloud_account_id !== account.id),
      ...(saved ? [saved] : []),
    ]);
    // Asset pages read one subscription's declaration under this key.
    queryClient.setQueryData(["account-context", account.id], saved);
  };

  const save = useMutation({
    mutationFn: () =>
      api
        .put<ContextDeclaration | null>(`/api/v1/cloud-accounts/${account.id}/context`, {
          environment: draft.environment.trim() || null,
          criticality: draft.criticality === NOT_DECLARED ? null : draft.criticality,
          data_sensitivity: draft.sensitivity === NOT_DECLARED ? null : draft.sensitivity,
          note: draft.note.trim() || null,
        })
        .then((r) => r.data),
    onSuccess: (saved) => {
      settle(saved);
      // A statement that claims nothing withdraws the declaration, and the
      // toast says which of the two happened.
      toast.success(
        saved
          ? t.settings.contextSaved(account.account_name)
          : t.settings.contextCleared(account.account_name),
      );
      onDone();
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : t.settings.contextFailed),
  });

  const clear = useMutation({
    mutationFn: () => api.del(`/api/v1/cloud-accounts/${account.id}/context`),
    onSuccess: () => {
      settle(null);
      toast.success(t.settings.contextCleared(account.account_name));
      onDone();
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : t.settings.contextFailed),
  });

  const busy = save.isPending || clear.isPending;
  const set = (field: keyof Draft) => (value: string) =>
    setDraft((current) => ({ ...current, [field]: value }));

  return (
    <SheetContent className="w-full gap-0 data-[side=right]:sm:max-w-lg">
      <LeaveGuard dirty={dirty && !busy} />
      <SheetHeader className="border-b border-border pr-12">
        <SheetTitle>{account.account_name}</SheetTitle>
        <SheetDescription className="font-mono text-meta">
          {account.subscription_id}
        </SheetDescription>
      </SheetHeader>

      <form
        id="context-form"
        className="flex min-h-0 flex-1 flex-col gap-6 overflow-y-auto p-4"
        onSubmit={(event) => {
          event.preventDefault();
          if (writable && dirty) save.mutate();
        }}
      >
        {!declaration && (
          <p className="text-meta leading-relaxed text-muted-foreground">
            {t.settings.notDeclaredHelp}
          </p>
        )}

        <Field>
          <FieldLabel htmlFor="context-environment">{t.settings.environment}</FieldLabel>
          <Input
            id="context-environment"
            value={draft.environment}
            maxLength={64}
            readOnly={!writable}
            placeholder={t.settings.environmentPlaceholder}
            onChange={(event) => set("environment")(event.target.value)}
          />
          {writable && (
            <div className="flex flex-wrap gap-1.5">
              {t.settings.environmentSuggestions.map((name) => (
                <Button
                  key={name}
                  type="button"
                  size="xs"
                  variant="outline"
                  aria-pressed={draft.environment === name}
                  className="aria-pressed:border-foreground aria-pressed:bg-muted"
                  onClick={() => set("environment")(draft.environment === name ? "" : name)}
                >
                  {name}
                </Button>
              ))}
            </div>
          )}
        </Field>

        <LevelChoice
          id="context-criticality"
          legend={t.settings.criticality}
          help={t.settings.criticalityHelp}
          value={draft.criticality}
          disabled={!writable}
          onChange={set("criticality")}
        />

        <LevelChoice
          id="context-sensitivity"
          legend={t.settings.dataSensitivity}
          help={t.settings.sensitivityHelp}
          value={draft.sensitivity}
          disabled={!writable}
          onChange={set("sensitivity")}
        />

        <Field>
          <FieldLabel htmlFor="context-note">{t.settings.note}</FieldLabel>
          <Textarea
            id="context-note"
            value={draft.note}
            maxLength={2000}
            rows={3}
            readOnly={!writable}
            onChange={(event) => set("note")(event.target.value)}
          />
          <FieldDescription>{t.settings.noteHelp}</FieldDescription>
        </Field>

        {/* What the form cannot say for itself, and it changes what a reader
            expects to happen after they click Save. */}
        <p className="text-meta leading-relaxed text-muted-foreground">{t.settings.appliesNext}</p>

        {declaration && (
          <p className="text-meta text-muted-foreground">
            {t.settings.declaredBy} {formatDateTime(declaration.declared_at)}
          </p>
        )}

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
      </form>

      {writable && (
        <SheetFooter className="flex-row flex-wrap items-center border-t border-border">
          <Button type="submit" form="context-form" disabled={busy || !dirty}>
            {save.isPending ? t.settings.saving : t.settings.declare}
          </Button>
          {/* Only offered where there is something to withdraw. On an
              undeclared subscription it would be a button that does nothing
              and reads as though it might. */}
          {declaration && (
            <Button
              type="button"
              variant="ghost"
              className="text-muted-foreground"
              disabled={busy}
              onClick={() => clear.mutate()}
            >
              {clear.isPending ? t.settings.clearing : t.settings.clear}
            </Button>
          )}
          <Button type="button" variant="ghost" className="ml-auto" onClick={onCancel}>
            {t.settings.cancel}
          </Button>
        </SheetFooter>
      )}
    </SheetContent>
  );
}

/** One level, chosen from the four a person may declare or none, each with what it means. */
function LevelChoice({
  id,
  legend,
  help,
  value,
  disabled,
  onChange,
}: {
  id: string;
  legend: string;
  help: Record<string, string>;
  value: string;
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  const t = useT();
  const options = [
    {
      value: NOT_DECLARED,
      label: t.settings.notDeclared,
      help: t.settings.notDeclaredOptionHelp,
    },
    ...DECLARABLE_LEVELS.map((level) => ({
      value: level,
      label: levelLabel(level),
      help: help[level] ?? "",
    })),
  ];

  return (
    <FieldSet>
      <FieldLegend id={`${id}-legend`} variant="label">
        {legend}
      </FieldLegend>
      <RadioGroup
        aria-labelledby={`${id}-legend`}
        value={value}
        disabled={disabled}
        onValueChange={(next) => onChange(String(next))}
        className="gap-1.5"
      >
        {options.map((option) => (
          <OptionCard
            key={option.value}
            id={`${id}-${option.value}`}
            value={option.value}
            title={option.label}
            description={option.help}
            checked={value === option.value}
          />
        ))}
      </RadioGroup>
    </FieldSet>
  );
}
