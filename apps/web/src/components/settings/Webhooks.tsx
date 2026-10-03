import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { PlugIcon, PlusIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import type {
  NotificationKind,
  Webhook,
  WebhookCreated,
  WebhookFormat,
  WebhookTest,
} from "@/lib/types";
import { useT } from "@/i18n";
import { cn, formatDateTime } from "@/lib/format";
import { CopyButton } from "@/components/common/CopyButton";
import { LiveStatus } from "@/components/common/LiveStatus";
import { CardsSkeleton, EmptyState } from "@/components/common/states";
import { OptionCard } from "@/components/settings/OptionCard";
import { SettingsSection } from "@/components/settings/SettingsSection";
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
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field, FieldDescription, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { RadioGroup } from "@/components/ui/radio-group";
import { Switch } from "@/components/ui/switch";

const FORMATS: WebhookFormat[] = ["SLACK", "TEAMS", "GENERIC"];
const KINDS: NotificationKind[] = ["REACHABLE_FINDING", "VERIFIED_FIX", "COVERAGE_DROP"];

type Health = "ok" | "failing" | "never" | "paused";

/** Whether an integration is delivering, read from its last attempts. */
function healthOf(webhook: Webhook): Health {
  if (!webhook.enabled) return "paused";
  const failedLast =
    webhook.last_failure_at !== null &&
    (webhook.last_success_at === null || webhook.last_failure_at > webhook.last_success_at);
  if (failedLast) return "failing";
  return webhook.last_success_at ? "ok" : "never";
}

const HEALTH_STYLES: Record<Health, string> = {
  ok: "bg-ok-bg text-ok border-ok-border",
  failing: "bg-critical-bg text-critical border-critical-border",
  never: "bg-unknown-bg text-unknown border-unknown-border border-dashed",
  paused: "bg-unknown-bg text-unknown border-unknown-border border-dashed",
};

/**
 * Where notifications go besides the bell: Slack, Teams, or a signed webhook
 * (DECISIONS.md §164). Owners and admins only, as the API allows.
 *
 * Each integration says in one word whether it is delivering -- read from its
 * last success and failure, so a Slack channel that started refusing in the
 * night reads "Failing" before anyone opens it -- and adding one is a dialog
 * opened from the heading, where it used to be a form open under the list at
 * all times (§207).
 *
 * A stored URL is shown only in part, because a Slack or Teams URL is itself
 * the credential. A generic webhook's signing secret is shown once, on the
 * answer that created it, and the dialog holding it closes only once the
 * reader says it is stored.
 */
export function WebhooksSection({ organizationId }: { organizationId: string }) {
  const t = useT();
  const [adding, setAdding] = useState(false);
  const webhooks = useQuery({
    queryKey: ["webhooks", organizationId],
    queryFn: () => api.get<Webhook[]>("/api/v1/webhooks").then((r) => r.data),
  });

  const openButton = (
    <Button onClick={() => setAdding(true)}>
      <PlusIcon />
      {t.webhooks.open}
    </Button>
  );

  return (
    <SettingsSection
      id="integrations"
      title={t.webhooks.title}
      description={t.webhooks.help}
      actions={webhooks.data && webhooks.data.length > 0 ? openButton : undefined}
    >
      {webhooks.isLoading && <CardsSkeleton count={1} />}
      {webhooks.data && webhooks.data.length === 0 && (
        <EmptyState
          icon={PlugIcon}
          title={t.webhooks.emptyTitle}
          detail={t.webhooks.empty}
          action={openButton}
        />
      )}
      {webhooks.data && webhooks.data.length > 0 && (
        <ul className="divide-y divide-border overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10">
          {webhooks.data.map((webhook) => (
            <WebhookRow key={webhook.id} webhook={webhook} />
          ))}
        </ul>
      )}
      <AddWebhookDialog open={adding} onOpenChange={setAdding} />
    </SettingsSection>
  );
}

function WebhookRow({ webhook }: { webhook: Webhook }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tested, setTested] = useState<WebhookTest | null>(null);

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["webhooks"] });
  const failed = (err: unknown) =>
    setError(err instanceof ApiError ? err.message : t.webhooks.changeFailed);

  const toggle = useMutation({
    mutationFn: (enabled: boolean) => api.patch(`/api/v1/webhooks/${webhook.id}`, { enabled }),
    onSuccess: (_, enabled) => {
      setError(null);
      toast.success(enabled ? t.webhooks.resumed(webhook.name) : t.webhooks.paused(webhook.name));
      void refresh();
    },
    onError: failed,
  });
  const test = useMutation({
    mutationFn: () =>
      api.post<WebhookTest>(`/api/v1/webhooks/${webhook.id}/test`).then((r) => r.data),
    onSuccess: (result) => {
      setError(null);
      setTested(result);
      void refresh();
    },
    onError: failed,
  });
  const remove = useMutation({
    mutationFn: () => api.del(`/api/v1/webhooks/${webhook.id}`),
    onSuccess: () => {
      setConfirming(false);
      toast.success(t.webhooks.removed(webhook.name));
      void refresh();
    },
    onError: (err) => {
      setConfirming(false);
      failed(err);
    },
  });

  const health = healthOf(webhook);
  const last =
    health === "failing"
      ? t.webhooks.lastFailed(formatDateTime(webhook.last_failure_at), webhook.last_error ?? "")
      : webhook.last_success_at
        ? t.webhooks.lastOk(formatDateTime(webhook.last_success_at))
        : t.webhooks.never;
  const testLine = tested
    ? tested.ok
      ? t.webhooks.testOk
      : t.webhooks.testFailed(tested.error ?? "")
    : null;

  return (
    <li className="flex flex-col gap-2 px-5 py-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-0 flex-1">
          <p className="flex flex-wrap items-center gap-2">
            <span className="truncate text-body font-medium text-foreground">{webhook.name}</span>
            <span
              className={cn(
                "rounded-full border px-2 py-px text-caption font-medium",
                HEALTH_STYLES[health],
              )}
            >
              {t.webhooks.health[health]}
            </span>
          </p>
          <p className="truncate text-meta text-muted-foreground">
            {t.webhooks.formats[webhook.format]} · {webhook.url_preview}
          </p>
        </div>
        <Switch
          aria-label={t.webhooks.enabled(webhook.name)}
          checked={webhook.enabled}
          disabled={toggle.isPending}
          onCheckedChange={(on) => toggle.mutate(on)}
        />
        <Button variant="outline" size="sm" disabled={test.isPending} onClick={() => test.mutate()}>
          {test.isPending ? t.webhooks.testing : t.webhooks.test}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          aria-label={`${t.webhooks.remove} ${webhook.name}`}
          onClick={() => setConfirming(true)}
        >
          {t.webhooks.remove}
        </Button>
      </div>
      <p className="text-meta text-muted-foreground">
        {webhook.kinds.map((kind) => t.webhooks.kinds[kind]).join(" · ")}
      </p>
      <p className="text-meta text-muted-foreground">{last}</p>
      <LiveStatus message={testLine} />
      {tested && (
        <p className={tested.ok ? "text-meta text-ok" : "text-meta text-critical"}>{testLine}</p>
      )}
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <AlertDialog open={confirming} onOpenChange={setConfirming}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.webhooks.removeTitle(webhook.name)}</AlertDialogTitle>
            <AlertDialogDescription>{t.webhooks.removeDetail}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t.webhooks.cancel}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={remove.isPending}
              onClick={() => remove.mutate()}
            >
              {t.webhooks.remove}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </li>
  );
}

function AddWebhookDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [format, setFormat] = useState<WebhookFormat>("SLACK");
  const [kinds, setKinds] = useState<NotificationKind[]>(KINDS);
  const [secret, setSecret] = useState<string | null>(null);
  const [stored, setStored] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reset = () => {
    setName("");
    setUrl("");
    setFormat("SLACK");
    setKinds(KINDS);
    setSecret(null);
    setStored(false);
    setError(null);
  };

  const close = () => {
    reset();
    onOpenChange(false);
  };

  const add = useMutation({
    mutationFn: () =>
      api
        .post<WebhookCreated>("/api/v1/webhooks", {
          name: name.trim(),
          url: url.trim(),
          format,
          kinds,
        })
        .then((r) => r.data),
    onSuccess: (created) => {
      void queryClient.invalidateQueries({ queryKey: ["webhooks"] });
      toast.success(t.webhooks.added(created.name));
      // A secret is shown once, so the dialog stays to show it; without one
      // there is nothing left to say here.
      if (created.secret) {
        setError(null);
        setSecret(created.secret);
      } else {
        close();
      }
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : t.webhooks.addFailed),
  });

  function toggleKind(kind: NotificationKind, on: boolean) {
    setKinds((current) =>
      on
        ? KINDS.filter((k) => k === kind || current.includes(k))
        : current.filter((k) => k !== kind),
    );
  }

  return (
    <Dialog
      open={open}
      // Holding a secret not yet confirmed stored, the dialog stays open: it
      // is the only time the secret can be read.
      disablePointerDismissal={secret !== null}
      onOpenChange={(next) => {
        if (next) onOpenChange(true);
        else if (secret === null || stored) close();
      }}
    >
      <DialogContent
        className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-lg"
        showCloseButton={secret === null}
      >
        <DialogHeader>
          <DialogTitle>{t.webhooks.dialogTitle}</DialogTitle>
          <DialogDescription>{t.webhooks.help}</DialogDescription>
        </DialogHeader>

        <LiveStatus message={secret ? t.webhooks.secretReady : null} />
        {secret ? (
          <>
            <div className="flex flex-col gap-2.5 rounded-lg bg-muted/50 p-4">
              <p className="text-body text-foreground">{t.webhooks.secretReady}</p>
              <code className="block overflow-x-auto rounded bg-background px-2.5 py-1.5 font-mono text-meta">
                {secret}
              </code>
              <div>
                <CopyButton text={secret} label={t.webhooks.copySecret} variant="outline" />
              </div>
            </div>
            <Field orientation="horizontal">
              <Checkbox
                id="webhook-secret-stored"
                checked={stored}
                onCheckedChange={(on) => setStored(on)}
              />
              <FieldLabel htmlFor="webhook-secret-stored" className="font-normal">
                {t.webhooks.secretStored}
              </FieldLabel>
            </Field>
            <DialogFooter>
              <Button disabled={!stored} onClick={close}>
                {t.webhooks.done}
              </Button>
            </DialogFooter>
          </>
        ) : (
          <form
            className="flex flex-col gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              add.mutate();
            }}
          >
            <Field>
              <FieldLabel htmlFor="webhook-name">{t.webhooks.name}</FieldLabel>
              <Input
                id="webhook-name"
                required
                maxLength={120}
                value={name}
                onChange={(event) => setName(event.target.value)}
              />
            </Field>
            <FieldSet>
              <FieldLegend id="webhook-format-legend" variant="label">
                {t.webhooks.format}
              </FieldLegend>
              <RadioGroup
                aria-labelledby="webhook-format-legend"
                value={format}
                onValueChange={(next) => setFormat(next as WebhookFormat)}
                className="gap-1.5"
              >
                {FORMATS.map((value) => (
                  <OptionCard
                    key={value}
                    id={`webhook-format-${value}`}
                    value={value}
                    title={t.webhooks.formats[value]}
                    description={t.webhooks.formatHelp[value]}
                    checked={format === value}
                  />
                ))}
              </RadioGroup>
            </FieldSet>
            <Field>
              <FieldLabel htmlFor="webhook-url">{t.webhooks.url}</FieldLabel>
              <Input
                id="webhook-url"
                type="url"
                required
                autoComplete="off"
                placeholder="https://"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
              />
              <FieldDescription>{t.webhooks.urlHelp}</FieldDescription>
            </Field>
            <fieldset className="flex flex-col gap-2">
              <legend className="mb-1 text-body font-medium text-foreground">
                {t.webhooks.kindsLabel}
              </legend>
              {KINDS.map((kind) => (
                <label key={kind} className="flex items-center gap-2 text-body text-foreground">
                  <Checkbox
                    checked={kinds.includes(kind)}
                    onCheckedChange={(on) => toggleKind(kind, on)}
                  />
                  {t.webhooks.kinds[kind]}
                </label>
              ))}
            </fieldset>

            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <DialogFooter>
              <Button
                type="submit"
                disabled={add.isPending || !name.trim() || !url.trim() || kinds.length === 0}
              >
                {add.isPending ? t.webhooks.adding : t.webhooks.add}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
