import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, ApiError } from "@/lib/api";
import type {
  NotificationKind,
  Webhook,
  WebhookCreated,
  WebhookFormat,
  WebhookTest,
} from "@/lib/types";
import { useT } from "@/i18n";
import { formatDateTime } from "@/lib/format";
import { CopyButton } from "@/components/common/CopyButton";
import { LiveStatus } from "@/components/common/LiveStatus";
import { SelectField } from "@/components/common/SelectField";
import { CardsSkeleton } from "@/components/common/states";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";

const FORMATS: WebhookFormat[] = ["SLACK", "TEAMS", "GENERIC"];
const KINDS: NotificationKind[] = ["REACHABLE_FINDING", "VERIFIED_FIX", "COVERAGE_DROP"];

/**
 * Where notifications go besides the bell: Slack, Teams, or a signed webhook
 * (DECISIONS.md §164). Owners and admins only, as the API allows.
 *
 * A stored URL is shown only in part, because a Slack or Teams URL is itself
 * the credential. A generic webhook's signing secret is shown once, on the
 * answer that created it.
 */
export function WebhooksSection({ organizationId }: { organizationId: string }) {
  const t = useT();
  const webhooks = useQuery({
    queryKey: ["webhooks", organizationId],
    queryFn: () => api.get<Webhook[]>("/api/v1/webhooks").then((r) => r.data),
  });

  return (
    <div className="flex flex-col gap-4">
      <div className="overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10">
        {webhooks.isLoading && <CardsSkeleton count={1} />}
        {webhooks.data && webhooks.data.length === 0 && (
          <p className="px-5 py-4 text-sm text-muted-foreground">{t.webhooks.empty}</p>
        )}
        {webhooks.data && webhooks.data.length > 0 && (
          <ul className="divide-y divide-border">
            {webhooks.data.map((webhook) => (
              <WebhookRow key={webhook.id} webhook={webhook} />
            ))}
          </ul>
        )}
      </div>
      <AddWebhook />
    </div>
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
    onSuccess: () => void refresh(),
    onError: failed,
  });
  const test = useMutation({
    mutationFn: () =>
      api.post<WebhookTest>(`/api/v1/webhooks/${webhook.id}/test`).then((r) => r.data),
    onSuccess: (result) => {
      setTested(result);
      void refresh();
    },
    onError: failed,
  });
  const remove = useMutation({
    mutationFn: () => api.del(`/api/v1/webhooks/${webhook.id}`),
    onSuccess: () => void refresh(),
    onError: failed,
  });

  const lastFailed =
    webhook.last_failure_at &&
    (!webhook.last_success_at || webhook.last_failure_at > webhook.last_success_at);
  const last = lastFailed
    ? t.webhooks.lastFailed(formatDateTime(webhook.last_failure_at), webhook.last_error ?? "")
    : webhook.last_success_at
      ? t.webhooks.lastOk(formatDateTime(webhook.last_success_at))
      : t.webhooks.never;

  return (
    <li className="flex flex-col gap-2 px-5 py-3.5">
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-foreground">{webhook.name}</p>
          <p className="truncate text-xs text-muted-foreground">
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
        {!confirming && (
          <Button
            variant="ghost"
            size="sm"
            aria-label={`${t.webhooks.remove} ${webhook.name}`}
            onClick={() => setConfirming(true)}
          >
            {t.webhooks.remove}
          </Button>
        )}
      </div>
      <p className="text-xs text-muted-foreground">
        {webhook.kinds.map((kind) => t.webhooks.kinds[kind]).join(" · ")}
      </p>
      <p className="text-xs text-muted-foreground">{last}</p>
      {tested && (
        <p className={tested.ok ? "text-xs text-foreground" : "text-xs text-critical"}>
          {tested.ok ? t.webhooks.testOk : t.webhooks.testFailed(tested.error ?? "")}
        </p>
      )}
      {confirming && (
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <span>{t.webhooks.removeConfirm(webhook.name)}</span>
          <Button
            size="sm"
            variant="outline"
            className="border-critical-border bg-critical-bg text-critical hover:bg-critical-bg hover:text-critical"
            disabled={remove.isPending}
            onClick={() => remove.mutate()}
          >
            {t.webhooks.remove}
          </Button>
          <Button size="sm" variant="ghost" onClick={() => setConfirming(false)}>
            {t.webhooks.cancel}
          </Button>
        </div>
      )}
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
    </li>
  );
}

function AddWebhook() {
  const t = useT();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [format, setFormat] = useState<WebhookFormat>("SLACK");
  const [kinds, setKinds] = useState<NotificationKind[]>(KINDS);
  const [secret, setSecret] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

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
      setError(null);
      setSecret(created.secret);
      setName("");
      setUrl("");
      void queryClient.invalidateQueries({ queryKey: ["webhooks"] });
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
    <div className="rounded-xl bg-card p-5 ring-1 ring-foreground/10">
      <h3 className="text-sm font-semibold text-foreground">{t.webhooks.add}</h3>
      <form
        className="mt-3 flex flex-col gap-3.5"
        onSubmit={(event) => {
          event.preventDefault();
          add.mutate();
        }}
      >
        <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_12rem]">
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
          <Field>
            <FieldLabel htmlFor="webhook-format">{t.webhooks.format}</FieldLabel>
            <SelectField
              id="webhook-format"
              size="default"
              value={format}
              ariaLabel={t.webhooks.format}
              onValueChange={(next) => {
                if (next) setFormat(next as WebhookFormat);
              }}
              options={FORMATS.map((value) => ({ value, label: t.webhooks.formats[value] }))}
            />
          </Field>
        </div>
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
          <legend className="mb-1 text-sm font-medium text-foreground">
            {t.webhooks.kindsLabel}
          </legend>
          {KINDS.map((kind) => (
            <label key={kind} className="flex items-center gap-2 text-sm text-foreground">
              <Checkbox
                checked={kinds.includes(kind)}
                onCheckedChange={(on) => toggleKind(kind, on === true)}
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

        <Button
          type="submit"
          className="self-start"
          disabled={add.isPending || !name.trim() || !url.trim() || kinds.length === 0}
        >
          {add.isPending ? t.webhooks.adding : t.webhooks.add}
        </Button>
      </form>

      <LiveStatus message={secret ? t.webhooks.secretReady : null} />
      {secret && (
        <div className="mt-4 flex flex-col gap-2.5 rounded-lg bg-muted/50 p-4">
          <p className="text-sm text-foreground">{t.webhooks.secretReady}</p>
          <code className="block overflow-x-auto rounded bg-background px-2.5 py-1.5 font-mono text-xs">
            {secret}
          </code>
          <div>
            <CopyButton text={secret} label={t.webhooks.copySecret} variant="outline" />
          </div>
        </div>
      )}
    </div>
  );
}
