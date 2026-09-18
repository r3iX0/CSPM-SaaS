import { useId, useState, type ReactNode } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { AnimatePresence, motion } from "motion/react";
import { ArrowRightIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import type {
  CloudConnection,
  ConnectionScope,
  Provider,
  ProviderOption,
} from "@/lib/types";
import { useT } from "@/i18n";
import { needsScopeId, scopesFor } from "@/lib/connectionStage";
import { SCOPE_ICONS, SETUP_ICONS } from "@/lib/icons";
import { DURATION, EASE_OUT } from "@/lib/motion";
import { setupCopy } from "@/lib/setupCopy";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { ProviderMark } from "@/components/security/ProviderMark";
import { cn } from "@/lib/format";

/**
 * Step one: cloud, name, scope, go.
 *
 * Creates the connection and hands the id back to the wizard, which navigates
 * to the connection's own setup URL. From that point the flow is resumable --
 * everything after this step is recorded on the server, and the browser is free
 * to leave for the provider's console and come back.
 *
 * Creating no longer opens the consent page itself. It used to `window.open`
 * the moment the connection existed, which a popup blocker eats often enough to
 * matter, and which assumes the person filling this form is the administrator --
 * frequently they are not, and the next step is now the place that asks.
 *
 * Laid out as choices rather than prose. Every option used to carry two
 * paragraphs, so the three scopes read as a document to be studied before a
 * decision could be made; now each card says what it covers in a line, and the
 * permission it will take to *finish* is shown once, for the one selected,
 * directly beneath the choice it depends on.
 */
export function StepScope({
  provider,
  onProviderChange,
  onCreated,
}: {
  provider: Provider;
  onProviderChange: (provider: Provider) => void;
  onCreated: (id: string) => void;
}) {
  const t = useT();
  const copy = setupCopy(t, provider);
  const nameId = useId();
  const scopeIdField = useId();
  const [name, setName] = useState("");
  const [scopeType, setScopeType] = useState<ConnectionScope>(
    () => scopesFor(provider)[0],
  );
  const [scopeId, setScopeId] = useState("");
  const [error, setError] = useState<string | null>(null);

  // Which clouds this deployment can actually connect. Asked rather than
  // assumed: an installation with no Entra app registration cannot start a
  // consent flow, and one that has not verified its AWS connector against a
  // live account must not be offering AWS at all.
  const providers = useQuery({
    queryKey: ["cloud-providers"],
    queryFn: () =>
      api
        .get<ProviderOption[]>("/api/v1/cloud-connections/providers")
        .then((r) => r.data),
  });

  const options = providers.data ?? [];
  const chosen = options.find((option) => option.id === provider);

  /**
   * Switching cloud resets the scope, in the handler rather than in an effect.
   *
   * The scope union spans both clouds, so a scope left over from the other one
   * would post a value the provider has never heard of. Doing it here rather
   * than syncing after the fact means there is no render in which the form
   * holds a scope its own radio group does not offer.
   */
  function chooseProvider(next: Provider) {
    onProviderChange(next);
    setScopeType(scopesFor(next)[0]);
    setScopeId("");
  }

  const scopeIdRequired = needsScopeId(provider, scopeType);

  const create = useMutation({
    mutationFn: () =>
      api.post<CloudConnection>("/api/v1/cloud-connections", {
        name,
        provider,
        scope_type: scopeType,
        scope_id: scopeIdRequired ? scopeId : null,
      }),
    onSuccess: ({ data }) => onCreated(data.id),
    onError: (err) =>
      setError(err instanceof ApiError ? err.message : "Could not create the connection"),
  });

  // Each option carries what it will take to *finish*, not just what it covers.
  //
  // Azure RBAC inherits downward only, so being Owner of a subscription grants
  // nothing at the management group above it — and by default nobody, not even
  // a Global Administrator, holds rights at the tenant root. AWS has the same
  // shape of trap in a different place: an organization-wide connection needs
  // the stack in every member account, not only in the management one.
  // Choosing on coverage alone sends people to a console error at the last
  // step, after their administrator has already been involved.
  const azureScopes = [
    {
      value: "TENANT_ROOT" as ConnectionScope,
      label: "Entire tenant",
      detail: "Every subscription in this directory, including future ones.",
      requires:
        "Owner at the tenant root management group. Most directories must turn on "
        + "Entra ID → Properties → Access management for Azure resources first; "
        + "without it this step fails in Azure Portal.",
    },
    {
      value: "MANAGEMENT_GROUP" as ConnectionScope,
      label: "Management group",
      detail: "The subscriptions under one management group.",
      requires: "Owner or User Access Administrator on that management group.",
    },
    {
      value: "SUBSCRIPTION" as ConnectionScope,
      label: "Single subscription",
      detail: "One subscription only.",
      requires:
        "Owner or User Access Administrator on that subscription — usually the "
        + "easiest to complete.",
    },
  ];

  const awsScopes = [
    {
      value: "ORGANIZATION" as ConnectionScope,
      label: t.setup.aws.scopeOrganization,
      detail: t.setup.aws.scopeOrganizationDetail,
      requires: t.setup.aws.scopeOrganizationRequires,
    },
    {
      value: "ORGANIZATIONAL_UNIT" as ConnectionScope,
      label: t.setup.aws.scopeOrganizationalUnit,
      detail: t.setup.aws.scopeOrganizationalUnitDetail,
      requires: t.setup.aws.scopeOrganizationalUnitRequires,
    },
    {
      value: "ACCOUNT" as ConnectionScope,
      label: t.setup.aws.scopeAccount,
      detail: t.setup.aws.scopeAccountDetail,
      requires: t.setup.aws.scopeAccountRequires,
    },
  ];

  const scopes = provider === "aws" ? awsScopes : azureScopes;
  const selectedScope = scopes.find((scope) => scope.value === scopeType) ?? scopes[0];

  function scopeIdLabel(): string {
    if (provider === "aws") {
      if (scopeType === "ORGANIZATIONAL_UNIT") return t.setup.aws.organizationalUnitId;
      if (scopeType === "ACCOUNT") return t.setup.aws.accountId;
      return t.setup.aws.organizationId;
    }
    return scopeType === "MANAGEMENT_GROUP"
      ? t.connection.managementGroupId
      : t.connection.subscriptionId;
  }

  function scopeIdPlaceholder(): string {
    if (provider === "aws") {
      return scopeType === "ORGANIZATIONAL_UNIT" ? "ou-abcd-12345678" : "111122223333";
    }
    return scopeType === "MANAGEMENT_GROUP" ? "platform-mg" : "00000000-…";
  }

  const PermissionIcon = SETUP_ICONS.permission;
  const ReadOnlyIcon = SETUP_ICONS.readOnly;
  const needs = [
    { icon: SETUP_ICONS.approver, title: copy.needFirstTitle, detail: copy.needFirstDetail },
    { icon: SETUP_ICONS.permission, title: copy.needSecondTitle, detail: copy.needSecondDetail },
  ];

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setError(null);
        create.mutate();
      }}
    >
      <div className="flex flex-col gap-8 p-6 sm:p-8">
        <Section label={t.connection.cloud}>
          {providers.isLoading ? (
            <div className="grid gap-3 sm:grid-cols-2">
              <Skeleton className="h-[74px] rounded-xl" />
              <Skeleton className="h-[74px] rounded-xl" />
            </div>
          ) : (
            <RadioGroup
              value={provider}
              onValueChange={(value) => chooseProvider(value as Provider)}
              className="grid gap-3 sm:grid-cols-2"
              aria-label={t.connection.cloud}
            >
              {options.map((option) => (
                <ChoiceCard
                  key={option.id}
                  id={`provider-${option.id}`}
                  value={option.id}
                  disabled={!option.available}
                >
                  <span className="flex size-10 shrink-0 items-center justify-center rounded-lg border border-border bg-background">
                    <ProviderMark provider={option.id} className="size-5" />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="flex flex-wrap items-center gap-2 text-sm font-medium text-foreground">
                      {option.name}
                      {!option.available && (
                        <Badge variant="outline" className="font-normal text-muted-foreground">
                          {copy.providerUnavailable}
                        </Badge>
                      )}
                    </span>
                    {/* Unavailable is shown rather than hidden. A picker that
                        held an option back answers "does this support AWS?"
                        with nothing, and the reason is what tells an operator
                        what to do about it. */}
                    <span className="mt-0.5 block text-xs leading-relaxed text-muted-foreground">
                      {!option.available && option.unavailable_reason
                        ? option.unavailable_reason
                        : option.id === "aws"
                          ? copy.providerDetailAws
                          : copy.providerDetailAzure}
                    </span>
                  </span>
                </ChoiceCard>
              ))}
            </RadioGroup>
          )}
        </Section>

        <Field>
          <FieldLabel htmlFor={nameId}>{t.connection.connectionName}</FieldLabel>
          <Input
            id={nameId}
            required
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Acme production"
            className="h-10 max-w-md"
          />
          <FieldDescription>{copy.nameHelp}</FieldDescription>
        </Field>

        <Section label={t.connection.scope}>
          <RadioGroup
            value={scopeType}
            onValueChange={(value) => setScopeType(value as ConnectionScope)}
            className="grid gap-3 md:grid-cols-3"
            aria-label={t.connection.scope}
          >
            {scopes.map((scope, index) => {
              const Icon = SCOPE_ICONS[scope.value];
              const tag =
                index === 0
                  ? copy.scopeTagWidest
                  : index === scopes.length - 1
                    ? copy.scopeTagNarrowest
                    : null;
              return (
                <ChoiceCard
                  key={scope.value}
                  id={`scope-${scope.value}`}
                  value={scope.value}
                  stacked
                >
                  <span className="flex items-center gap-2">
                    <span className="flex size-8 items-center justify-center rounded-lg border border-border bg-background text-muted-foreground">
                      <Icon className="size-4" aria-hidden />
                    </span>
                    {tag && (
                      <Badge variant="secondary" className="font-normal">
                        {tag}
                      </Badge>
                    )}
                  </span>
                  <span className="mt-3 block text-sm font-medium text-foreground">
                    {scope.label}
                  </span>
                  <span className="mt-0.5 block text-xs leading-relaxed text-muted-foreground">
                    {scope.detail}
                  </span>
                </ChoiceCard>
              );
            })}
          </RadioGroup>

          {/* What it will take to *finish*, for the one scope chosen -- see the
              note above the list. Replaced rather than appended, so there is
              one requirement on screen and it is always the right one. */}
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={selectedScope.value}
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: DURATION.quick / 1000, ease: EASE_OUT }}
              className="mt-3 flex items-start gap-3 rounded-lg border border-border bg-muted/40 px-4 py-3"
            >
              <PermissionIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
              <p className="text-xs leading-relaxed text-muted-foreground">
                <span className="font-medium text-foreground">{copy.permissionNeeded}: </span>
                {selectedScope.requires}
              </p>
            </motion.div>
          </AnimatePresence>

          {scopeIdRequired && (
            <Field className="mt-5">
              <FieldLabel htmlFor={scopeIdField}>{scopeIdLabel()}</FieldLabel>
              <Input
                id={scopeIdField}
                required
                value={scopeId}
                onChange={(e) => setScopeId(e.target.value)}
                placeholder={scopeIdPlaceholder()}
                className="h-10 max-w-md font-mono text-[13px]"
              />
            </Field>
          )}
        </Section>

        <Section label={copy.beforeYouStart}>
          <ul className="divide-y divide-border rounded-xl border border-border">
            {needs.map(({ icon: Icon, title, detail }) => (
              <li key={title} className="flex items-start gap-3 px-4 py-3.5">
                <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
                  <Icon className="size-4" aria-hidden />
                </span>
                <span className="min-w-0">
                  <span className="block text-sm font-medium text-foreground">{title}</span>
                  <span className="mt-0.5 block text-xs leading-relaxed text-muted-foreground">
                    {detail}
                  </span>
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs leading-relaxed text-muted-foreground">{copy.noIdsNeeded}</p>
        </Section>

        {error && (
          <Alert variant="destructive">
            <AlertTitle>Could not create the connection</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
      </div>

      {/* Sticky, so the way forward is on screen from the first field rather
          than below four sections of reading. */}
      <div className="sticky bottom-0 flex flex-wrap items-center justify-between gap-3 rounded-b-xl border-t border-border bg-card/90 px-6 py-4 backdrop-blur supports-[backdrop-filter]:bg-card/75 sm:px-8">
        <p className="hidden items-center gap-2 text-xs text-muted-foreground sm:flex">
          <ReadOnlyIcon className="size-3.5 shrink-0" aria-hidden />
          {copy.footerPromise}
        </p>
        <Button
          type="submit"
          size="lg"
          className="w-full px-4 sm:w-auto"
          disabled={create.isPending || !chosen?.available}
        >
          {create.isPending && <Spinner data-icon="inline-start" />}
          {create.isPending ? "Creating…" : t.connection.create}
          {!create.isPending && <ArrowRightIcon data-icon="inline-end" aria-hidden />}
        </Button>
      </div>
    </form>
  );
}

function Section({ label, children }: { label: string; children: ReactNode }) {
  return (
    <section>
      <h3 className="mb-3 text-sm font-medium text-foreground">{label}</h3>
      {children}
    </section>
  );
}

/**
 * One option in a card-shaped radio group.
 *
 * The whole card is the label, so the target is the card and not a 16px dot;
 * the radio stays in the corner as the element that holds focus and state, so
 * keyboard and screen-reader behaviour are the radio group's own. Every card in
 * a group is the full width of its column -- the field primitive's label is
 * `w-fit`, which is why the options used to be three different widths.
 */
function ChoiceCard({
  id,
  value,
  disabled = false,
  stacked = false,
  children,
}: {
  id: string;
  value: string;
  disabled?: boolean;
  stacked?: boolean;
  children: ReactNode;
}) {
  return (
    <label
      htmlFor={id}
      className={cn(
        "relative flex w-full cursor-pointer rounded-xl border border-border bg-card p-4 text-left transition-[border-color,background-color,box-shadow]",
        stacked ? "flex-col items-start" : "items-center gap-3 pr-11",
        "hover:border-foreground/25 hover:bg-muted/30",
        "has-data-checked:border-foreground has-data-checked:bg-muted/40 has-data-checked:shadow-[0_0_0_1px_var(--foreground)]",
        "has-focus-visible:ring-3 has-focus-visible:ring-ring/50",
        disabled && "cursor-not-allowed opacity-60 hover:border-border hover:bg-card",
      )}
    >
      {children}
      <RadioGroupItem
        id={id}
        value={value}
        disabled={disabled}
        className="absolute top-4 right-4"
      />
    </label>
  );
}
