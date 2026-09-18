import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BoxesIcon, SettingsIcon } from "lucide-react";

import { api, ApiError, auth } from "@/lib/api";
import type { CloudAccount, Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { OrganizationForm } from "@/components/settings/OrganizationForm";
import { ContextDeclarationForm } from "@/components/settings/ContextDeclaration";
import { SettingsSection } from "@/components/settings/SettingsSection";
import {
  CardsSkeleton,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/common/states";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";

/**
 * What a person has told CloudGuard.
 *
 * Everything else in the product is something CloudGuard observed. This is the
 * other half of the evidence: how the organization is named, and what its
 * subscriptions are actually for -- the second of which is the highest-leverage
 * input a customer has, because the risk engine multiplies every finding by it
 * and was otherwise guessing from tags and resource names.
 */
export function SettingsPage() {
  const t = useT();

  const organizations = useQuery({
    queryKey: ["organizations"],
    queryFn: () => api.get<Organization[]>("/api/v1/organizations").then((r) => r.data),
  });

  const accounts = useQuery({
    queryKey: ["cloud-accounts"],
    queryFn: () => api.get<CloudAccount[]>("/api/v1/cloud-accounts").then((r) => r.data),
  });

  // The one being acted in, which is what every other request on this page
  // targets. Falls back to the first membership for the common single-org
  // case, exactly as the API does when no header is sent.
  const current =
    organizations.data?.find((org) => org.id === auth.organizationId) ??
    organizations.data?.[0];

  if (organizations.isLoading) return <CardsSkeleton count={2} />;

  if (organizations.error) {
    return (
      <ErrorState
        title="Could not load your organization"
        detail="CloudGuard could not reach its own API."
        impact="Nothing about your environment has changed — this is a problem displaying it."
        onRetry={() => organizations.refetch()}
      />
    );
  }

  if (!current) return null;

  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        icon={SettingsIcon}
        title={t.settings.title}
        description={t.settings.intro}
      />

      <div>
        <SettingsSection title={t.settings.orgTitle} description={t.settings.orgHelp}>
          {/* Keyed, so switching organization remounts the form with the new
              values rather than leaving the previous one's name in the boxes. */}
          <OrganizationForm key={current.id} organization={current} />
        </SettingsSection>

        <SettingsSection
          title={t.settings.contextTitle}
          description={t.settings.contextHelp}
        >
          <div className="flex flex-col gap-3">
            {accounts.isLoading && <CardsSkeleton count={1} />}

            {accounts.data && accounts.data.length === 0 && (
              <EmptyState
                icon={BoxesIcon}
                title={t.settings.contextEmpty}
                detail={t.settings.contextEmptyDetail}
              />
            )}

            {accounts.data?.map((account) => (
              <ContextDeclarationForm key={account.id} account={account} />
            ))}

            {accounts.data && accounts.data.length > 0 && (
              <>
                {/* Two things the form cannot say for itself, and both change
                    what a reader expects to happen after they click Save. */}
                <p className="text-xs leading-relaxed text-muted-foreground">
                  {t.settings.notDeclaredHelp}
                </p>
                <p className="text-xs leading-relaxed text-muted-foreground">
                  {t.settings.appliesNext}
                </p>
              </>
            )}
          </div>
        </SettingsSection>

        <DangerZone organization={current} />
      </div>
    </div>
  );
}

/**
 * Deletion, gated on typing the name.
 *
 * Fourteen tables cascade from this row and there is no undo, so the
 * confirmation asks for something only a person who meant it would produce. A
 * second "are you sure" button would be a speed bump; this is a check.
 */
function DangerZone({ organization }: { organization: Organization }) {
  const t = useT();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);

  const owner = organization.role === "OWNER";

  const remove = useMutation({
    mutationFn: () => api.del(`/api/v1/organizations/${organization.id}`),
    onSuccess: () => {
      // The stored preference now names nothing, and every request carries it
      // as a header. Dropped before any refetch can send it.
      if (auth.organizationId === organization.id) auth.organizationId = null;
      queryClient.clear();
      navigate("/", { replace: true });
    },
    onError: (err) =>
      setError(err instanceof ApiError ? err.message : t.settings.deleteFailed),
  });

  return (
    <SettingsSection
      title={t.settings.dangerTitle}
      description={t.settings.dangerHelp}
      tone="danger"
    >
      <div className="rounded-xl border border-critical-border bg-card p-5 sm:p-6">
        {!owner ? (
          <p className="text-sm text-muted-foreground">{t.settings.dangerOwnerOnly}</p>
        ) : (
          <div className="flex max-w-md flex-col gap-3">
            <Field>
              <FieldLabel htmlFor="confirm-name">
                {t.settings.dangerConfirmLabel}
              </FieldLabel>
              <Input
                id="confirm-name"
                value={typed}
                placeholder={organization.name}
                onChange={(event) => setTyped(event.target.value)}
              />
            </Field>

            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button
              variant="destructive"
              className="self-start"
              disabled={typed !== organization.name || remove.isPending}
              onClick={() => remove.mutate()}
            >
              {remove.isPending ? t.settings.deleting : t.settings.delete}
            </Button>
          </div>
        )}
      </div>
    </SettingsSection>
  );
}
