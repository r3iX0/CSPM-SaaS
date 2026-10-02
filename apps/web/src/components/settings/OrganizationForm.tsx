import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api, ApiError } from "@/lib/api";
import type { Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";

const EDITORS = ["OWNER", "ADMIN"];

/**
 * How this organization describes itself.
 *
 * A profile rather than a statement, and the API honours that distinction: it
 * writes only the fields the form sends, so saving a corrected name cannot
 * clear a country nobody touched. The context declarations below work the
 * opposite way, and the two are not interchangeable.
 *
 * State is seeded from the props once. Switching organization is handled by
 * the caller keying this component on the organization id, which remounts it
 * with fresh state -- rather than an effect that watches the props and writes
 * state back, which is the same reset a render later and one React warns about.
 */
export function OrganizationForm({ organization }: { organization: Organization }) {
  const t = useT();
  const queryClient = useQueryClient();
  const editable = EDITORS.includes(organization.role ?? "");

  const [name, setName] = useState(organization.name);
  const [industry, setIndustry] = useState(organization.industry ?? "");
  const [country, setCountry] = useState(organization.country ?? "");
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: () =>
      api.patch<Organization>("/api/v1/organizations", {
        name,
        // Empty is a cleared field, not an unset one: the customer emptied the
        // box, and null is how that is said.
        industry: industry.trim() || null,
        country: country.trim() ? country.trim().toUpperCase() : null,
      }),
    onSuccess: () => {
      setError(null);
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2000);
      queryClient.invalidateQueries({ queryKey: ["organizations"] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : t.settings.orgFailed),
  });

  const changed =
    name !== organization.name ||
    industry !== (organization.industry ?? "") ||
    country !== (organization.country ?? "");

  return (
    <div className="rounded-xl bg-card ring-1 ring-foreground/10">
      <form
        onSubmit={(event) => {
          event.preventDefault();
          save.mutate();
        }}
      >
        <div className="flex flex-col gap-3.5 p-5">
          {!editable && (
            <Alert>
              <AlertDescription>{t.settings.orgReadOnly}</AlertDescription>
            </Alert>
          )}

          <Field>
            <FieldLabel htmlFor="org-name">{t.settings.orgName}</FieldLabel>
            <Input
              id="org-name"
              value={name}
              minLength={2}
              required
              disabled={!editable}
              onChange={(event) => setName(event.target.value)}
              className="max-w-[380px]"
            />
          </Field>

          <div className="grid max-w-[380px] gap-x-3 gap-y-3.5 sm:grid-cols-[minmax(0,1fr)_7rem]">
            <Field>
              <FieldLabel htmlFor="org-industry">{t.settings.orgIndustry}</FieldLabel>
              <Input
                id="org-industry"
                value={industry}
                disabled={!editable}
                onChange={(event) => setIndustry(event.target.value)}
              />
            </Field>

            <Field>
              <FieldLabel htmlFor="org-country">{t.settings.orgCountry}</FieldLabel>
              <Input
                id="org-country"
                value={country}
                maxLength={2}
                disabled={!editable}
                className="font-mono uppercase"
                onChange={(event) => setCountry(event.target.value)}
              />
            </Field>
            <FieldDescription className="-mt-2 sm:col-span-2">
              {t.settings.orgCountryHelp}
            </FieldDescription>
          </div>

          <Field>
            <FieldLabel htmlFor="org-slug">{t.settings.orgSlug}</FieldLabel>
            {/* Shown but never editable, and the description says why rather
                than leaving a greyed-out box to imply a missing permission. */}
            <Input
              id="org-slug"
              value={organization.slug}
              readOnly
              disabled
              className="max-w-[380px] font-mono"
            />
            <FieldDescription className="max-w-[380px]">{t.settings.orgSlugHelp}</FieldDescription>
          </Field>

          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {editable && (
            <div className="flex items-center gap-3">
              <Button type="submit" disabled={!changed || save.isPending}>
                {save.isPending ? t.settings.saving : t.settings.save}
              </Button>
              {saved && !save.isPending && (
                <span className="text-xs text-ok">{t.settings.saved}</span>
              )}
            </div>
          )}
        </div>
      </form>
    </div>
  );
}
