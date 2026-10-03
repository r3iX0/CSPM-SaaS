import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import type { Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { countryName } from "@/lib/countries";
import { CopyButton } from "@/components/common/CopyButton";
import { LeaveGuard } from "@/components/common/LeaveGuard";
import { CountryPicker } from "@/components/settings/CountryPicker";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";

const EDITORS = ["OWNER", "ADMIN"];

/**
 * Suggestions, not a closed list: an organization that is a "Port authority"
 * types it. A `datalist` offers these while keeping the field free text,
 * which is what the API stores.
 */
const INDUSTRIES = [
  "Banking",
  "Insurance",
  "Financial services",
  "Healthcare",
  "Pharmaceuticals",
  "Retail",
  "Technology",
  "Telecommunications",
  "Energy",
  "Manufacturing",
  "Transport and logistics",
  "Government",
  "Education",
  "Media",
  "Professional services",
  "Non-profit",
];

interface Profile {
  name: string;
  industry: string;
  country: string;
}

function profileOf(organization: Organization): Profile {
  return {
    name: organization.name,
    industry: organization.industry ?? "",
    country: organization.country ?? "",
  };
}

/**
 * How this organization describes itself.
 *
 * A profile rather than a statement, and the API honours that distinction: it
 * writes only the fields the form sends, so saving a corrected name cannot
 * clear a country nobody touched. The context declarations work the opposite
 * way, and the two are not interchangeable.
 *
 * Edits are held until Save, with Discard beside it and a guard on leaving
 * (DECISIONS.md §207): the form says when it holds something unsaved rather
 * than leaving the reader to remember. A reader who cannot edit reads the
 * profile as text -- disabled boxes are hard to read and say nothing about why.
 *
 * State is seeded from the props once. Switching organization is handled by
 * the caller keying this component on the organization id, which remounts it
 * with fresh state.
 */
export function OrganizationForm({ organization }: { organization: Organization }) {
  const t = useT();
  const editable = EDITORS.includes(organization.role ?? "") && !organization.is_demo;

  if (!editable) {
    return (
      <div className="flex flex-col gap-4 rounded-xl bg-card p-5 ring-1 ring-foreground/10">
        <Alert>
          <AlertDescription>{t.settings.orgReadOnly}</AlertDescription>
        </Alert>
        <dl className="grid gap-x-6 gap-y-3 text-body sm:grid-cols-[10rem_minmax(0,1fr)]">
          <dt className="text-muted-foreground">{t.settings.orgName}</dt>
          <dd className="text-foreground">{organization.name}</dd>
          <dt className="text-muted-foreground">{t.settings.orgIndustry}</dt>
          <dd className="text-foreground">{organization.industry ?? "—"}</dd>
          <dt className="text-muted-foreground">{t.settings.orgCountry}</dt>
          <dd className="text-foreground">
            {organization.country ? countryName(organization.country) : "—"}
          </dd>
          <dt className="text-muted-foreground">{t.settings.orgSlug}</dt>
          <dd className="font-mono text-foreground">{organization.slug}</dd>
        </dl>
      </div>
    );
  }

  return <ProfileForm organization={organization} />;
}

function ProfileForm({ organization }: { organization: Organization }) {
  const t = useT();
  const queryClient = useQueryClient();

  // What the server last held, which "unsaved" is measured against. Moved on
  // a save rather than waiting for the refetch, so the bar does not flash
  // "unsaved" over values that were just saved.
  const [saved, setSaved] = useState<Profile>(() => profileOf(organization));
  const [draft, setDraft] = useState<Profile>(saved);
  const [error, setError] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (profile: Profile) =>
      api.patch<Organization>("/api/v1/organizations", {
        name: profile.name,
        // Empty is a cleared field, not an unset one: the customer emptied the
        // box, and null is how that is said.
        industry: profile.industry.trim() || null,
        country: profile.country.trim() ? profile.country.trim().toUpperCase() : null,
      }),
    onSuccess: (_, profile) => {
      setError(null);
      setSaved(profile);
      toast.success(t.settings.orgSaved);
      void queryClient.invalidateQueries({ queryKey: ["organizations"] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : t.settings.orgFailed),
  });

  const dirty =
    draft.name !== saved.name ||
    draft.industry !== saved.industry ||
    draft.country !== saved.country;

  const set = (field: keyof Profile) => (value: string) =>
    setDraft((current) => ({ ...current, [field]: value }));

  return (
    <form
      className="rounded-xl bg-card ring-1 ring-foreground/10"
      onSubmit={(event) => {
        event.preventDefault();
        if (dirty) save.mutate(draft);
      }}
    >
      <LeaveGuard dirty={dirty && !save.isPending} />
      <div className="flex flex-col gap-4 p-5">
        <Field>
          <FieldLabel htmlFor="org-name">{t.settings.orgName}</FieldLabel>
          <Input
            id="org-name"
            value={draft.name}
            minLength={2}
            required
            onChange={(event) => set("name")(event.target.value)}
            className="max-w-sm"
          />
        </Field>

        <div className="grid max-w-xl gap-4 sm:grid-cols-2">
          <Field>
            <FieldLabel htmlFor="org-industry">{t.settings.orgIndustry}</FieldLabel>
            <Input
              id="org-industry"
              list="org-industries"
              value={draft.industry}
              placeholder={t.settings.orgIndustryPlaceholder}
              autoComplete="off"
              onChange={(event) => set("industry")(event.target.value)}
            />
            <datalist id="org-industries">
              {INDUSTRIES.map((industry) => (
                <option key={industry} value={industry} />
              ))}
            </datalist>
          </Field>

          <Field>
            <FieldLabel htmlFor="org-country">{t.settings.orgCountry}</FieldLabel>
            <CountryPicker id="org-country" value={draft.country} onChange={set("country")} />
            <FieldDescription>{t.settings.orgCountryHelp}</FieldDescription>
          </Field>
        </div>

        <Field>
          <FieldLabel htmlFor="org-slug">{t.settings.orgSlug}</FieldLabel>
          {/* Read-only rather than disabled: it can be selected and copied, and
              reads at full contrast. The description says why it is fixed. */}
          <div className="flex max-w-sm items-center gap-2">
            <Input id="org-slug" value={organization.slug} readOnly className="font-mono" />
            <CopyButton text={organization.slug} label={t.settings.copySlug} variant="outline" />
          </div>
          <FieldDescription className="max-w-sm">{t.settings.orgSlugHelp}</FieldDescription>
        </Field>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
      </div>

      <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border px-5 py-3">
        {dirty && (
          <p className="mr-auto text-meta text-muted-foreground" role="status">
            {t.settings.unsaved}
          </p>
        )}
        {dirty && (
          <Button
            type="button"
            variant="ghost"
            disabled={save.isPending}
            onClick={() => {
              setDraft(saved);
              setError(null);
            }}
          >
            {t.settings.discard}
          </Button>
        )}
        <Button type="submit" disabled={!dirty || save.isPending}>
          {save.isPending ? t.settings.saving : t.settings.save}
        </Button>
      </div>
    </form>
  );
}
