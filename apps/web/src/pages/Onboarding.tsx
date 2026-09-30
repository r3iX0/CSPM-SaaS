import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRightIcon } from "lucide-react";

import { api, auth, ApiError } from "@/lib/api";
import type { Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { cn } from "@/lib/format";
import { Wordmark } from "@/components/Brand";
import { DEMO_ICON } from "@/lib/icons";
import { useJoinDemo } from "@/lib/useDemo";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { PAGE_TITLE_CLASS } from "@/components/common/states";

/**
 * Step one of two: the organization every other row in the database hangs off.
 *
 * The form is a `FieldGroup` rather than stacked divs so the label, the control
 * and its description are one accessible unit -- which matters more here than
 * anywhere else in the product, because this is the first screen a new customer
 * ever fills in.
 *
 * It says what comes after it. "Step 1 / 2" on its own announces a second step
 * without naming it; the two labelled segments make the promise concrete --
 * a name now, a cloud next -- and the second segment is the connection wizard
 * the button lands on.
 */
const FIELD_CLASS = "h-10 rounded-[9px] px-[13px] text-body";

export function OnboardingPage() {
  const t = useT();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [industry, setIndustry] = useState("");
  const [country, setCountry] = useState("AL");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const joinDemo = useJoinDemo();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { data } = await api.post<Organization>("/api/v1/organizations", {
        name,
        industry: industry || null,
        country: country || null,
      });
      auth.organizationId = data.id;
      navigate("/connections", { replace: true });
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Could not create organization",
      );
      setBusy(false);
    }
  }

  const steps = [t.onboarding.stepOrganization, t.onboarding.stepCloud];

  return (
    <div className="flex min-h-screen flex-col bg-[color-mix(in_oklab,var(--muted)_35%,var(--background))] px-6">
      <header className="flex items-center gap-2.5 py-6">
        <Wordmark markClassName="size-5" labelClassName="text-title" />
      </header>

      <main className="flex flex-1 items-center justify-center pb-20">
        <div className="w-full max-w-[440px]">
          <ol className="grid grid-cols-2 gap-2.5" aria-label={t.onboarding.step}>
            {steps.map((label, index) => (
              <li
                key={label}
                aria-current={index === 0 ? "step" : undefined}
                className="flex flex-col gap-2"
              >
                <span
                  className={cn(
                    "h-[3px] rounded-full",
                    index === 0 ? "bg-primary" : "bg-border",
                  )}
                />
                <span
                  className={cn(
                    "text-caption",
                    index === 0 ? "font-medium text-foreground" : "text-muted-foreground",
                  )}
                >
                  <span className="tabular-nums">{index + 1}.</span> {label}
                </span>
              </li>
            ))}
          </ol>

          <h1 className={cn("mt-7", PAGE_TITLE_CLASS)}>
            {t.onboarding.createOrg}
          </h1>
          <p className="mt-2 text-body leading-[1.7] text-muted-foreground">
            {t.onboarding.intro}
          </p>

          <form
            onSubmit={submit}
            className="mt-6 rounded-xl border border-border bg-card p-6"
          >
            <FieldGroup className="gap-4">
              <Field>
                <FieldLabel htmlFor="org-name">{t.onboarding.orgName}</FieldLabel>
                <Input
                  id="org-name"
                  required
                  // The page is this form, outside the shell with nothing before
                  // it to read, and the field is its first.
                  // eslint-disable-next-line jsx-a11y/no-autofocus
                  autoFocus
                  minLength={2}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Acme sh.p.k."
                  className={FIELD_CLASS}
                />
                <FieldDescription>{t.onboarding.orgNameHelp}</FieldDescription>
              </Field>

              <div className="grid gap-x-3 gap-y-4 sm:grid-cols-[minmax(0,1fr)_96px]">
                <Field>
                  <FieldLabel htmlFor="org-industry">
                    {t.onboarding.industry}
                    <span className="font-normal text-muted-foreground">
                      {" "}
                      · {t.onboarding.optional}
                    </span>
                  </FieldLabel>
                  <Input
                    id="org-industry"
                    value={industry}
                    onChange={(e) => setIndustry(e.target.value)}
                    placeholder="Financial services"
                    className={FIELD_CLASS}
                  />
                </Field>

                <Field>
                  <FieldLabel htmlFor="org-country">{t.onboarding.country}</FieldLabel>
                  <Input
                    id="org-country"
                    maxLength={2}
                    value={country}
                    onChange={(e) => setCountry(e.target.value.toUpperCase())}
                    placeholder="AL"
                    className={cn(FIELD_CLASS, "font-mono uppercase")}
                    aria-describedby="org-country-help"
                  />
                </Field>
                <FieldDescription id="org-country-help" className="-mt-2 sm:col-span-2">
                  {t.onboarding.countryHelp}
                </FieldDescription>
              </div>

              {error && (
                <Alert variant="destructive">
                  <AlertTitle>Could not create your organization</AlertTitle>
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <Button
                type="submit"
                disabled={busy}
                className="h-[42px] w-full rounded-[9px] text-body"
              >
                {busy && <Spinner data-icon="inline-start" />}
                {busy ? t.common.loading : t.onboarding.create}
              </Button>
            </FieldGroup>
          </form>

          {/* The other way in: see the product before setting anything up.
              Below the form rather than beside it, because creating an
              organization is still the path, and the demo is the detour for
              somebody not ready to take it. */}
          <div className="mt-[22px] flex items-center gap-3 text-caption text-muted-foreground" aria-hidden>
            <span className="h-px flex-1 bg-border" />
            {t.auth.orDivider}
            <span className="h-px flex-1 bg-border" />
          </div>
          <button
            type="button"
            // Unavailable rather than disabled while it opens, so the button
            // keeps focus (DECISIONS.md section 165).
            onClick={() => {
              if (!joinDemo.isPending) joinDemo.mutate();
            }}
            aria-disabled={joinDemo.isPending || undefined}
            className="group mt-4 flex w-full items-center gap-3 rounded-xl border border-border bg-card p-4 text-left transition-colors hover:bg-muted/60 focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring aria-disabled:opacity-60"
          >
            <span className="flex size-[34px] shrink-0 items-center justify-center rounded-[9px] bg-primary-soft text-primary">
              <DEMO_ICON className="size-4" aria-hidden />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block text-body font-medium text-foreground">
                {joinDemo.isPending ? t.demo.opening : t.onboarding.demoTitle}
              </span>
              <span className="mt-0.5 block text-caption leading-[1.6] text-muted-foreground">
                {joinDemo.isError ? t.demo.unavailable : t.onboarding.demoDetail}
              </span>
            </span>
            <ArrowRightIcon
              className="size-4 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-0.5"
              aria-hidden
            />
          </button>
        </div>
      </main>
    </div>
  );
}
