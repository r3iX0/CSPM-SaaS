import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRightIcon } from "lucide-react";

import { api, auth, ApiError } from "@/lib/api";
import type { Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { cn } from "@/lib/format";
import { ShieldMark } from "@/components/Brand";
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
export function OnboardingPage() {
  const t = useT();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [industry, setIndustry] = useState("");
  const [country, setCountry] = useState("AL");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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
    <div className="flex min-h-screen flex-col bg-muted/40 px-6">
      <header className="flex items-center gap-2.5 py-6">
        <ShieldMark className="size-6 text-foreground" />
        <span className="text-sm font-semibold tracking-tight">{t.app.name}</span>
      </header>

      <main className="flex flex-1 items-center justify-center pb-24">
        <div className="w-full max-w-md">
          <ol className="grid grid-cols-2 gap-2" aria-label={t.onboarding.step}>
            {steps.map((label, index) => (
              <li
                key={label}
                aria-current={index === 0 ? "step" : undefined}
                className="flex flex-col gap-2"
              >
                <span
                  className={cn(
                    "h-1 rounded-full",
                    index === 0 ? "bg-foreground" : "bg-border",
                  )}
                />
                <span
                  className={cn(
                    "text-xs",
                    index === 0 ? "font-medium text-foreground" : "text-muted-foreground",
                  )}
                >
                  <span className="tabular-nums">{index + 1}.</span> {label}
                </span>
              </li>
            ))}
          </ol>

          <h1 className="mt-8 text-2xl font-semibold tracking-tight">
            {t.onboarding.createOrg}
          </h1>
          <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">
            {t.onboarding.intro}
          </p>

          <form
            onSubmit={submit}
            className="mt-6 rounded-xl border bg-background p-6 shadow-sm"
          >
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="org-name">{t.onboarding.orgName}</FieldLabel>
                <Input
                  id="org-name"
                  required
                  autoFocus
                  minLength={2}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Acme sh.p.k."
                  className="h-10"
                />
                <FieldDescription>{t.onboarding.orgNameHelp}</FieldDescription>
              </Field>

              <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_7rem]">
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
                    className="h-10"
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
                    className="h-10 font-mono uppercase"
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

              <Button type="submit" size="lg" disabled={busy} className="w-full">
                {busy && <Spinner data-icon="inline-start" />}
                {busy ? t.common.loading : t.onboarding.create}
                {!busy && <ArrowRightIcon data-icon="inline-end" aria-hidden />}
              </Button>
            </FieldGroup>
          </form>
        </div>
      </main>
    </div>
  );
}
