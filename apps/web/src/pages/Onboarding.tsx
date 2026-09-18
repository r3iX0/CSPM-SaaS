import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRightIcon } from "lucide-react";

import { api, auth, ApiError } from "@/lib/api";
import type { Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { cn } from "@/lib/format";
import { ShieldMark } from "@/components/Brand";
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

          {/* The other way in: see the product before setting anything up.
              Below the form rather than beside it, because creating an
              organization is still the path, and the demo is the detour for
              somebody not ready to take it. */}
          <div className="mt-6 flex items-center gap-3 text-xs text-muted-foreground">
            <span className="h-px flex-1 bg-border" />
            {t.auth.orDivider}
            <span className="h-px flex-1 bg-border" />
          </div>
          <button
            type="button"
            onClick={() => joinDemo.mutate()}
            disabled={joinDemo.isPending}
            className="group mt-4 flex w-full items-center gap-3 rounded-xl border border-border bg-background p-4 text-left transition-colors hover:border-foreground/25 disabled:opacity-60"
          >
            <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-medium-bg text-medium">
              <DEMO_ICON className="size-4" aria-hidden />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block text-sm font-medium text-foreground">
                {joinDemo.isPending ? t.demo.opening : t.demo.explore}
              </span>
              <span className="mt-0.5 block text-xs leading-relaxed text-muted-foreground">
                {joinDemo.isError ? t.demo.unavailable : t.demo.exploreDetail}
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
