import { useState } from "react";
import { Link, Navigate } from "react-router-dom";
import {
  saveGuestWithEmail,
  saveGuestWithProvider,
  sendPasswordReset,
  signInWithGoogle,
  signInWithMicrosoft,
  signInWithPassword,
  signUpWithPassword,
} from "@/lib/supabase";
import { useAuthToken, useIsGuest } from "@/lib/useAuth";
import { useT } from "@/i18n";
import { Wordmark } from "@/components/Brand";
import { ScoreTile } from "@/components/security/ScoreTile";
import { PAGE_TITLE_CLASS } from "@/components/common/states";
import { cn } from "@/lib/utils";

/**
 * Sign-in and sign-up, via Supabase.
 *
 * CloudGuard's own backend never authenticates anyone — Supabase does, and the
 * API only ever *verifies* the JWT that comes back
 * (app/core/security.py::decode_token). Four routes in, one token out:
 *
 *   Microsoft (Entra ID)  the front door for an Azure-first product — the same
 *                         directory account that will later grant consent
 *   Google                for teams whose work accounts are Google Workspace
 *   Email + password      familiar, and works where corporate mail scanners
 *                         eat one-time links before the user sees them
 *   Password reset        because a password flow without recovery is a trap
 *
 * A password typed here goes from the browser straight to Supabase over TLS.
 * It is never sent to, logged by, or stored by CloudGuard's API.
 *
 * A guest -- somebody exploring the demo without an account -- meets the same page
 * as "keep this as an account": Microsoft and Google are linked to the guest
 * rather than signed in to, and an email is confirmed on the guest, so the user
 * stays the same one (DECISIONS.md §219). Signing in to an existing account
 * instead simply replaces the guest session.
 *
 * The left panel is not decoration. This is the screen where someone decides
 * whether to hand a product read access to their whole cloud estate, so it
 * states plainly what the access is and what it is not.
 */

/** Which form is showing. `sent` states are tracked separately, below. */
type Mode = "signin" | "signup" | "reset";

/** A "we emailed you something" confirmation, and which something it was. */
interface Sent {
  kind: "confirm" | "reset";
  email: string;
}

const MIN_PASSWORD_LENGTH = 8;

export function SignInPage() {
  const t = useT();
  const token = useAuthToken();
  const guest = useIsGuest();
  const [mode, setMode] = useState<Mode>(guest ? "signup" : "signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState<Sent | null>(null);

  // A guest keeping their session confirms an address first; Supabase sets a
  // password only once it is confirmed, on the page the link opens.
  const saving = guest && mode === "signup";
  const needsPassword = mode === "signin" || (mode === "signup" && !saving);

  function switchTo(next: Mode) {
    setMode(next);
    setError(null);
    // The password does not carry across a mode change: a value typed for
    // sign-in should not silently become the password of a new account.
    setPassword("");
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    // The button says it is unavailable rather than being disabled, so it
    // keeps focus while the request runs; this is what refuses the press.
    if (busy) return;

    if (needsPassword && password.length < MIN_PASSWORD_LENGTH) {
      setError(t.auth.passwordTooShort);
      return;
    }

    setBusy(true);
    setError(null);
    try {
      if (saving) {
        await saveGuestWithEmail(email);
        setSent({ kind: "confirm", email });
      } else if (mode === "signin") {
        await signInWithPassword(email, password);
        // No navigation here. Supabase's onAuthStateChange writes the token,
        // useAuthToken re-renders this component, and the redirect below fires.
      } else if (mode === "signup") {
        const { needsEmailConfirmation } = await signUpWithPassword(email, password);
        if (needsEmailConfirmation) setSent({ kind: "confirm", email });
      } else {
        await sendPasswordReset(email);
        setSent({ kind: "reset", email });
      }
    } catch (err) {
      setError(authErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function withProvider(signIn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      // Navigates away to the provider and does not come back here, so `busy`
      // is deliberately left set — the buttons should stay disabled for the
      // moment the browser spends unloading the page.
      await signIn();
    } catch (err) {
      setError(authErrorMessage(err));
      setBusy(false);
    }
  }

  // Returning from a confirmation, Microsoft or Google lands here first.
  // Once the session is parsed, move on rather than showing a sign-in form to
  // someone who is already signed in.
  if (token && !guest) return <Navigate to="/" replace />;

  return (
    <div className="flex min-h-screen bg-background">
      <BrandPanel />

      <main className="flex flex-1 items-center justify-center px-6 py-12">
        <div className="w-full max-w-[360px]">
          {/* The mark repeats on mobile, where the left panel is hidden. */}
          <div className="mb-10 flex items-center gap-2.5 lg:hidden">
            <Wordmark />
          </div>

          {sent ? (
            <SentNotice
              sent={sent}
              onUseAnother={() => {
                setSent(null);
                setPassword("");
              }}
            />
          ) : (
            <>
              <h1 className={PAGE_TITLE_CLASS}>
                {saving
                  ? t.auth.saveGuestTitle
                  : mode === "signup"
                    ? t.auth.signUp
                    : mode === "reset"
                      ? t.auth.resetTitle
                      : t.auth.signIn}
              </h1>
              <p className="mt-2 text-body leading-[1.65] text-muted-foreground">
                {saving
                  ? t.auth.saveGuestIntro
                  : mode === "signup"
                    ? "Start with your work email. You can connect Azure once you're in."
                    : mode === "reset"
                      ? t.auth.resetIntro
                      : "Use your Microsoft or Google account, or the email and password you signed up with."}
              </p>

              {/* Microsoft first: for an Azure-first product it is the account
                  most users already have, and the one they will consent with. */}
              {mode !== "reset" && (
                <>
                  <div className="mt-7 flex flex-col gap-3">
                    <ProviderButton
                      onClick={() =>
                        void withProvider(
                          saving ? () => saveGuestWithProvider("azure") : signInWithMicrosoft,
                        )
                      }
                      disabled={busy}
                      mark={<MicrosoftMark />}
                      label={t.auth.continueWithMicrosoft}
                    />
                    <ProviderButton
                      onClick={() =>
                        void withProvider(
                          saving ? () => saveGuestWithProvider("google") : signInWithGoogle,
                        )
                      }
                      disabled={busy}
                      mark={<GoogleMark />}
                      label={t.auth.continueWithGoogle}
                    />
                  </div>
                  <Divider label={t.auth.orDivider} />
                </>
              )}

              <form onSubmit={submit} className={mode === "reset" ? "mt-7" : "mt-6"}>
                <label htmlFor="email" className="block text-body font-medium text-foreground">
                  {t.auth.email}
                </label>
                <input
                  id="email"
                  type="email"
                  required
                  // The page is this form, outside the shell with nothing before
                  // it to read, and the field is its first.
                  // eslint-disable-next-line jsx-a11y/no-autofocus -- the page is this form, and the field is its first.
                  autoFocus
                  autoComplete="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  className={FIELD_CLASS}
                />

                {needsPassword && (
                  <PasswordField
                    id="password"
                    label={t.auth.password}
                    value={password}
                    onChange={setPassword}
                    // Telling the browser's password manager which of the two
                    // this is, so it offers to fill rather than to save on
                    // sign-in and the reverse on sign-up.
                    autoComplete={mode === "signup" ? "new-password" : "current-password"}
                    hint={mode === "signup" ? t.auth.passwordTooShort : undefined}
                    trailing={
                      mode === "signin" ? (
                        <button
                          type="button"
                          onClick={() => switchTo("reset")}
                          className="rounded-sm text-caption text-muted-foreground underline underline-offset-[3px] transition hover:text-foreground focus-ring"
                        >
                          {t.auth.forgotPassword}
                        </button>
                      ) : undefined
                    }
                  />
                )}

                {error && (
                  <p
                    role="alert"
                    className="mt-3 rounded-lg border border-critical-border bg-critical-bg px-3 py-2 text-sm text-critical"
                  >
                    {error}
                  </p>
                )}

                <button
                  type="submit"
                  aria-disabled={busy || undefined}
                  className="mt-6 flex h-10 w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 text-body font-medium text-primary-foreground transition-colors hover:bg-primary/90 focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring aria-disabled:cursor-not-allowed aria-disabled:bg-muted aria-disabled:text-muted-foreground"
                >
                  {busy && (
                    <span
                      aria-hidden
                      className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current/30 border-t-current"
                    />
                  )}
                  {saving
                    ? busy
                      ? t.auth.sending
                      : t.auth.sendConfirmation
                    : submitLabel(mode, busy, t)}
                </button>
              </form>

              <AlternateRoutes mode={mode} onSwitch={switchTo} />

              {guest && (
                <p className="mt-3 text-center text-body">
                  <Link
                    to="/"
                    className="rounded-sm text-muted-foreground underline underline-offset-[3px] transition-colors hover:text-foreground focus-ring"
                  >
                    {t.auth.backToDemo}
                  </Link>
                </p>
              )}

              {/* What each route on screen does and does not hand over. Reset
                  gets none: there is no password typed here yet and no
                  provider button on screen to qualify. */}
              {mode !== "reset" && (
                <div className="mt-6 space-y-2 border-t border-border pt-5 text-caption leading-[1.7] text-muted-foreground">
                  <p>{t.auth.providerHint}</p>
                  <p>{t.auth.passwordNotice}</p>
                </div>
              )}
            </>
          )}
        </div>
      </main>
    </div>
  );
}

const FIELD_CLASS =
  "mt-2 h-10 w-full rounded-lg border border-input bg-background px-3 text-body text-foreground transition-colors placeholder:text-muted-foreground hover:border-ring focus-visible:border-ring focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-ring/50";

function submitLabel(mode: Mode, busy: boolean, t: ReturnType<typeof useT>): string {
  if (busy) {
    if (mode === "signup") return t.auth.creatingAccount;
    if (mode === "signin") return t.auth.signingIn;
    return t.auth.sending;
  }
  if (mode === "signup") return t.auth.signUp;
  if (mode === "signin") return t.auth.signIn;
  return t.auth.sendReset;
}

/**
 * Turns Supabase's auth errors into something a person can act on.
 *
 * Deliberately does not distinguish "no such user" from "wrong password":
 * that difference is an account-enumeration oracle, and Supabase does not
 * offer it either.
 */
function authErrorMessage(err: unknown): string {
  const raw = err instanceof Error ? err.message : "";
  const text = raw.toLowerCase();

  if (text.includes("invalid login credentials")) {
    return "That email and password don't match an account.";
  }
  if (text.includes("already registered") || text.includes("already exists")) {
    return "An account with that email already exists — sign in instead.";
  }
  if (text.includes("email not confirmed")) {
    return "Confirm your email first. Check for the link we sent when you signed up.";
  }
  if (text.includes("password should be") || text.includes("password is too")) {
    return "That password is too short or too easily guessed. Try a longer one.";
  }
  if (text.includes("rate limit") || text.includes("too many")) {
    return "Too many attempts. Wait a minute and try again.";
  }
  // Supabase's answer when a provider button is pressed before the provider
  // is switched on in the project (docs/DEPLOYMENT.md §1).
  if (text.includes("provider is not enabled")) {
    return "That sign-in option is not switched on for this deployment yet.";
  }
  if (text.includes("not configured")) {
    return "This deployment has no Supabase project configured, so sign-in is unavailable.";
  }
  return raw || "Something went wrong. Try again.";
}

function Divider({ label }: { label: string }) {
  return (
    <div className="mt-6 flex items-center gap-3" aria-hidden="true">
      <span className="h-px flex-1 bg-border" />
      <span className="text-caption text-muted-foreground">{label}</span>
      <span className="h-px flex-1 bg-border" />
    </div>
  );
}

function ProviderButton({
  onClick,
  disabled,
  mark,
  label,
}: {
  onClick: () => void;
  disabled: boolean;
  mark: React.ReactNode;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="flex h-10 w-full items-center justify-center gap-2.5 rounded-lg border border-border bg-card px-4 text-body font-medium text-foreground transition-colors hover:bg-muted/60 focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring disabled:cursor-not-allowed disabled:text-muted-foreground"
    >
      {mark}
      {label}
    </button>
  );
}

/** Microsoft's four-square mark, at its published brand colors. */
function MicrosoftMark() {
  return (
    <svg viewBox="0 0 16 16" className="size-[15px] shrink-0" aria-hidden="true">
      <path fill="#f25022" d="M0 0h7.6v7.6H0z" />
      <path fill="#7fba00" d="M8.4 0H16v7.6H8.4z" />
      <path fill="#00a4ef" d="M0 8.4h7.6V16H0z" />
      <path fill="#ffb900" d="M8.4 8.4H16V16H8.4z" />
    </svg>
  );
}

/** Google's "G" mark, at its published brand colors. */
function GoogleMark() {
  return (
    <svg viewBox="0 0 48 48" className="size-[15px] shrink-0" aria-hidden="true">
      <path
        fill="#ea4335"
        d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
      />
      <path
        fill="#4285f4"
        d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"
      />
      <path
        fill="#fbbc05"
        d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"
      />
      <path
        fill="#34a853"
        d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"
      />
    </svg>
  );
}

function PasswordField({
  id,
  label,
  value,
  onChange,
  autoComplete,
  hint,
  trailing,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  autoComplete: string;
  hint?: string;
  trailing?: React.ReactNode;
}) {
  const t = useT();
  const [visible, setVisible] = useState(false);

  return (
    <div className="mt-4">
      <div className="flex items-baseline justify-between gap-3">
        <label htmlFor={id} className="block text-body font-medium text-foreground">
          {label}
        </label>
        {trailing}
      </div>
      <div className="relative">
        <input
          id={id}
          type={visible ? "text" : "password"}
          required
          autoComplete={autoComplete}
          minLength={MIN_PASSWORD_LENGTH}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          aria-describedby={hint ? `${id}-hint` : undefined}
          className={`${FIELD_CLASS} pr-11`}
        />
        <button
          type="button"
          onClick={() => setVisible((v) => !v)}
          aria-label={visible ? t.auth.hidePassword : t.auth.showPassword}
          className="absolute inset-y-0 right-0 mt-2 flex items-center rounded-r-lg px-3 text-muted-foreground transition hover:text-foreground focus-ring-inset"
        >
          <EyeIcon crossed={visible} />
        </button>
      </div>
      {hint && (
        <p id={`${id}-hint`} className="mt-1.5 text-xs text-muted-foreground">
          {hint}
        </p>
      )}
    </div>
  );
}

function EyeIcon({ crossed }: { crossed: boolean }) {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4" aria-hidden="true">
      <g
        fill="none"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" />
        <circle cx="12" cy="12" r="2.8" />
        {crossed && <path d="m4 20 16-16" />}
      </g>
    </svg>
  );
}

/** Links to the sign-in routes that are not the one currently showing. */
function AlternateRoutes({ mode, onSwitch }: { mode: Mode; onSwitch: (mode: Mode) => void }) {
  const t = useT();

  if (mode === "reset") {
    return (
      <div className="mt-6 text-center text-body">
        <TextLink onClick={() => onSwitch("signin")}>{t.auth.backToSignIn}</TextLink>
      </div>
    );
  }

  return (
    <div className="mt-6 text-center text-body">
      <p className="text-muted-foreground">
        {mode === "signup" ? t.auth.haveAccount : t.auth.noAccount}{" "}
        <TextLink onClick={() => onSwitch(mode === "signup" ? "signin" : "signup")}>
          {mode === "signup" ? t.auth.signIn : t.auth.createOne}
        </TextLink>
      </p>
    </div>
  );
}

function TextLink({ onClick, children }: { onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="rounded-sm text-muted-foreground underline underline-offset-[3px] transition-colors hover:text-foreground focus-ring"
    >
      {children}
    </button>
  );
}

function BrandPanel() {
  return (
    // A muted wash of the page's own background, in either theme: the panel
    // belongs to the product rather than standing in front of it.
    <aside className="hidden w-[46%] max-w-[660px] shrink-0 flex-col justify-between border-r border-border bg-[color-mix(in_oklab,var(--muted)_45%,var(--background))] p-12 text-foreground lg:flex">
      <Wordmark className="gap-2.5" markClassName="size-[22px]" labelClassName="text-heading" />

      <div>
        <h2 className="max-w-[15ch] text-4xl leading-[1.12] font-semibold tracking-[-0.03em]">
          Cut the one link that matters.
        </h2>
        <p className="mt-4 max-w-[46ch] text-sm leading-[1.7] text-muted-foreground">
          Cleave reads your Azure environment, ranks what it finds by what it would cost this
          business, and proves the fix worked on the next scan.
        </p>

        <ProductPreview />

        <ul className="mt-7 flex flex-col gap-3">
          <Assurance>Read-only. Cleave never changes your resources.</Assurance>
          <Assurance>No Azure credential to hand over — consent, not secrets.</Assurance>
          <Assurance>Your data is isolated at the database level, not just in code.</Assurance>
        </ul>
      </div>

      <p className="text-caption text-muted-foreground">
        Azure-first cloud security posture management
      </p>
    </aside>
  );
}

/**
 * What the product looks like, before anyone has signed in.
 *
 * A sign-in page is the last screen somebody sees before deciding the product
 * is worth their credentials, and three sentences of promise are weaker than
 * one glance at the thing itself. Drawn from the product's own primitives --
 * the severity tokens, the tinted score tile -- so it cannot drift into a
 * marketing picture of a product that does not exist. Hidden from assistive
 * technology: it is an illustration with example values, and read aloud it
 * would sound like somebody's real findings.
 */
function ProductPreview() {
  const rows = [
    {
      score: 98,
      level: "CRITICAL",
      title: "Internet → vm-jumpbox → storage-prod-01",
      tag: "Attack path",
    },
    {
      score: 94,
      level: "CRITICAL",
      title: "RDP reachable from the internet on prod-vm-01",
      tag: "Internet-facing",
    },
  ];

  return (
    <div
      aria-hidden="true"
      className="mt-8 max-w-[440px] overflow-hidden rounded-xl border border-border bg-card"
    >
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <div className="flex items-baseline gap-2">
          <span className="text-stat font-semibold tracking-[-0.02em] text-medium tabular-nums">
            71
          </span>
          <span className="text-caption text-muted-foreground">/ 100 security score</span>
        </div>
        <span className="rounded-full border border-ok-border bg-ok-bg px-2 py-0.5 text-caption font-medium text-ok">
          +5 since last scan
        </span>
      </div>
      <ul className="divide-y divide-border">
        {rows.map((row) => (
          <li key={row.title} className="flex items-center gap-3 px-4 py-2.5">
            <ScoreTile score={row.score} level={row.level} className="size-8 [&>span]:text-xs" />
            <span className="min-w-0 flex-1">
              <span className="block truncate text-xs font-medium text-foreground">
                {row.title}
              </span>
              <span className="block text-caption text-muted-foreground">{row.tag}</span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Assurance({ children }: { children: React.ReactNode }) {
  return (
    <li className="flex items-start gap-2.5 text-body leading-[1.6] text-foreground">
      <span className="mt-px flex size-[18px] shrink-0 items-center justify-center rounded-full bg-ok-bg text-ok">
        <svg viewBox="0 0 16 16" className="size-[11px]" aria-hidden="true">
          <path
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            d="m4 8.5 2.5 2.5L12 5.5"
          />
        </svg>
      </span>
      {children}
    </li>
  );
}

/**
 * "We emailed you something." One screen for both, because from the
 * user's side the next action is identical: go to your inbox, click the link.
 */
function SentNotice({ sent, onUseAnother }: { sent: Sent; onUseAnother: () => void }) {
  const t = useT();
  const lead = sent.kind === "confirm" ? t.auth.confirmSentTo : t.auth.resetSentTo;

  return (
    <div>
      <div className="flex h-11 w-11 items-center justify-center rounded-full bg-ok-bg text-ok">
        <svg viewBox="0 0 24 24" className="h-5 w-5" aria-hidden="true">
          <path
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M3 7.5 12 13l9-5.5M4.5 5.5h15a1.5 1.5 0 0 1 1.5 1.5v10a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17V7a1.5 1.5 0 0 1 1.5-1.5Z"
          />
        </svg>
      </div>

      <h1 className={cn("mt-5", PAGE_TITLE_CLASS)}>{t.auth.checkEmail}</h1>
      <p className="mt-2 text-body leading-[1.65] text-muted-foreground">
        {lead} <strong className="text-foreground">{sent.email}</strong>. {t.auth.openOnThisDevice}
      </p>

      <p className="mt-6 rounded-lg bg-muted px-4 py-3 text-caption leading-[1.7] text-muted-foreground">
        The link works once and expires after an hour. If nothing arrives, check spam — and note
        that some disposable inboxes open links automatically, which uses the link up before you get
        to it.
      </p>

      <button
        onClick={onUseAnother}
        className="mt-6 rounded-sm text-body text-muted-foreground underline underline-offset-[3px] transition-colors hover:text-foreground focus-ring"
      >
        {t.auth.useAnotherAddress}
      </button>
    </div>
  );
}
