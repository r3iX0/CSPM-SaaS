import { useState } from "react";
import { Navigate } from "react-router-dom";
import {
  sendPasswordReset,
  signInWithMagicLink,
  signInWithMicrosoft,
  signInWithPassword,
  signUpWithPassword,
} from "@/lib/supabase";
import { useAuthToken } from "@/lib/useAuth";
import { useT } from "@/i18n";
import { Wordmark } from "@/components/Brand";
import { ScoreTile } from "@/components/security/ScoreTile";

/**
 * Sign-in and sign-up, via Supabase.
 *
 * CloudGuard's own backend never authenticates anyone — Supabase does, and the
 * API only ever *verifies* the JWT that comes back
 * (app/core/security.py::decode_token). Four routes in, one token out:
 *
 *   Microsoft (Entra ID)  the front door for an Azure-first product — the same
 *                         directory account that will later grant consent
 *   Email + password      familiar, and works where corporate mail scanners
 *                         eat one-time links before the user sees them
 *   Magic link            no password to choose, forget, or have stolen
 *   Password reset        because a password flow without recovery is a trap
 *
 * A password typed here goes from the browser straight to Supabase over TLS.
 * It is never sent to, logged by, or stored by CloudGuard's API.
 *
 * The left panel is not decoration. This is the screen where someone decides
 * whether to hand a product read access to their whole cloud estate, so it
 * states plainly what the access is and what it is not.
 */

/** Which form is showing. `sent` states are tracked separately, below. */
type Mode = "signin" | "signup" | "magic" | "reset";

/** A "we emailed you something" confirmation, and which something it was. */
type Sent = { kind: "magic" | "confirm" | "reset"; email: string };

const MIN_PASSWORD_LENGTH = 8;

export function SignInPage() {
  const t = useT();
  const token = useAuthToken();
  const [mode, setMode] = useState<Mode>("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState<Sent | null>(null);

  const needsPassword = mode === "signin" || mode === "signup";

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
      if (mode === "signin") {
        await signInWithPassword(email, password);
        // No navigation here. Supabase's onAuthStateChange writes the token,
        // useAuthToken re-renders this component, and the redirect below fires.
      } else if (mode === "signup") {
        const { needsEmailConfirmation } = await signUpWithPassword(email, password);
        if (needsEmailConfirmation) setSent({ kind: "confirm", email });
      } else if (mode === "magic") {
        await signInWithMagicLink(email);
        setSent({ kind: "magic", email });
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

  async function microsoft() {
    setBusy(true);
    setError(null);
    try {
      // Navigates away to Microsoft and does not come back here, so `busy`
      // is deliberately left set — the button should stay disabled for the
      // moment the browser spends unloading the page.
      await signInWithMicrosoft();
    } catch (err) {
      setError(authErrorMessage(err));
      setBusy(false);
    }
  }

  // Returning from a magic link, a confirmation, or Microsoft lands here first.
  // Once the session is parsed, move on rather than showing a sign-in form to
  // someone who is already signed in.
  if (token) return <Navigate to="/" replace />;

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
              <h1 className="text-2xl font-semibold tracking-[-0.02em] text-foreground">
                {mode === "signup"
                  ? t.auth.signUp
                  : mode === "reset"
                    ? t.auth.resetTitle
                    : t.auth.signIn}
              </h1>
              <p className="mt-2 text-[13px] leading-[1.65] text-muted-foreground">
                {mode === "signup"
                  ? "Start with your work email. You can connect Azure once you're in."
                  : mode === "reset"
                    ? t.auth.resetIntro
                    : mode === "magic"
                      ? "We'll email you a one-time link. No password to choose, forget, or have stolen."
                      : "Use your Microsoft account, or the email and password you signed up with."}
              </p>

              {/* Microsoft first: for an Azure-first product it is the account
                  most users already have, and the one they will consent with. */}
              {mode !== "reset" && (
                <>
                  <MicrosoftButton onClick={microsoft} disabled={busy} label={t.auth.continueWithMicrosoft} />
                  <Divider label={t.auth.orDivider} />
                </>
              )}

              <form onSubmit={submit} className={mode === "reset" ? "mt-7" : "mt-[22px]"}>
                <label htmlFor="email" className="block text-[13px] font-medium text-foreground">
                  {t.auth.email}
                </label>
                <input
                  id="email"
                  type="email"
                  required
                  // The page is this form, outside the shell with nothing before
                  // it to read, and the field is its first.
                  // eslint-disable-next-line jsx-a11y/no-autofocus
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
                          className="rounded-sm text-[11.5px] text-muted-foreground underline underline-offset-[3px] transition hover:text-foreground focus-ring"
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
                  className="mt-[22px] flex h-[42px] w-full items-center justify-center gap-2 rounded-[9px] bg-primary px-4 text-[13.5px] font-medium text-primary-foreground transition-colors hover:bg-primary/90 focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring aria-disabled:cursor-not-allowed aria-disabled:bg-muted aria-disabled:text-muted-foreground"
                >
                  {busy && (
                    <span
                      aria-hidden
                      className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current/30 border-t-current"
                    />
                  )}
                  {submitLabel(mode, busy, t)}
                </button>
              </form>

              <AlternateRoutes mode={mode} onSwitch={switchTo} />

              {/* Whichever assurance the mode has actually earned. Reset gets
                  none: there is no password typed here yet and no Microsoft
                  button on screen to qualify. */}
              {mode !== "reset" && (
                <p className="mt-[26px] border-t border-border pt-5 text-[11.5px] leading-[1.7] text-muted-foreground">
                  {needsPassword ? t.auth.passwordNotice : t.auth.microsoftHint}
                </p>
              )}
            </>
          )}
        </div>
      </main>
    </div>
  );
}

const FIELD_CLASS =
  "mt-2 h-10 w-full rounded-[9px] border border-input bg-background px-[13px] text-[13.5px] text-foreground transition-colors placeholder:text-muted-foreground hover:border-ring focus-visible:border-ring focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-ring/50";

function submitLabel(mode: Mode, busy: boolean, t: ReturnType<typeof useT>): string {
  if (busy) {
    if (mode === "signup") return t.auth.creatingAccount;
    if (mode === "signin") return t.auth.signingIn;
    return t.auth.sending;
  }
  if (mode === "signup") return t.auth.signUp;
  if (mode === "signin") return t.auth.signIn;
  if (mode === "magic") return t.auth.sendLink;
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
  if (text.includes("not configured")) {
    return "This deployment has no Supabase project configured, so sign-in is unavailable.";
  }
  return raw || "Something went wrong. Try again.";
}

function Divider({ label }: { label: string }) {
  return (
    <div className="mt-[22px] flex items-center gap-3" aria-hidden="true">
      <span className="h-px flex-1 bg-border" />
      <span className="text-[11.5px] text-muted-foreground">{label}</span>
      <span className="h-px flex-1 bg-border" />
    </div>
  );
}

function MicrosoftButton({
  onClick,
  disabled,
  label,
}: {
  onClick: () => void;
  disabled: boolean;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="mt-7 flex h-[42px] w-full items-center justify-center gap-2.5 rounded-[9px] border border-border bg-card px-4 text-[13.5px] font-medium text-foreground transition-colors hover:bg-muted/60 focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring disabled:cursor-not-allowed disabled:text-muted-foreground"
    >
      <MicrosoftMark />
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
        <label htmlFor={id} className="block text-[13px] font-medium text-foreground">
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
          className="absolute inset-y-0 right-0 mt-2 flex items-center rounded-r-[9px] px-3 text-muted-foreground transition hover:text-foreground focus-ring-inset"
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
      <g fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
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
      <div className="mt-[22px] text-center text-[13px]">
        <TextLink onClick={() => onSwitch("signin")}>{t.auth.backToSignIn}</TextLink>
      </div>
    );
  }

  return (
    <div className="mt-[22px] space-y-3 text-center text-[13px]">
      <p>
        <TextLink onClick={() => onSwitch(mode === "magic" ? "signin" : "magic")}>
          {mode === "magic" ? t.auth.passwordInstead : t.auth.magicLinkInstead}
        </TextLink>
      </p>
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
      <Wordmark className="gap-2.5" markClassName="size-[22px]" labelClassName="text-[17px]" />

      <div>
        <h2 className="max-w-[15ch] text-4xl leading-[1.12] font-semibold tracking-[-0.03em]">
          Cut the one link that matters.
        </h2>
        <p className="mt-[18px] max-w-[46ch] text-sm leading-[1.7] text-muted-foreground">
          Cleave reads your Azure environment, ranks what it finds by what it
          would cost this business, and proves the fix worked on the next scan.
        </p>

        <ProductPreview />

        <ul className="mt-7 flex flex-col gap-3">
          <Assurance>Read-only. Cleave never changes your resources.</Assurance>
          <Assurance>No Azure credential to hand over — consent, not secrets.</Assurance>
          <Assurance>Your data is isolated at the database level, not just in code.</Assurance>
        </ul>
      </div>

      <p className="text-[11.5px] text-muted-foreground">
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
    { score: 98, level: "CRITICAL", title: "Internet → vm-jumpbox → storage-prod-01", tag: "Attack path" },
    { score: 94, level: "CRITICAL", title: "RDP reachable from the internet on prod-vm-01", tag: "Internet-facing" },
  ];

  return (
    <div
      aria-hidden="true"
      className="mt-8 max-w-[440px] overflow-hidden rounded-xl border border-border bg-card"
    >
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <div className="flex items-baseline gap-2">
          <span className="text-[26px] font-semibold tracking-[-0.02em] text-medium tabular-nums">71</span>
          <span className="text-[11.5px] text-muted-foreground">/ 100 security score</span>
        </div>
        <span className="rounded-full border border-ok-border bg-ok-bg px-2 py-0.5 text-[11px] font-medium text-ok">
          +5 since last scan
        </span>
      </div>
      <ul className="divide-y divide-border">
        {rows.map((row) => (
          <li key={row.title} className="flex items-center gap-3 px-4 py-2.5">
            <ScoreTile score={row.score} level={row.level} className="size-8 [&>span]:text-xs" />
            <span className="min-w-0 flex-1">
              <span className="block truncate text-xs font-medium text-foreground">{row.title}</span>
              <span className="block text-[11px] text-muted-foreground">{row.tag}</span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Assurance({ children }: { children: React.ReactNode }) {
  return (
    <li className="flex items-start gap-2.5 text-[13px] leading-[1.6] text-foreground">
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
 * "We emailed you something." One screen for all three, because from the
 * user's side the next action is identical: go to your inbox, click the link.
 */
function SentNotice({ sent, onUseAnother }: { sent: Sent; onUseAnother: () => void }) {
  const t = useT();
  const lead =
    sent.kind === "confirm"
      ? t.auth.confirmSentTo
      : sent.kind === "reset"
        ? t.auth.resetSentTo
        : t.auth.linkSentTo;

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

      <h1 className="mt-5 text-2xl font-semibold tracking-[-0.02em] text-foreground">
        {t.auth.checkEmail}
      </h1>
      <p className="mt-2 text-[13px] leading-[1.65] text-muted-foreground">
        {lead} <strong className="text-foreground">{sent.email}</strong>.{" "}
        {t.auth.openOnThisDevice}
      </p>

      <p className="mt-6 rounded-[10px] bg-muted px-4 py-3 text-[11.5px] leading-[1.7] text-muted-foreground">
        The link works once and expires after an hour. If nothing arrives, check
        spam — and note that some disposable inboxes open links automatically,
        which uses the link up before you get to it.
      </p>

      <button
        onClick={onUseAnother}
        className="mt-6 rounded-sm text-[13px] text-muted-foreground underline underline-offset-[3px] transition-colors hover:text-foreground focus-ring"
      >
        {t.auth.useAnotherAddress}
      </button>
    </div>
  );
}
