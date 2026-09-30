import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { updatePassword } from "@/lib/supabase";
import { useAuthToken } from "@/lib/useAuth";
import { useT } from "@/i18n";
import { Wordmark } from "@/components/Brand";
import { PAGE_TITLE_CLASS } from "@/components/common/states";

/**
 * Where a password-reset email lands.
 *
 * The recovery link carries a real (short-lived) session, which Supabase has
 * already parsed out of the URL by the time this renders — App.tsx waits on
 * `authReady` before routing anything. So the check below is not an auth gate;
 * it is how an expired or already-used link is recognised, and it says so
 * rather than bouncing the user to a sign-in form that will not help them.
 */
const MIN_PASSWORD_LENGTH = 8;

export function ResetPasswordPage() {
  const t = useT();
  const navigate = useNavigate();
  const token = useAuthToken();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    // Unavailable rather than disabled while busy, so the button keeps focus;
    // this is what refuses the press.
    if (busy) return;

    if (password.length < MIN_PASSWORD_LENGTH) {
      setError(t.auth.passwordTooShort);
      return;
    }
    if (password !== confirm) {
      setError(MISMATCH);
      return;
    }

    setBusy(true);
    setError(null);
    try {
      await updatePassword(password);
      // The recovery session is a normal session, so there is nowhere to send
      // them but in — signing them out to re-enter the password they just set
      // would be theatre.
      navigate("/", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not update your password");
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/40 px-6">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex items-center gap-2.5">
          <Wordmark />
        </div>

        {token ? (
          <>
            <h1 className={PAGE_TITLE_CLASS}>
              {t.auth.setPassword}
            </h1>
            <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
              Choose something long. {t.auth.passwordTooShort}
            </p>

            <form
              onSubmit={submit}
              className="mt-6 space-y-4 rounded-xl border border-border bg-background p-6 shadow-sm"
            >
              <label className="block">
                <span className="mb-1.5 block text-sm font-medium text-foreground">
                  {t.auth.newPassword}
                </span>
                <input
                  type="password"
                  required
                  // The page is this form, outside the shell with nothing before
                  // it to read, and the field is its first.
                  // eslint-disable-next-line jsx-a11y/no-autofocus
                  autoFocus
                  autoComplete="new-password"
                  minLength={MIN_PASSWORD_LENGTH}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={FIELD_CLASS}
                />
              </label>

              <label className="block">
                <span className="mb-1.5 block text-sm font-medium text-foreground">
                  Confirm password
                </span>
                <input
                  type="password"
                  required
                  autoComplete="new-password"
                  minLength={MIN_PASSWORD_LENGTH}
                  // The one error that is about a field rather than the
                  // request: said on the field, and read with it.
                  aria-invalid={error === MISMATCH || undefined}
                  aria-describedby={error === MISMATCH ? "reset-error" : undefined}
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  className={FIELD_CLASS}
                />
              </label>

              {error && (
                <p id="reset-error" role="alert" className="text-sm text-critical">
                  {error}
                </p>
              )}

              <button
                type="submit"
                aria-disabled={busy || undefined}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground shadow-sm transition hover:bg-primary/90 focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring aria-disabled:cursor-not-allowed aria-disabled:bg-muted aria-disabled:text-muted-foreground"
              >
                {busy ? t.common.loading : t.auth.setPassword}
              </button>
            </form>
          </>
        ) : (
          <>
            <h1 className={PAGE_TITLE_CLASS}>
              This link has expired
            </h1>
            <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
              Reset links work once and expire after an hour. Ask for a fresh one
              and open it on this device.
            </p>
            <Link
              to="/sign-in"
              className="mt-6 inline-block text-sm font-medium text-muted-foreground underline underline-offset-4 transition hover:text-foreground"
            >
              {t.auth.backToSignIn}
            </Link>
          </>
        )}
      </div>
    </div>
  );
}

const MISMATCH = "The two passwords don't match.";

const FIELD_CLASS =
  "w-full rounded-lg border border-input bg-background px-3.5 py-2.5 text-sm text-foreground shadow-sm transition placeholder:text-muted-foreground hover:border-ring focus:border-ring focus:outline-none focus:ring-2 focus:ring-ring/20 aria-invalid:border-critical-border";
