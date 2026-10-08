/**
 * Supabase Auth bridge.
 *
 * CloudGuard's backend never authenticates anyone itself — it only verifies the
 * JWT Supabase issues (app/core/security.py::decode_token). This file is the
 * other half: it drives Supabase's hosted sign-in and mirrors the resulting
 * session into the same `auth` token store api.ts already uses, so the rest of
 * the app never has to know whether a session came from Supabase or from the
 * local dev-token route.
 *
 * Four ways in, all of them ending in the same Supabase-issued JWT: an email +
 * password pair, a password reset, Microsoft (Entra ID) and Google.
 * The backend cannot tell them apart and does not need to — it verifies the
 * token's signature and reads the user id, nothing more.
 *
 * Only active when VITE_SUPABASE_URL / VITE_SUPABASE_PUBLISHABLE_KEY are set;
 * with neither, every function here throws rather than silently doing nothing.
 */
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { auth } from "./api";

const url = import.meta.env.VITE_SUPABASE_URL;
const key = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;

export const supabaseConfigured = Boolean(url && key);

// A plain top-level `if` (not an assignment inside a closure) so TypeScript's
// control-flow narrowing correctly widens this to `SupabaseClient | null`
// afterward, instead of anchoring on the `null` initializer.
let clientOrNull: SupabaseClient | null = null;
if (url && key) {
  clientOrNull = createClient(url, key);
}

/** `const` so its narrowing survives being captured by the closures below —
 * TypeScript does not trust a mutable `let` across a closure boundary. */
export const supabase = clientOrNull;

/**
 * Resolves once the initial session check (including parsing a sign-in
 * redirect's URL fragment) has completed. The router waits on this before
 * deciding whether to redirect to /sign-in — without it, a page load that
 * lands mid-redirect would see `auth.token` still null and bounce the user
 * back to sign-in before the session finished parsing.
 */
export const authReady: Promise<void> = supabase
  ? new Promise((resolve) => {
      supabase.auth.onAuthStateChange((_event, session) => {
        auth.token = session?.access_token ?? null;
      });

      supabase.auth.getSession().then(({ data }) => {
        auth.token = data.session?.access_token ?? null;
        resolve();
      });
    })
  : Promise.resolve();

/**
 * Password sign-in.
 *
 * The password goes from the browser straight to Supabase's auth API over
 * TLS. It never reaches CloudGuard's own API, which still only ever verifies
 * the JWT that comes back (app/core/security.py::decode_token) — so the
 * backend's threat model is unchanged by this file, whatever provider the
 * session came from.
 */
export async function signInWithPassword(email: string, password: string): Promise<void> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) throw error;
}

/**
 * Password sign-up.
 *
 * Returns whether a session was established immediately. With Supabase's
 * "Confirm email" setting on — the default, and what DEPLOYMENT.md tells you
 * to leave on — sign-up creates the user but no session, and the caller must
 * tell the user to go and click the confirmation email. With it off, the user
 * is signed in on the spot. The caller cannot guess which, so it is reported.
 */
export async function signUpWithPassword(
  email: string,
  password: string,
): Promise<{ needsEmailConfirmation: boolean }> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: { emailRedirectTo: window.location.origin },
  });
  if (error) throw error;
  return { needsEmailConfirmation: data.session === null };
}

/** Emails a recovery link that lands on /reset-password with a live session. */
export async function sendPasswordReset(email: string): Promise<void> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { error } = await supabase.auth.resetPasswordForEmail(email, {
    redirectTo: `${window.location.origin}/reset-password`,
  });
  if (error) throw error;
}

/** Sets a new password for the session the recovery link just established. */
export async function updatePassword(password: string): Promise<void> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { error } = await supabase.auth.updateUser({ password });
  if (error) throw error;
}

/**
 * Sign in with Microsoft (Entra ID).
 *
 * The natural front door for an Azure-first product: the account someone uses
 * here is the same directory account that will later grant CloudGuard admin
 * consent. Supabase calls this provider `azure`.
 *
 * This never returns normally — it navigates away to Microsoft. The session
 * comes back on the redirect and is picked up by `onAuthStateChange` above,
 * so there is nothing to await and no token handling here.
 */
export async function signInWithMicrosoft(): Promise<void> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { error } = await supabase.auth.signInWithOAuth({
    provider: "azure",
    options: {
      // openid/profile/email is the minimum that yields a usable identity.
      // Nothing here grants access to Azure *resources* — scanning access is a
      // separate admin consent against CloudGuard's own Entra application
      // (docs/AZURE_INTEGRATION.md), not this sign-in.
      scopes: "openid profile email",
      redirectTo: window.location.origin,
    },
  });
  if (error) throw error;
}

/**
 * Sign in with Google.
 *
 * For the people whose work account is Google Workspace rather than Entra ID.
 * Like Microsoft above, it navigates away and the session comes back on the
 * redirect through `onAuthStateChange`. It grants nothing in any cloud: Google
 * is an identity here, never a scanned provider.
 */
export async function signInWithGoogle(): Promise<void> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { error } = await supabase.auth.signInWithOAuth({
    provider: "google",
    options: {
      // Supabase asks Google for openid, email and profile by default, which
      // is all an identity needs.
      redirectTo: window.location.origin,
      // Someone signed in to a personal and a work Google account at once
      // should choose which one becomes their Cleave identity, rather than
      // have Google pick whichever was used last.
      queryParams: { prompt: "select_account" },
    },
  });
  if (error) throw error;
}

/**
 * Open a guest session: a visitor exploring the demo without an account.
 *
 * Supabase's anonymous sign-in. The token is real -- a user id, signed by
 * Supabase -- with no email and `is_anonymous` set, which the API reads to keep
 * a guest in the demo and refuse everything else (DECISIONS.md §219).
 */
export async function signInAsGuest(): Promise<void> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { data, error } = await supabase.auth.signInAnonymously();
  if (error) throw error;
  // Written here as well as by onAuthStateChange, because the very next call
  // is the API's, and it must carry this token rather than race the listener.
  auth.token = data.session?.access_token ?? null;
}

/**
 * Keep a guest as an account, by email.
 *
 * The same user, so nothing they had moves: Supabase sends a confirmation to the
 * address, and the link lands on /reset-password with the session, where they
 * choose a password -- Supabase sets one only once the address is confirmed.
 */
export async function saveGuestWithEmail(email: string): Promise<void> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { error } = await supabase.auth.updateUser(
    { email },
    { emailRedirectTo: `${window.location.origin}/reset-password` },
  );
  if (error) throw error;
}

/**
 * Keep a guest as an account, by linking Microsoft or Google to it.
 *
 * Navigates away to the provider like a sign-in does, and comes back as the same
 * user with an identity attached and `is_anonymous` gone. Needs manual linking
 * switched on in the Supabase project (docs/DEPLOYMENT.md §1).
 */
export async function saveGuestWithProvider(provider: "azure" | "google"): Promise<void> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { error } = await supabase.auth.linkIdentity({
    provider,
    options: {
      redirectTo: window.location.origin,
      ...(provider === "azure"
        ? { scopes: "openid profile email" }
        : { queryParams: { prompt: "select_account" } }),
    },
  });
  if (error) throw error;
}

/** An authenticator app the signed-in user has confirmed with a code. */
export interface SecondFactor {
  readonly id: string;
  readonly createdAt: string;
}

/** An authenticator app added but not yet confirmed with its first code. */
export interface PendingSecondFactor {
  readonly id: string;
  /** The code to scan, as the SVG data URL Supabase draws. */
  readonly qrCode: string;
  /** The same key as text, for an app that cannot scan. */
  readonly secret: string;
}

/**
 * Whether this session still owes a code from an authenticator app.
 *
 * True when the user has a confirmed authenticator and the session was opened
 * with one factor only -- a password, Microsoft, Google, or an emailed link.
 * Read from the session Supabase holds in this browser, without a request.
 * The API refuses such a session whatever this says (DECISIONS.md §217).
 */
export async function secondFactorNeeded(): Promise<boolean> {
  if (!supabase) return false;
  const { data, error } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
  if (error) throw error;
  return data.nextLevel === "aal2" && data.currentLevel !== "aal2";
}

/** The TanStack Query key holding the signed-in user's authenticator apps. */
export const SECOND_FACTORS_KEY = ["second-factors"] as const;

/** The user's confirmed authenticator apps, read fresh from Supabase. */
export async function listSecondFactors(): Promise<SecondFactor[]> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { data, error } = await supabase.auth.mfa.listFactors();
  if (error) throw error;
  return data.totp.map((factor) => ({ id: factor.id, createdAt: factor.created_at }));
}

/**
 * Adds an authenticator app, to be confirmed with `confirmSecondFactor`.
 *
 * One left unconfirmed -- a set-up closed halfway -- is removed first, so they
 * do not pile up on the account.
 */
export async function startSecondFactor(): Promise<PendingSecondFactor> {
  if (!supabase) throw new Error("Supabase is not configured");
  const client = supabase;
  const listed = await client.auth.mfa.listFactors();
  if (listed.error) throw listed.error;
  await Promise.all(
    listed.data.all
      .filter((factor) => factor.status === "unverified")
      .map(async (factor) => {
        const { error } = await client.auth.mfa.unenroll({ factorId: factor.id });
        if (error) throw error;
      }),
  );

  const { data, error } = await client.auth.mfa.enroll({ factorType: "totp", issuer: "Cleave" });
  if (error) throw error;
  return { id: data.id, qrCode: data.totp.qr_code, secret: data.totp.secret };
}

/**
 * Checks a code against an authenticator app: the first one confirms a new
 * app, and any one passes a session's second factor. Either way the session
 * Supabase hands back is two-factor, and `onAuthStateChange` stores it.
 */
export async function confirmSecondFactor(factorId: string, code: string): Promise<void> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { error } = await supabase.auth.mfa.challengeAndVerify({ factorId, code });
  if (error) throw error;
}

/** Removes an authenticator app. Supabase allows it only to a two-factor session. */
export async function removeSecondFactor(factorId: string): Promise<void> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { error } = await supabase.auth.mfa.unenroll({ factorId });
  if (error) throw error;
}

export async function supabaseSignOut(): Promise<void> {
  if (!supabase) return;
  await supabase.auth.signOut();
}
