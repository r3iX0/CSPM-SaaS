import { useMemo, useSyncExternalStore } from "react";
import { auth, subscribeToAuth } from "./api";

/**
 * The current access token, as React state.
 *
 * useSyncExternalStore rather than a context provider: the token's real home is
 * localStorage (so it survives reloads) and Supabase mutates it from outside
 * the React tree entirely — on sign-in, on the hourly token refresh, and on
 * sign-out. This subscribes to that store directly instead of mirroring it into
 * state that can drift.
 */
export function useAuthToken(): string | null {
  return useSyncExternalStore(
    subscribeToAuth,
    () => auth.token,
    () => null, // server snapshot; there is no SSR here, but the API requires it
  );
}

/**
 * The signed-in user's email, read out of the token rather than stored.
 *
 * Supabase puts it in the JWT's `email` claim, so deriving it here keeps one
 * source of truth: it cannot drift from the session, survives a reload for the
 * same reason the token does, and disappears on sign-out without anything
 * having to remember to clear it.
 *
 * No signature check, deliberately. This value only ever labels the account
 * menu — nothing is authorized by it. The API verifies the same token properly
 * (app/core/security.py) and would reject a forged one, and a user editing
 * their own localStorage to show themselves a different label has achieved
 * nothing.
 */
export function useAuthEmail(): string | null {
  const token = useAuthToken();
  return useMemo(() => emailFromToken(token), [token]);
}

/**
 * Who the session belongs to and whether it passed a second factor, read out
 * of the token like the email above and trusted no further: the gate this
 * feeds only decides whether to ask for a code, and the API checks the same
 * claims on the verified token (DECISIONS.md §213).
 */
export function useSessionClaims(): {
  subject: string | null;
  sessionId: string | null;
  secondFactor: boolean;
} {
  const token = useAuthToken();
  return useMemo(() => {
    const claims = claimsFromToken(token);
    return {
      subject: typeof claims?.sub === "string" ? claims.sub : null,
      // Supabase's id for one sign-in, kept across the hourly token refresh.
      sessionId: typeof claims?.session_id === "string" ? claims.session_id : null,
      secondFactor: claims?.aal === "aal2",
    };
  }, [token]);
}

function emailFromToken(token: string | null): string | null {
  const claims = claimsFromToken(token);
  return typeof claims?.email === "string" ? claims.email : null;
}

function claimsFromToken(token: string | null): Record<string, unknown> | null {
  if (!token) return null;
  const payload = token.split(".")[1];
  if (!payload) return null;
  try {
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    const claims: unknown = JSON.parse(json);
    // A JSON object, checked on the line itself; its values stay unknown.
    return typeof claims === "object" && claims !== null
      ? (claims as Record<string, unknown>)
      : null;
  } catch {
    // A malformed token is the API's problem to reject, not this label's.
    return null;
  }
}
