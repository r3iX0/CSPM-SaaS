/**
 * An invitation link opened before its reader was signed in.
 *
 * The token arrives in the URL fragment of `/invite`, and every way of signing
 * in -- Microsoft, Google, a confirmation email -- lands back on the
 * site's root, so the fragment is gone by the time the reader is somebody.
 * Held here until then, and the shell sends a signed-in reader holding one to
 * `/invite` before anything else, including the empty-organization onboarding
 * an invitee would otherwise be dropped into (DECISIONS.md §162).
 *
 * localStorage rather than sessionStorage, because an emailed link opens in a
 * new tab. Kept for a day: the invitation itself lasts a week, and a token found
 * much later than it was stored is more likely forgotten than wanted.
 */
const KEY = "cleave.pendingInvite";
const LIFETIME_MS = 24 * 60 * 60 * 1000;

export function holdInvite(token: string): void {
  try {
    window.localStorage.setItem(KEY, JSON.stringify({ token, at: Date.now() }));
  } catch {
    // Storage disabled: the reader opens the link again after signing in.
  }
}

export function heldInvite(): string | null {
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return null;
    const { token, at } = JSON.parse(raw) as { token?: unknown; at?: unknown };
    if (typeof token !== "string" || typeof at !== "number" || Date.now() - at > LIFETIME_MS) {
      window.localStorage.removeItem(KEY);
      return null;
    }
    return token;
  } catch {
    return null;
  }
}

export function forgetInvite(): void {
  try {
    window.localStorage.removeItem(KEY);
  } catch {
    // Nothing held, or nothing that can be.
  }
}

/** The token in `/invite#<token>`, if the fragment carries one. */
export function inviteFromHash(hash: string): string | null {
  const token = hash.replace(/^#/, "").trim();
  return token.length >= 20 ? token : null;
}
