/**
 * An auditor's link opened before its reader was signed in.
 *
 * The same problem as an invitation (`lib/pendingInvite.ts`): the token is in
 * the URL fragment of `/auditor`, and every way of signing in lands back on the
 * site's root, so the fragment is gone by the time the reader is somebody. Held
 * here until then; the shell sends a signed-in reader holding one to `/auditor`
 * before onboarding, which would otherwise ask an auditor to create an
 * organization (DECISIONS.md §211, §218).
 *
 * A separate key, because the two tokens are different kinds of link and one
 * person may hold both. Kept for a day, as an invitation is: a grant's link is
 * made to be opened soon, and one found much later is more likely forgotten.
 */
const KEY = "cleave.pendingGrant";
const LIFETIME_MS = 24 * 60 * 60 * 1000;

export function holdGrant(token: string): void {
  try {
    window.localStorage.setItem(KEY, JSON.stringify({ token, at: Date.now() }));
  } catch {
    // Storage disabled: the reader opens the link again after signing in.
  }
}

export function heldGrant(): string | null {
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

export function forgetGrant(): void {
  try {
    window.localStorage.removeItem(KEY);
  } catch {
    // Nothing held, or nothing that can be.
  }
}

/** The token in `/auditor#<token>`, if the fragment carries one. */
export function grantFromHash(hash: string): string | null {
  const token = hash.replace(/^#/, "").trim();
  return token.length >= 20 ? token : null;
}
