/** Where the product lives. The marketing site only links to it; no session is shared. */
export const APP_URL = "https://cspmcloud.vercel.app";

export const SIGN_UP_URL = `${APP_URL}/sign-in`;

/** Opens the shared demo as a guest: no account, no organization (DECISIONS.md §219). */
export const DEMO_URL = `${APP_URL}/demo`;

/** TODO: replace with the real sales address before launch. */
export const SALES_EMAIL = "sales@example.com";

export const NAV = [
  { href: "/#product", label: "Product" },
  { href: "/#how", label: "How it works" },
  { href: "/pricing", label: "Pricing" },
  { href: "/security", label: "Security" },
] as const;
