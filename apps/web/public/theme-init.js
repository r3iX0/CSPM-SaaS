// The theme, before the first paint.
//
// React cannot do this: by the time it mounts, the browser has already painted
// a white page, and correcting it afterwards is a flash of light in a dark
// room. Kept deliberately small -- the key, the class and the fallback are the
// same ones in src/lib/theme.ts, and a test compares them.
//
// A file of its own rather than inline in index.html: the Content-Security-
// Policy in vercel.json allows scripts from 'self' only, which refuses an
// inline script. Loaded as a classic, blocking script in <head>, so it still
// runs before anything is painted.
(function () {
  try {
    const stored = localStorage.getItem("cloudguard-theme");
    const choice = stored === "light" || stored === "dark" ? stored : "system";
    const dark =
      choice === "dark" ||
      (choice === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.classList.toggle("dark", dark);
    document.documentElement.style.colorScheme = dark ? "dark" : "light";
  } catch (e) {
    /* No storage, no preference read: the light default already applies. */
  }
})();
