// @ts-check
import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";

// A static site: every page is HTML at build time, so it reads without
// JavaScript and indexes cleanly. The product itself stays in apps/web.
export default defineConfig({
  output: "static",
  devToolbar: { enabled: false },
  vite: { plugins: [tailwindcss()] },
});
