import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

import vercel from "./vercel.json";

/** The local API and Auth a built app served on this machine calls (tools/local/env.sh). */
const LOCAL_ORIGINS = "http://localhost:8000 http://127.0.0.1:54321";

/**
 * vercel.json's headers, for `vite preview` (tools/local/run.sh, DECISIONS.md §241).
 *
 * A local run serves the built app with the headers Vercel sends, so a page that breaks under
 * the deployed Content-Security-Policy breaks here first. Two changes only, both because the
 * local stack speaks plain HTTP: the policy also allows the local API and Auth origins and
 * drops `upgrade-insecure-requests`, and Strict-Transport-Security is left out, since a browser
 * holding it for localhost would refuse every other local server.
 */
function vercelHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const { key, value } of vercel.headers.find((rule) => rule.source === "/(.*)")?.headers ??
    []) {
    if (key === "Strict-Transport-Security") continue;
    headers[key] =
      key === "Content-Security-Policy"
        ? value
            .replace("connect-src 'self'", `connect-src 'self' ${LOCAL_ORIGINS}`)
            .replace(/;\s*upgrade-insecure-requests/, "")
        : value;
  }
  return headers;
}

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        /**
         * Vendor code, split off from ours.
         *
         * Not about total bytes -- the same libraries are downloaded either
         * way. It is about what a deploy invalidates: app code changes on
         * every release and React does not, so keeping them in one file made
         * every returning reader re-download a megabyte of unchanged
         * dependencies to pick up a copy edit.
         *
         * Grouped by how they change rather than one chunk per package. A file
         * per dependency trades one large download for fifty small ones, and
         * on a cold connection the round trips cost more than the bytes saved.
         */
        manualChunks: {
          react: ["react", "react-dom", "react-router-dom"],
          data: ["@tanstack/react-query", "@supabase/supabase-js"],
        },
      },
    },
  },
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  preview: {
    headers: vercelHeaders(),
  },
  server: {
    port: 5173,
    host: true,
    watch: { usePolling: true },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    /**
     * Longer than vitest's five seconds, because of what these tests are.
     *
     * Almost every one of them mounts a real page -- a router, a query client,
     * several settling requests and a full component tree -- inside jsdom, and
     * the suite runs those in parallel across every core the machine has. On a
     * loaded machine a page that renders in 200ms alone can take several
     * seconds, and the failure that produced was always the same shape: a
     * `findByText` that times out on text the page does render, in a test that
     * passes on its own. That is a slow machine reported as a broken product,
     * which is worse than a slow suite.
     */
    testTimeout: 20_000,
  },
});
