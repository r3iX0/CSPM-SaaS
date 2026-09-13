import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

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
