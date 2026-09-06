import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import { I18nProvider } from "@/i18n";
import { App } from "@/App";
import { createQueryClient } from "@/lib/queryClient";
import { configProblems } from "@/lib/config";
import { ConfigError } from "@/components/ConfigError";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { initTheme } from "@/lib/theme";
// The face files are imported here rather than `@import`ed from index.css:
// Tailwind v4 inlines an `@import` of a node_modules stylesheet without
// rebasing the `url()`s inside it, so the @font-face rules survive the build
// pointing at `./files/*.woff2`, nothing is emitted, and the browser silently
// falls back to system-ui. Going through the bundler instead makes the woff2
// files real build assets. (This is why Geist never actually loaded either.)
import "@fontsource-variable/space-grotesk";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "./index.css";

const queryClient = createQueryClient();

// The inline script in index.html has already put the class on the document;
// this re-reads the same stored choice so React's view of it is derived
// rather than assumed, and starts following the OS while the tab is open.
initTheme();

// A misconfigured production build cannot reach its API at all, so there is
// nothing useful to render -- say why instead of failing silently.
const problems = configProblems();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    {problems.length > 0 ? (
      <ConfigError problems={problems} />
    ) : (
      // Outside the providers, not inside: a query client or a router that
      // throws while mounting takes the app with it, and that error has to land
      // somewhere too.
      <ErrorBoundary>
        <QueryClientProvider client={queryClient}>
          <BrowserRouter>
            <I18nProvider>
              <App />
            </I18nProvider>
          </BrowserRouter>
        </QueryClientProvider>
      </ErrorBoundary>
    )}
  </React.StrictMode>,
);
