import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import { MotionConfig } from "motion/react";
import { BrowserRouter } from "react-router-dom";
import { I18nProvider } from "@/i18n";
import { App } from "@/App";
import { createQueryClient } from "@/lib/queryClient";
import { configProblems } from "@/lib/config";
import { ConfigError } from "@/components/ConfigError";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { initTheme } from "@/lib/theme";
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
          {/* One answer to "this reader asked for less motion", in one place,
              the way the `prefers-reduced-motion` media query in index.css is
              the one answer for the CSS half. `reducedMotion="user"` makes
              every animation below it snap to its final state rather than run
              slower -- reduced motion means arriving, not crawling. */}
          <MotionConfig reducedMotion="user">
            <BrowserRouter>
              <I18nProvider>
                <App />
              </I18nProvider>
            </BrowserRouter>
          </MotionConfig>
        </QueryClientProvider>
      </ErrorBoundary>
    )}
  </React.StrictMode>,
);
