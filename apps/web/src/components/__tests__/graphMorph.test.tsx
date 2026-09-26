/**
 * The morph from a dashboard row into the graph frame (DECISIONS.md §140).
 *
 * jsdom draws nothing and has no View Transitions, so these read what the morph
 * asks of the browser and of the router: which element is named when the
 * first picture is taken, that the page it waits for is there when the second
 * is, and that without the API, or for a reader who asked for less motion, the
 * link is an ordinary link.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { PageTransition } from "@/components/PageTransition";
import { GraphLink } from "@/components/graph/GraphLink";

vi.mock("@/components/graph/graphQueries", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/components/graph/graphQueries")>()),
  // Loading ahead is §139's and tested there; here it would import whole pages.
  preloadGraph: vi.fn(),
}));

type Start = (update: () => Promise<void> | void) => { finished: Promise<void> };

function Where() {
  const location = useLocation();
  return <p data-testid="where">{JSON.stringify([location.pathname, location.state])}</p>;
}

function mount() {
  const client = new QueryClient();
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/"]}>
        <PageTransition>
          <Routes>
            <Route
              path="/"
              element={
                <ol>
                  <li data-graph-source="" data-testid="row">
                    Storage account allows public blobs
                    <GraphLink to={{ kind: "asset", assetId: "asset-1" }}>Open</GraphLink>
                  </li>
                </ol>
              }
            />
            <Route path="/assets/:id" element={<div data-graph-frame="">The frame</div>} />
          </Routes>
        </PageTransition>
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** A browser that has the API: runs the update, and says when it is done. */
function lendViewTransitions(onStart?: () => void) {
  const start = vi.fn<Start>((update) => {
    onStart?.();
    const finished = Promise.resolve(update());
    return { finished };
  });
  (document as unknown as { startViewTransition?: Start }).startViewTransition = start;
  return start;
}

afterEach(() => {
  delete (document as unknown as { startViewTransition?: Start }).startViewTransition;
  vi.restoreAllMocks();
});

describe("the morph into the graph", () => {
  it("names the row it was clicked from, then lands on the next page's frame", async () => {
    const row = () => screen.getByTestId("row");
    let namedAtFirstPicture = "";
    const start = lendViewTransitions(() => {
      namedAtFirstPicture = row().style.viewTransitionName;
    });
    const { container } = mount();
    const page = container.firstElementChild;

    fireEvent.click(screen.getByRole("link", { name: "Open" }));

    expect(start).toHaveBeenCalledTimes(1);
    expect(namedAtFirstPicture).toBe("graph-frame");
    // Named only while the morph runs, so the frame is the one thing it lands on.
    expect(document.documentElement).toHaveClass("cg-graph-morph");

    expect(await screen.findByText("The frame")).toBeInTheDocument();
    expect(screen.getByTestId("where")).toHaveTextContent(
      '["/assets/asset-1",{"graphMorph":true}]',
    );
    // The old page left at once, into the same element: an exit counted in
    // frames the browser is not drawing would never have let this one mount.
    expect(screen.queryByText(/Storage account/)).not.toBeInTheDocument();
    expect(container.firstElementChild).toBe(page);

    await start.mock.results[0].value.finished;
    await waitFor(() =>
      expect(document.documentElement).not.toHaveClass("cg-graph-morph"),
    );
  });

  it("is an ordinary link where the browser has no View Transitions", async () => {
    mount();
    fireEvent.click(screen.getByRole("link", { name: "Open" }));

    expect(await screen.findByText("The frame")).toBeInTheDocument();
    expect(screen.getByTestId("where")).toHaveTextContent('["/assets/asset-1",null]');
  });

  it("does not morph for a reader who asked for less motion", async () => {
    const start = lendViewTransitions();
    vi.spyOn(window, "matchMedia").mockImplementation(
      (query: string) =>
        ({ matches: query.includes("reduce"), media: query }) as MediaQueryList,
    );
    mount();
    fireEvent.click(screen.getByRole("link", { name: "Open" }));

    expect(await screen.findByText("The frame")).toBeInTheDocument();
    expect(start).not.toHaveBeenCalled();
  });

  it("leaves a modified click to the browser, which opens a tab", () => {
    const start = lendViewTransitions();
    mount();
    // What the browser would do with it -- open a tab -- jsdom cannot.
    window.addEventListener("click", (event) => event.preventDefault(), { once: true });
    fireEvent.click(screen.getByRole("link", { name: "Open" }), { metaKey: true });

    expect(start).not.toHaveBeenCalled();
  });
});
