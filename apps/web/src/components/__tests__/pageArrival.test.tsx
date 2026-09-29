/**
 * A new page takes the keyboard to its heading, so the next Tab starts in the
 * page and a screen reader says where it arrived (WCAG 2.4.3).
 */
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Link, MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { PageTransition } from "@/components/PageTransition";

function Page({ title, next }: { title: string; next?: string }) {
  return (
    <>
      <h1>{title}</h1>
      {next && <Link to={next}>Open {next}</Link>}
    </>
  );
}

describe("arriving on a page", () => {
  it("focuses the new page's heading, and not the first page's", async () => {
    render(
      <MemoryRouter initialEntries={["/findings"]}>
        <main id="main-content" tabIndex={-1}>
          <PageTransition>
            <Routes>
              <Route path="/findings" element={<Page title="Findings" next="/risks" />} />
              <Route path="/risks" element={<Page title="Risks" />} />
            </Routes>
          </PageTransition>
        </main>
      </MemoryRouter>,
    );

    // Loaded, not navigated to: the browser already put the reader at the top.
    expect(screen.getByRole("heading", { name: "Findings" })).not.toHaveFocus();

    fireEvent.click(screen.getByRole("link", { name: "Open /risks" }));
    const heading = await screen.findByRole("heading", { name: "Risks" });
    await waitFor(() => expect(heading).toHaveFocus());
  });
});
