/**
 * The product's keyboard: lists move with j/k and open with Enter, pages are
 * two keys away, and none of it fires while somebody is typing.
 */
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { KeyboardShortcuts } from "@/components/layout/KeyboardShortcuts";
import { useRowNavigation } from "@/lib/keyboard";

function Where() {
  return <p data-testid="where">{useLocation().pathname}</p>;
}

function List() {
  const hrefs = ["/findings/a", "/findings/b", "/findings/c"];
  const active = useRowNavigation(hrefs);
  return (
    <>
      <input aria-label="Search findings" data-page-search />
      <ul>
        {hrefs.map((href, index) => (
          <li key={href} data-row-index={index} data-active={active === index}>
            {href}
          </li>
        ))}
      </ul>
    </>
  );
}

function mount() {
  return render(
    <MemoryRouter initialEntries={["/findings"]}>
      <KeyboardShortcuts />
      <Where />
      <Routes>
        <Route path="/findings" element={<List />} />
        <Route path="*" element={null} />
      </Routes>
    </MemoryRouter>,
  );
}

const key = (k: string, target: Element | Document = document) =>
  fireEvent.keyDown(target, { key: k });

describe("the keyboard", () => {
  it("moves through a list with j and k and opens the row with Enter", () => {
    mount();
    key("j");
    key("j");
    key("k");
    expect(screen.getByText("/findings/a")).toHaveAttribute("data-active", "true");

    key("j");
    key("Enter");
    expect(screen.getByTestId("where")).toHaveTextContent("/findings/b");
  });

  it("marks nothing until the keyboard is used", () => {
    mount();
    expect(document.querySelector('[data-active="true"]')).toBeNull();
  });

  it("stands down while somebody is typing", () => {
    mount();
    const search = screen.getByLabelText("Search findings");
    key("j", search);
    key("g", search);
    key("r", search);
    expect(document.querySelector('[data-active="true"]')).toBeNull();
    expect(screen.getByTestId("where")).toHaveTextContent("/findings");
  });

  it("goes to a page with g and a letter", () => {
    mount();
    key("g");
    key("r");
    expect(screen.getByTestId("where")).toHaveTextContent("/risks");
  });

  it("focuses the page's search with a slash", () => {
    mount();
    key("/");
    expect(screen.getByLabelText("Search findings")).toHaveFocus();
  });

  it("lists the shortcuts on a question mark", async () => {
    mount();
    key("?");
    expect(await screen.findByText("Keyboard shortcuts")).toBeInTheDocument();
    expect(screen.getByText("Next row")).toBeInTheDocument();
  });
});
