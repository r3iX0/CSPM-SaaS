import { describe, expect, it } from "vitest";
import { renderHook } from "@testing-library/react";

import { LAYOUT_ROW_LIMIT, listLayout, useValueChange } from "@/lib/motion";

describe("useValueChange", () => {
  it("counts nothing on mount", () => {
    const { result } = renderHook(() => useValueChange(71));
    expect(result.current).toEqual({ changes: 0, previous: undefined });
  });

  it("counts nothing when a render carries the same value", () => {
    const { result, rerender } = renderHook(({ value }) => useValueChange(value), {
      initialProps: { value: 71 },
    });
    rerender({ value: 71 });
    rerender({ value: 71 });
    expect(result.current.changes).toBe(0);
  });

  it("counts each change, in the render that carries it, with what it was", () => {
    const { result, rerender } = renderHook(({ value }) => useValueChange(value), {
      initialProps: { value: 71 },
    });
    rerender({ value: 74 });
    expect(result.current).toEqual({ changes: 1, previous: 71 });
    rerender({ value: 74 });
    expect(result.current).toEqual({ changes: 1, previous: 71 });
    rerender({ value: 69 });
    expect(result.current).toEqual({ changes: 2, previous: 74 });
  });
});

describe("listLayout", () => {
  it("moves a row only when the list's order changes", () => {
    const props = listLayout(["a", "b", "c"]);
    expect(props).toMatchObject({ layout: "position", layoutDependency: "a,b,c" });
    expect(listLayout(["c", "a", "b"])).toMatchObject({ layoutDependency: "c,a,b" });
  });

  it("leaves a long list still", () => {
    const ids = Array.from({ length: LAYOUT_ROW_LIMIT + 1 }, (_, index) => String(index));
    expect(listLayout(ids)).toEqual({});
  });
});
