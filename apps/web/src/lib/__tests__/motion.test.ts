import { describe, expect, it } from "vitest";
import { renderHook } from "@testing-library/react";

import { useValueChange } from "@/lib/motion";

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
