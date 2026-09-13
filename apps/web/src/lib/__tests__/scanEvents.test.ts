/**
 * Reading a server-sent event stream that arrives in arbitrary chunks.
 *
 * The network decides where a chunk ends, so the parser's one real job is to
 * never act on half an event.
 */
import { describe, expect, it } from "vitest";

import { parseEvents } from "@/lib/scanEvents";

describe("parseEvents", () => {
  it("reads complete events and keeps the unfinished tail", () => {
    const { events, rest } = parseEvents(
      'event: scan\ndata: {"status":"QUEUED"}\n\nevent: scan\ndata: {"sta',
    );
    expect(events).toEqual([{ event: "scan", data: '{"status":"QUEUED"}' }]);
    expect(rest).toBe('event: scan\ndata: {"sta');
  });

  it("completes an event once the rest of it arrives", () => {
    const first = parseEvents('event: scan\ndata: {"sta');
    const second = parseEvents(`${first.rest}tus":"EVALUATING"}\n\n`);
    expect(first.events).toEqual([]);
    expect(second.events).toEqual([{ event: "scan", data: '{"status":"EVALUATING"}' }]);
    expect(second.rest).toBe("");
  });

  it("ignores keep-alive comments", () => {
    const { events } = parseEvents(": keep-alive\n\nevent: end\ndata: {}\n\n");
    expect(events).toEqual([{ event: "end", data: "{}" }]);
  });

  it("accepts CRLF line endings", () => {
    const { events } = parseEvents("event: gone\r\ndata: {}\r\n\r\n");
    expect(events).toEqual([{ event: "gone", data: "{}" }]);
  });
});
