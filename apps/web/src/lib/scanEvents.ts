import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { API_URL, auth } from "@/lib/api";
import type { ScanDetail } from "@/lib/types";

export type StreamEvent = { event: string; data: string };

/**
 * Split a server-sent event buffer into complete events and the unfinished tail.
 *
 * A network chunk can end anywhere -- mid-line, mid-JSON -- so whatever follows
 * the last blank line is handed back to be prefixed to the next chunk rather
 * than parsed. Comment lines (": keep-alive") carry nothing and are dropped.
 */
export function parseEvents(buffer: string): { events: StreamEvent[]; rest: string } {
  const blocks = buffer.split(/\r?\n\r?\n/);
  const rest = blocks.pop() ?? "";
  const events: StreamEvent[] = [];

  for (const block of blocks) {
    let name = "message";
    const data: string[] = [];
    for (const line of block.split(/\r?\n/)) {
      if (!line || line.startsWith(":")) continue;
      const colon = line.indexOf(":");
      const field = colon === -1 ? line : line.slice(0, colon);
      let value = colon === -1 ? "" : line.slice(colon + 1);
      if (value.startsWith(" ")) value = value.slice(1);
      if (field === "event") name = value;
      else if (field === "data") data.push(value);
    }
    if (data.length > 0 || name !== "message") {
      events.push({ event: name, data: data.join("\n") });
    }
  }

  return { events, rest };
}

/**
 * Follow a scan over `GET /scans/{id}/events`, writing each state into the
 * `["scan-detail", id]` query the pipeline already renders.
 *
 * Returns whether the stream is live, so the caller can stop polling while it
 * is and resume the moment it is not. The stream is an optimisation over the
 * poll, never a replacement for it: a proxy that buffers, a network that drops,
 * or the server's own time ceiling all end here in polling, and nothing on
 * screen depends on which one delivered the state.
 *
 * `fetch` rather than `EventSource`, because the bearer token lives in memory
 * and `EventSource` cannot send an Authorization header.
 */
export function useScanEvents(scanId: string): boolean {
  const queryClient = useQueryClient();
  const [live, setLive] = useState(false);

  useEffect(() => {
    if (typeof TextDecoder === "undefined") return;
    const controller = new AbortController();
    let active = true;

    const follow = async () => {
      try {
        const headers = new Headers({ Accept: "text/event-stream" });
        if (auth.token) headers.set("Authorization", `Bearer ${auth.token}`);
        if (auth.organizationId) headers.set("X-Organization-Id", auth.organizationId);

        const response = await fetch(`${API_URL}/api/v1/scans/${scanId}/events`, {
          headers,
          signal: controller.signal,
        });
        const body = response.body;
        if (!response.ok || !body || typeof body.getReader !== "function") return;

        if (active) setLive(true);
        const reader = body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        for (;;) {
          const { done, value } = await reader.read();
          if (done) return;
          buffer += decoder.decode(value, { stream: true });
          const parsed = parseEvents(buffer);
          buffer = parsed.rest;

          for (const item of parsed.events) {
            if (item.event === "scan") {
              queryClient.setQueryData<ScanDetail>(
                ["scan-detail", scanId],
                JSON.parse(item.data) as ScanDetail,
              );
            } else if (item.event === "gone" || item.event === "end") {
              await queryClient.invalidateQueries({ queryKey: ["scan-detail", scanId] });
              return;
            }
          }
        }
      } catch {
        // Aborted on unmount, or the connection failed. Either way polling
        // takes over; there is nothing to tell the reader.
      } finally {
        if (active) setLive(false);
      }
    };

    void follow();
    return () => {
      active = false;
      controller.abort();
    };
  }, [scanId, queryClient]);

  return live;
}
