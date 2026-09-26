import { useEffect, useRef, type ComponentProps } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";

import { canMorph, GRAPH_SOURCE, morphInto, MORPH_STATE } from "@/lib/viewTransition";
import { graphHref, preloadGraph, type GraphTarget } from "./graphQueries";

/**
 * How long a pointer rests before its target is loaded. Long enough that
 * sweeping down a list of five does not ask for five graphs; short enough
 * that the load starts well before a click lands.
 */
const INTENT_MS = 100;

/**
 * A link into the graph that loads the graph on the way.
 *
 * Opening a graph used to wait on three things in turn after the click: the
 * page's code, React Flow's, and the graph itself. Here all three start when
 * the pointer settles on the link or the keyboard reaches it, so by the time
 * somebody commits the page is usually already there (DECISIONS.md §139).
 *
 * A plain click then grows what it was clicked from -- the nearest
 * `data-graph-source`, else the link -- into the next page's graph frame, where
 * the browser can and the reader has not asked for less motion (§140). An
 * ordinary `Link` otherwise: Back returns, and a middle or modified click opens
 * a tab as it always did.
 */
export function GraphLink({
  to,
  ...props
}: { to: GraphTarget } & Omit<ComponentProps<typeof Link>, "to">) {
  const client = useQueryClient();
  const navigate = useNavigate();
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);

  const preload = () => preloadGraph(client, to);
  const href = graphHref(to);

  return (
    <Link
      {...props}
      to={href}
      onClick={(event) => {
        props.onClick?.(event);
        const plain =
          event.button === 0 &&
          !event.metaKey &&
          !event.ctrlKey &&
          !event.shiftKey &&
          !event.altKey &&
          !props.target &&
          !props.reloadDocument;
        if (event.defaultPrevented || !plain || !canMorph()) return;
        event.preventDefault();
        preload();
        const source =
          event.currentTarget.closest<HTMLElement>(`[${GRAPH_SOURCE}]`) ?? event.currentTarget;
        morphInto(source, () => navigate(href, { state: MORPH_STATE }));
      }}
      onPointerEnter={(event) => {
        props.onPointerEnter?.(event);
        window.clearTimeout(timer.current);
        timer.current = window.setTimeout(preload, INTENT_MS);
      }}
      onPointerLeave={(event) => {
        props.onPointerLeave?.(event);
        window.clearTimeout(timer.current);
      }}
      onFocus={(event) => {
        props.onFocus?.(event);
        preload();
      }}
    />
  );
}
