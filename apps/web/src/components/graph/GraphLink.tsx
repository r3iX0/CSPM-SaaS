import { useEffect, useRef, type ComponentProps } from "react";
import { Link } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";

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
 * An ordinary `Link` otherwise: Back returns, and a middle click opens a tab.
 */
export function GraphLink({
  to,
  ...props
}: { to: GraphTarget } & Omit<ComponentProps<typeof Link>, "to">) {
  const client = useQueryClient();
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);

  const preload = () => preloadGraph(client, to);

  return (
    <Link
      {...props}
      to={graphHref(to)}
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
