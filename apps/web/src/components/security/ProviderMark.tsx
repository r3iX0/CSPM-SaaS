import type { ReactNode } from "react";
import { CloudIcon } from "lucide-react";

import { cn } from "@/lib/format";

const NAMES: Record<string, string> = {
  azure: "Microsoft Azure",
  aws: "Amazon Web Services",
  gcp: "Google Cloud",
  kubernetes: "Kubernetes",
  docker: "Docker",
  github: "GitHub",
  gitlab: "GitLab",
};

/**
 * Outline glyphs for the platforms Cleave does not read yet, drawn in the same
 * 1.4 stroke on a 20px grid as the redesign's other marks. Shapes that suggest
 * the platform rather than reproduce its logo.
 */
const OUTLINES: Record<string, ReactNode> = {
  gcp: (
    <>
      <circle cx="10" cy="10" r="6.5" />
      <path d="M10 6.3 12.8 12H7.2Z" />
    </>
  ),
  kubernetes: <polygon points="10,3 16,6.5 16,13.5 10,17 4,13.5 4,6.5" />,
  docker: (
    <>
      <rect x="3.5" y="11" width="4" height="4" rx="0.8" />
      <rect x="8" y="11" width="4" height="4" rx="0.8" />
      <rect x="12.5" y="11" width="4" height="4" rx="0.8" />
      <rect x="8" y="6.5" width="4" height="4" rx="0.8" />
    </>
  ),
  github: (
    <>
      <circle cx="6" cy="5" r="1.6" />
      <circle cx="6" cy="15" r="1.6" />
      <circle cx="14" cy="10" r="1.6" />
      <path d="M6 6.6V13.4M7.5 10H12.4" />
    </>
  ),
  gitlab: <polygon points="10,3 17,10 10,17 3,10" />,
};

/**
 * Which cloud a connection reads.
 *
 * Lucide carries no brand marks, so these are small hand-drawn glyphs in
 * the current text colour -- simplified shapes that identify the provider,
 * not the vendors' official artwork, and deliberately monochrome so they sit
 * in the product's palette rather than bringing two brand colours into it. A
 * provider this does not know falls back to a plain cloud.
 *
 * Labelled with the provider's name, because a mark on its own is only
 * recognisable to somebody who already knows it.
 */
export function ProviderMark({
  provider,
  tile = false,
  className,
}: {
  provider: string | null | undefined;
  /**
   * Set in a 28px muted tile, as it stands at the head of a row on the
   * environments page and in the setup's first step.
   */
  tile?: boolean;
  className?: string;
}) {
  if (tile) {
    return (
      <span
        className={cn(
          "inline-flex size-7 shrink-0 items-center justify-center rounded-md bg-muted text-foreground",
          className,
        )}
      >
        <ProviderMark provider={provider} className="size-[15px]" />
      </span>
    );
  }

  const name = provider ? NAMES[provider] : undefined;
  const classes = cn("size-4 shrink-0", className);

  if (provider === "azure") {
    return (
      <svg viewBox="0 0 24 24" className={classes} role="img" aria-label={name}>
        <title>{name}</title>
        <path d="M9.6 3h5.3L8.3 21H3l6.6-18Z" fill="currentColor" />
        <path d="M15.5 7.2 21 21H9.4l7.1-2.1-3.9-4.5 2.9-7.2Z" fill="currentColor" opacity="0.6" />
      </svg>
    );
  }

  if (provider === "aws") {
    return (
      <svg viewBox="0 0 24 24" className={classes} role="img" aria-label={name}>
        <title>{name}</title>
        <path
          d="M2.5 14.5c5.4 3.6 13.5 3.6 19 0"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
        />
        <path
          d="m18.6 13.2 3 1.2-1.1 3"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d="M4 11.5 5.6 5.5h.8l1.6 6M4.6 9.5h2.8M9 5.5l1.2 6 1.3-4.5 1.3 4.5 1.2-6M19.8 6.2c-.4-.5-1-.7-1.6-.7-.9 0-1.6.5-1.6 1.3 0 1.8 3.4 1.2 3.4 3.2 0 .9-.8 1.5-1.8 1.5-.7 0-1.4-.3-1.8-.8"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    );
  }

  const outline = provider ? OUTLINES[provider] : undefined;
  if (outline) {
    return (
      <svg
        viewBox="0 0 20 20"
        className={classes}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
        role="img"
        aria-label={name}
      >
        <title>{name}</title>
        {outline}
      </svg>
    );
  }

  return <CloudIcon className={classes} aria-hidden />;
}
