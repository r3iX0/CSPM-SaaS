import type { ReactNode } from "react";

import { EXPLAIN_ICON } from "@/lib/icons";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";

const Explain = EXPLAIN_ICON;

/**
 * The longer explanation, a question mark away (DECISIONS.md §166).
 *
 * The page says what a thing is in one line; why it is, how it is measured,
 * what it does not claim is here, for the reader who asks. It is a button that
 * opens a popover rather than a hover tooltip, so it is reached by Tab and read
 * by a touch screen the same as by a pointer, and it scales out of the button
 * that opened it (the popover's `--transform-origin`), so the eye follows it.
 *
 * Copy written for one belongs under a key ending `Explain` in `en.ts`: the
 * copy budget test lets those run long, and only those.
 */
export function InfoTip({
  label,
  children,
  align = "start",
  size = "icon-xs",
  className,
  contentClassName,
}: {
  /** The button's accessible name, which says what it explains: "About coverage". */
  label: string;
  /** What it opens. */
  children: ReactNode;
  align?: "start" | "center" | "end";
  size?: "icon-xs" | "icon-sm";
  className?: string;
  contentClassName?: string;
}) {
  return (
    <Popover>
      <PopoverTrigger
        render={
          <Button
            variant="ghost"
            size={size}
            aria-label={label}
            className={cn("text-muted-foreground", className)}
          >
            <Explain />
          </Button>
        }
      />
      <PopoverContent
        align={align}
        aria-label={label}
        className={cn("w-72 text-meta leading-relaxed", contentClassName)}
      >
        {children}
      </PopoverContent>
    </Popover>
  );
}
