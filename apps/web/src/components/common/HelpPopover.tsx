import { useState, type ReactNode } from "react";
import { CircleHelpIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { cn } from "@/lib/format";

/**
 * The reasoning a panel used to print under its own heading.
 *
 * Every section carried an epigram — "What the rules judged, in the abstract",
 * "Accepted risk is counted, never absorbed" — and ten of them stacked on one
 * page is ten sentences a reader scrolls past on every visit to reach the
 * numbers (docs/UI_REDESIGN.md §0). The writing was not the problem; printing
 * it permanently was. What is worth keeping moves here, where it is one click
 * away for the reader who wants it and invisible to the reader who does not.
 *
 * A `?` and nothing else by default: a panel title should carry the label, and
 * a control that needs its own sentence to be understood is the label failing.
 */
export function HelpPopover({
  label,
  title,
  children,
  align = "start",
  className,
}: {
  /** What the button says to a screen reader. Names the thing being explained. */
  label: string;
  /** Shown on the button when the affordance has to be visible, as on a page header. */
  title?: string;
  children: ReactNode;
  align?: "start" | "center" | "end";
  className?: string;
}) {
  const [open, setOpen] = useState(false);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger
        render={
          <Button
            variant={title ? "outline" : "ghost"}
            size={title ? "sm" : "icon-sm"}
            aria-label={title ? undefined : label}
            className={cn(
              !title && "text-muted-foreground hover:text-foreground",
              className,
            )}
          />
        }
      >
        {title ? (
          <>
            <CircleHelpIcon data-icon="inline-start" />
            {title}
          </>
        ) : (
          <CircleHelpIcon />
        )}
      </PopoverTrigger>

      <PopoverContent align={align} className="w-80 p-3.5">
        <p className="text-[13px] leading-relaxed text-muted-foreground">
          {children}
        </p>
      </PopoverContent>
    </Popover>
  );
}
