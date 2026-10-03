import type { ReactNode } from "react";

import { cn } from "@/lib/format";
import { FieldLabel } from "@/components/ui/field";
import { RadioGroupItem } from "@/components/ui/radio-group";

/**
 * One choice in a `RadioGroup`, drawn as a card that says what it means.
 *
 * Settings asks several questions whose answers need a line of explanation --
 * which role, which kind of integration, which theme -- and a bare menu of
 * names leaves the reader to guess what each one does. The whole card is the
 * radio's label, so a click anywhere on it chooses.
 */
export function OptionCard({
  id,
  value,
  title,
  description,
  checked,
}: {
  id: string;
  value: string;
  title: ReactNode;
  description?: ReactNode;
  checked: boolean;
}) {
  return (
    <FieldLabel
      htmlFor={id}
      className={cn(
        "flex w-full cursor-pointer items-start gap-3 rounded-lg border px-3 py-2.5 font-normal transition-colors",
        checked ? "border-foreground bg-muted/40" : "hover:border-input",
      )}
    >
      <RadioGroupItem id={id} value={value} className="mt-0.5" />
      <span className="flex min-w-0 flex-col gap-0.5">
        <span className="text-body font-medium text-foreground">{title}</span>
        {description && <span className="text-meta text-muted-foreground">{description}</span>}
      </span>
    </FieldLabel>
  );
}
