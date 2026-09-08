import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { cn } from "@/lib/format";

export type ToggleOption = { value: string; label: string };

/**
 * A short filter shown as its own choices rather than hidden behind a menu.
 *
 * Severity is the filter this exists for. It has four values plus "all", they
 * never change, and they are the thing a security engineer reaches for most —
 * so putting them behind a select cost two clicks and, more importantly, hid
 * which one was active behind a trigger the reader had to stop and read. Laid
 * out, the current filter is visible from across the room.
 *
 * Only for short, stable sets. Anything longer than about six values, or whose
 * options come from data, stays a `SelectField`: a row of toggles that wraps
 * onto three lines is worse than the menu it replaced.
 *
 * Single-select and never empty. Base UI's toggle group hands back an array and
 * will happily hand back an empty one when somebody clicks the active item
 * again; that would mean "no severity", which is not a filter anybody wants and
 * would show nothing at all. Deselecting keeps the current value instead.
 */
export function ToggleFilter({
  value,
  onValueChange,
  options,
  ariaLabel,
  className,
}: {
  value: string;
  onValueChange: (value: string) => void;
  options: ToggleOption[];
  /** What this filter is, for a reader who cannot see the row it sits in. */
  ariaLabel: string;
  className?: string;
}) {
  return (
    <ToggleGroup
      multiple={false}
      value={[value]}
      onValueChange={(next) => {
        const chosen = next[0];
        if (chosen) onValueChange(chosen);
      }}
      variant="outline"
      size="sm"
      spacing={0}
      aria-label={ariaLabel}
      className={cn("flex-wrap", className)}
    >
      {options.map((option) => (
        <ToggleGroupItem key={option.value} value={option.value}>
          {option.label}
        </ToggleGroupItem>
      ))}
    </ToggleGroup>
  );
}
