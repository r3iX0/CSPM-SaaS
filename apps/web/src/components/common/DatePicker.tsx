import { useState } from "react";
import { CalendarIcon, XIcon } from "lucide-react";

import { useT } from "@/i18n";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Calendar } from "@/components/ui/calendar";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";

/** A day as the API sends it (`YYYY-MM-DD`), read in the reader's own time zone. */
function parseDay(value: string): Date | undefined {
  const [year, month, day] = value.split("-").map(Number);
  if (year === undefined || month === undefined || day === undefined) return undefined;
  const date = new Date(year, month - 1, day);
  return Number.isFinite(date.getTime()) ? date : undefined;
}

/** A picked day back as `YYYY-MM-DD`, from its local parts so no time zone moves it. */
function formatDayValue(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

/**
 * One day, picked from a calendar in a popover.
 *
 * The browser's own date input drew its own control in its own locale's
 * order (`dd.mm.yyyy`), and matched nothing else on the page (DECISIONS.md
 * §223). The value stays the API's `YYYY-MM-DD` string, `""` for none.
 */
export function DatePicker({
  id,
  value,
  onChange,
  min,
  disabled = false,
  className,
}: {
  id?: string;
  /** `YYYY-MM-DD`, or `""` when no day is set. */
  value: string;
  /** The new day as `YYYY-MM-DD`, or `null` when it is cleared. */
  onChange: (value: string | null) => void;
  /** The earliest day that may be picked, as `YYYY-MM-DD`. */
  min?: string;
  disabled?: boolean;
  className?: string;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const selected = value ? parseDay(value) : undefined;
  const earliest = min ? parseDay(min) : undefined;

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger
        render={
          <Button
            id={id}
            type="button"
            variant="outline"
            disabled={disabled}
            className={cn("w-40 justify-start font-normal", className)}
          />
        }
      >
        <CalendarIcon data-icon="inline-start" className="text-muted-foreground" aria-hidden />
        {selected ? (
          selected.toLocaleDateString(undefined, {
            day: "numeric",
            month: "short",
            year: "numeric",
          })
        ) : (
          <span className="text-muted-foreground">{t.common.pickDate}</span>
        )}
      </PopoverTrigger>
      <PopoverContent align="start" className="w-auto p-0">
        <Calendar
          mode="single"
          selected={selected}
          defaultMonth={selected ?? earliest}
          disabled={earliest ? { before: earliest } : undefined}
          onSelect={(date) => {
            if (!date) return;
            onChange(formatDayValue(date));
            setOpen(false);
          }}
        />
        {selected && (
          <div className="border-t p-2">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="w-full text-muted-foreground"
              onClick={() => {
                onChange(null);
                setOpen(false);
              }}
            >
              <XIcon data-icon="inline-start" aria-hidden />
              {t.common.clearDate}
            </Button>
          </div>
        )}
      </PopoverContent>
    </Popover>
  );
}
