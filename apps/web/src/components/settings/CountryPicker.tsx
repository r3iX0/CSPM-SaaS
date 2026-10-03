import { useState } from "react";
import { ChevronsUpDownIcon } from "lucide-react";

import { useT } from "@/i18n";
import { countries, countryName } from "@/lib/countries";
import { Button } from "@/components/ui/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";

/**
 * A country, chosen by name and stored as its two-letter code.
 *
 * Searchable, because two hundred and fifty names in a plain menu is a scroll
 * hunt; matched on the name and the code together, so "AL" and "Alb" both
 * find Albania. `id` lands on the trigger, so the field's label names it.
 */
export function CountryPicker({
  id,
  value,
  onChange,
}: {
  id: string;
  /** The code, or "" for none. */
  value: string;
  onChange: (code: string) => void;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);

  const choose = (code: string) => {
    onChange(code);
    setOpen(false);
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger
        render={
          <Button
            id={id}
            type="button"
            variant="outline"
            role="combobox"
            aria-expanded={open}
            className="w-full justify-between font-normal"
          />
        }
      >
        {value ? (
          <span className="truncate">
            {countryName(value)}{" "}
            <span className="font-mono text-meta text-muted-foreground">{value}</span>
          </span>
        ) : (
          <span className="text-muted-foreground">{t.settings.countryNone}</span>
        )}
        <ChevronsUpDownIcon className="text-muted-foreground" />
      </PopoverTrigger>
      <PopoverContent align="start" className="w-72 p-0">
        <Command>
          <CommandInput
            placeholder={t.settings.countrySearch}
            aria-label={t.settings.countrySearch}
          />
          <CommandList>
            <CommandEmpty>{t.settings.countryEmpty}</CommandEmpty>
            <CommandGroup>
              <CommandItem
                value={t.settings.countryNone}
                data-checked={value === ""}
                onSelect={() => choose("")}
              >
                <span className="text-muted-foreground">{t.settings.countryNone}</span>
              </CommandItem>
              {countries().map((country) => (
                <CommandItem
                  key={country.code}
                  value={`${country.name} ${country.code}`}
                  data-checked={value === country.code}
                  onSelect={() => choose(country.code)}
                >
                  <span className="truncate">{country.name}</span>
                  <span className="font-mono text-meta text-muted-foreground">{country.code}</span>
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
