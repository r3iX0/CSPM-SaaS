import { useT } from "@/i18n";
import { setThemeChoice, useTheme, type ThemeChoice } from "@/lib/theme";
import { SHORTCUTS_EVENT, setSingleKeyShortcuts, useSingleKeyShortcuts } from "@/lib/keyboard";
import { OptionCard } from "@/components/settings/OptionCard";
import { SettingsSection } from "@/components/settings/SettingsSection";
import { Button } from "@/components/ui/button";
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldLabel,
  FieldLegend,
  FieldSet,
} from "@/components/ui/field";
import { RadioGroup } from "@/components/ui/radio-group";
import { Switch } from "@/components/ui/switch";

const THEMES: ThemeChoice[] = ["light", "dark", "system"];

/**
 * How Cleave looks and behaves in this browser (DECISIONS.md §207).
 *
 * The theme and the single-key shortcuts were each settable only where they
 * act -- a menu in the header, a switch inside the shortcuts sheet -- and a
 * reader looking for them looked here first. These are the same stores, not
 * copies: changing one here changes it there. Nothing is sent to the API;
 * the page says so, because a reader on a second machine would otherwise
 * expect to find their choice waiting.
 */
export function PreferencesSection() {
  const t = useT();
  const { choice } = useTheme();
  const singleKey = useSingleKeyShortcuts();

  return (
    <SettingsSection id="preferences" title={t.preferences.title} description={t.preferences.help}>
      <div className="flex flex-col gap-6 rounded-xl bg-card p-5 ring-1 ring-foreground/10">
        <FieldSet>
          <FieldLegend id="theme-legend" variant="label">
            {t.preferences.theme}
          </FieldLegend>
          <RadioGroup
            aria-labelledby="theme-legend"
            value={choice}
            onValueChange={(next) => setThemeChoice(next as ThemeChoice)}
            className="grid gap-2 sm:grid-cols-3"
          >
            {THEMES.map((theme) => (
              <OptionCard
                key={theme}
                id={`theme-${theme}`}
                value={theme}
                title={t.preferences.themes[theme]}
                description={t.preferences.themeHelp[theme]}
                checked={choice === theme}
              />
            ))}
          </RadioGroup>
        </FieldSet>

        <FieldSet>
          <FieldLegend variant="label">{t.preferences.keyboard}</FieldLegend>
          <Field orientation="horizontal">
            <FieldContent>
              <FieldLabel htmlFor="single-key-shortcuts">{t.preferences.singleKey}</FieldLabel>
              <FieldDescription>{t.preferences.singleKeyHelp}</FieldDescription>
            </FieldContent>
            <Switch
              id="single-key-shortcuts"
              checked={singleKey}
              onCheckedChange={(on) => setSingleKeyShortcuts(on)}
            />
          </Field>
          <div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => window.dispatchEvent(new Event(SHORTCUTS_EVENT))}
            >
              {t.preferences.allShortcuts}
            </Button>
          </div>
        </FieldSet>
      </div>
    </SettingsSection>
  );
}
