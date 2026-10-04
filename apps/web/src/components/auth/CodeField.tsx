import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";

/** Digits in a code from an authenticator app. */
export const CODE_LENGTH = 6;

/**
 * The six digits from an authenticator app.
 *
 * `one-time-code` lets a phone offer the code it was just shown, and anything
 * that is not a digit is dropped as it is typed or pasted, so "123 456" from a
 * password manager arrives as the six digits Supabase checks.
 */
export function CodeField({
  id,
  label,
  value,
  onChange,
  autoFocus,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  autoFocus?: boolean;
}) {
  return (
    <Field>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <Input
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value.replace(/\D/g, "").slice(0, CODE_LENGTH))}
        inputMode="numeric"
        autoComplete="one-time-code"
        pattern={`[0-9]{${CODE_LENGTH}}`}
        maxLength={CODE_LENGTH}
        required
        // eslint-disable-next-line jsx-a11y/no-autofocus -- only where the code is the page's one question.
        autoFocus={autoFocus}
        className="max-w-48 font-mono tracking-[0.3em] tabular-nums"
      />
    </Field>
  );
}
