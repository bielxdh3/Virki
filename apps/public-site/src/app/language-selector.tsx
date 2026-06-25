import { LOCALE_OPTIONS } from "@bielos/ui";
import type { BielosLocale } from "@bielos/ui";
import { setLocalePreference } from "./actions";

type LanguageSelectorProps = {
  locale: BielosLocale;
  label: string;
  returnTo?: string;
};

export function LanguageSelector({ locale, label, returnTo = "/" }: LanguageSelectorProps) {
  return (
    <form className="language-selector" action={setLocalePreference}>
      <input type="hidden" name="returnTo" value={returnTo} />
      <label>
        <span>{label}</span>
        <select name="locale" defaultValue={locale} aria-label={label}>
          {LOCALE_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
      <button type="submit">OK</button>
    </form>
  );
}

