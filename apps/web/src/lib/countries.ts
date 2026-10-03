/**
 * Countries by their ISO 3166-1 alpha-2 code, named in the reader's words.
 *
 * The organization's country is stored as the two-letter code (the API
 * upper-cases it), and the settings page used to ask for the code itself:
 * "AL" is Albania, but a reader has to know that. The codes are listed here
 * and the names come from the browser's own `Intl.DisplayNames`, so there is
 * no table of names to keep and no library to load for one (DECISIONS.md §207).
 */
const CODES =
  "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ " +
  "BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM " +
  "DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS " +
  "GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN " +
  "KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ " +
  "MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM " +
  "PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV " +
  "SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI " +
  "VN VU WF WS XK YE YT ZA ZM ZW";

export interface Country {
  readonly code: string;
  readonly name: string;
}

let names: Intl.DisplayNames | null = null;

/** The country's name, or the code itself where the browser has none for it. */
export function countryName(code: string): string {
  try {
    names ??= new Intl.DisplayNames(["en"], { type: "region" });
    return names.of(code.toUpperCase()) ?? code;
  } catch {
    // An engine without DisplayNames, or a code it refuses: the code still
    // says which country it is.
    return code;
  }
}

let sorted: readonly Country[] | null = null;

/** Every country, alphabetically by name. Built once, on first use. */
export function countries(): readonly Country[] {
  sorted ??= CODES.split(" ")
    .map((code) => ({ code, name: countryName(code) }))
    .sort((a, b) => a.name.localeCompare(b.name));
  return sorted;
}
