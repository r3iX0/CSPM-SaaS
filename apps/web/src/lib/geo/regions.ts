/**
 * Where each cloud region is, for drawing it — and what to call it.
 *
 * The API returns region *codes* and nothing about geography, deliberately:
 * a coordinate is a drawing concern, and the codes are what the provider said
 * (DECISIONS.md §113). The two clouds' codes never collide — Azure's have no
 * hyphens and AWS's always do — so one table serves both.
 *
 * A point is the metro the provider names for the region, to about a degree.
 * That is the resolution of the map it is drawn on; claiming more would be
 * precision the map cannot show and the provider does not publish.
 *
 * A code missing from here is not guessed at. It is listed by its own code and
 * left off the map, because a dot in the wrong country is worse than no dot —
 * and a region nobody has added yet is exactly the one somebody should notice.
 */
export interface RegionInfo {
  /** What the provider's own console calls it. */
  name: string;
  /** Where it is, in words a reader can place. */
  place: string;
  lat: number;
  lon: number;
}

const r = (name: string, place: string, lat: number, lon: number): RegionInfo => ({
  name,
  place,
  lat,
  lon,
});

export const REGIONS: Readonly<Record<string, RegionInfo>> = {
  // ---------------------------------------------------------------- Azure
  eastus: r("East US", "Virginia", 37.4, -79.8),
  eastus2: r("East US 2", "Virginia", 36.7, -78.4),
  centralus: r("Central US", "Iowa", 41.6, -93.6),
  northcentralus: r("North Central US", "Illinois", 41.9, -87.6),
  southcentralus: r("South Central US", "Texas", 29.4, -98.5),
  westcentralus: r("West Central US", "Wyoming", 41.1, -104.8),
  westus: r("West US", "California", 37.8, -122.4),
  westus2: r("West US 2", "Washington", 47.2, -119.9),
  westus3: r("West US 3", "Arizona", 33.4, -112.1),
  canadacentral: r("Canada Central", "Toronto", 43.7, -79.4),
  canadaeast: r("Canada East", "Quebec City", 46.8, -71.2),
  mexicocentral: r("Mexico Central", "Querétaro", 20.6, -100.4),
  brazilsouth: r("Brazil South", "São Paulo", -23.5, -46.6),
  brazilsoutheast: r("Brazil Southeast", "Rio de Janeiro", -22.9, -43.2),
  northeurope: r("North Europe", "Ireland", 53.3, -6.3),
  westeurope: r("West Europe", "Netherlands", 52.4, 4.9),
  uksouth: r("UK South", "London", 51.5, -0.1),
  ukwest: r("UK West", "Cardiff", 51.5, -3.2),
  francecentral: r("France Central", "Paris", 48.9, 2.4),
  francesouth: r("France South", "Marseille", 43.3, 5.4),
  germanywestcentral: r("Germany West Central", "Frankfurt", 50.1, 8.7),
  germanynorth: r("Germany North", "Berlin", 52.5, 13.4),
  switzerlandnorth: r("Switzerland North", "Zürich", 47.4, 8.5),
  switzerlandwest: r("Switzerland West", "Geneva", 46.2, 6.1),
  norwayeast: r("Norway East", "Oslo", 59.9, 10.8),
  norwaywest: r("Norway West", "Stavanger", 59.0, 5.7),
  swedencentral: r("Sweden Central", "Gävle", 60.7, 17.1),
  polandcentral: r("Poland Central", "Warsaw", 52.2, 21.0),
  italynorth: r("Italy North", "Milan", 45.5, 9.2),
  spaincentral: r("Spain Central", "Madrid", 40.4, -3.7),
  uaenorth: r("UAE North", "Dubai", 25.3, 55.3),
  uaecentral: r("UAE Central", "Abu Dhabi", 24.5, 54.4),
  qatarcentral: r("Qatar Central", "Doha", 25.3, 51.5),
  israelcentral: r("Israel Central", "Israel", 31.5, 34.8),
  southafricanorth: r("South Africa North", "Johannesburg", -26.2, 28.0),
  southafricawest: r("South Africa West", "Cape Town", -34.0, 18.5),
  centralindia: r("Central India", "Pune", 18.6, 73.9),
  southindia: r("South India", "Chennai", 13.1, 80.3),
  westindia: r("West India", "Mumbai", 19.1, 72.9),
  eastasia: r("East Asia", "Hong Kong", 22.3, 114.2),
  southeastasia: r("Southeast Asia", "Singapore", 1.3, 103.8),
  japaneast: r("Japan East", "Tokyo", 35.7, 139.8),
  japanwest: r("Japan West", "Osaka", 34.7, 135.5),
  koreacentral: r("Korea Central", "Seoul", 37.6, 127.0),
  koreasouth: r("Korea South", "Busan", 35.2, 129.0),
  indonesiacentral: r("Indonesia Central", "Jakarta", -6.2, 106.8),
  malaysiawest: r("Malaysia West", "Kuala Lumpur", 3.1, 101.7),
  australiaeast: r("Australia East", "Sydney", -33.9, 151.2),
  australiasoutheast: r("Australia Southeast", "Melbourne", -37.8, 145.0),
  australiacentral: r("Australia Central", "Canberra", -35.3, 149.1),
  australiacentral2: r("Australia Central 2", "Canberra", -35.3, 149.1),
  newzealandnorth: r("New Zealand North", "Auckland", -36.8, 174.8),

  // ------------------------------------------------------------------ AWS
  "us-east-1": r("US East (N. Virginia)", "Virginia", 38.9, -77.5),
  "us-east-2": r("US East (Ohio)", "Ohio", 40.0, -83.0),
  "us-west-1": r("US West (N. California)", "California", 37.4, -121.9),
  "us-west-2": r("US West (Oregon)", "Oregon", 45.8, -119.7),
  "ca-central-1": r("Canada (Central)", "Montréal", 45.5, -73.6),
  "ca-west-1": r("Canada West (Calgary)", "Calgary", 51.0, -114.1),
  "mx-central-1": r("Mexico (Central)", "Querétaro", 20.6, -100.4),
  "sa-east-1": r("South America (São Paulo)", "São Paulo", -23.5, -46.6),
  "eu-west-1": r("Europe (Ireland)", "Ireland", 53.3, -6.3),
  "eu-west-2": r("Europe (London)", "London", 51.5, -0.1),
  "eu-west-3": r("Europe (Paris)", "Paris", 48.9, 2.4),
  "eu-central-1": r("Europe (Frankfurt)", "Frankfurt", 50.1, 8.7),
  "eu-central-2": r("Europe (Zurich)", "Zürich", 47.4, 8.5),
  "eu-north-1": r("Europe (Stockholm)", "Stockholm", 59.3, 18.1),
  "eu-south-1": r("Europe (Milan)", "Milan", 45.5, 9.2),
  "eu-south-2": r("Europe (Spain)", "Aragón", 41.6, -0.9),
  "me-south-1": r("Middle East (Bahrain)", "Bahrain", 26.1, 50.6),
  "me-central-1": r("Middle East (UAE)", "UAE", 25.2, 55.3),
  "il-central-1": r("Israel (Tel Aviv)", "Tel Aviv", 32.1, 34.8),
  "af-south-1": r("Africa (Cape Town)", "Cape Town", -33.9, 18.4),
  "ap-south-1": r("Asia Pacific (Mumbai)", "Mumbai", 19.1, 72.9),
  "ap-south-2": r("Asia Pacific (Hyderabad)", "Hyderabad", 17.4, 78.5),
  "ap-east-1": r("Asia Pacific (Hong Kong)", "Hong Kong", 22.3, 114.2),
  "ap-east-2": r("Asia Pacific (Taipei)", "Taipei", 25.0, 121.5),
  "ap-southeast-1": r("Asia Pacific (Singapore)", "Singapore", 1.3, 103.8),
  "ap-southeast-2": r("Asia Pacific (Sydney)", "Sydney", -33.9, 151.2),
  "ap-southeast-3": r("Asia Pacific (Jakarta)", "Jakarta", -6.2, 106.8),
  "ap-southeast-4": r("Asia Pacific (Melbourne)", "Melbourne", -37.8, 145.0),
  "ap-southeast-5": r("Asia Pacific (Malaysia)", "Kuala Lumpur", 3.1, 101.7),
  "ap-southeast-7": r("Asia Pacific (Thailand)", "Bangkok", 13.8, 100.5),
  "ap-northeast-1": r("Asia Pacific (Tokyo)", "Tokyo", 35.7, 139.7),
  "ap-northeast-2": r("Asia Pacific (Seoul)", "Seoul", 37.6, 127.0),
  "ap-northeast-3": r("Asia Pacific (Osaka)", "Osaka", 34.7, 135.5),
};

/** What a link says for "not tied to a region"; the API's `NO_REGION`. */
export const NO_REGION = "none";

/** The API's spelling of a region: lower case, no spaces. */
export const regionKey = (code: string) => code.replace(/\s+/g, "").toLowerCase();

export const regionInfo = (code: string): RegionInfo | undefined => REGIONS[regionKey(code)];

/** A region's name for a sentence or a menu, falling back to its code. */
export function regionLabel(code: string | null): string {
  if (code === null || code === NO_REGION) return "Not tied to a region";
  return regionInfo(code)?.name ?? code;
}
