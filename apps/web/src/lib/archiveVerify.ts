import { unzipSync } from "fflate";

/**
 * Checking a sealed audit package's archive in the browser, without asking
 * Cleave whether it is genuine (DECISIONS.md §208, §218).
 *
 * Two claims are tested, both the ones the archive's README tells an auditor to
 * test with `sha256sum`: that `manifest.json` hashes to the value sealed when
 * the package was made, and that every file listed in `SHA256SUMS` hashes to
 * what it lists. The page does with `SubtleCrypto` what a person does in a
 * terminal, so the answer does not depend on Cleave's own `/verification`
 * route -- which can only say what Cleave says.
 *
 * What it does not test is whether the provider said what a payload holds;
 * that rests on Cleave having asked, and no hash can show it.
 */

export interface ArchiveCheck {
  /** SHA-256 of `manifest.json`, as computed here. */
  manifestSha256: string | null;
  /** Whether it equals the hash the package was sealed under. */
  manifestMatches: boolean;
  /** Files `SHA256SUMS` lists that were read and hashed. */
  checked: number;
  /** Listed files whose bytes do not hash to the listed value. */
  mismatched: string[];
  /** Listed files the zip does not hold. */
  missing: string[];
  /** Files the zip holds that `SHA256SUMS` does not list (apart from itself). */
  unlisted: string[];
  /** The archive has no `manifest.json` or no `SHA256SUMS`: it is not one of ours. */
  malformed: boolean;
}

export const MANIFEST = "manifest.json";
export const SUMS = "SHA256SUMS";

const HEX = /^[0-9a-f]{64}$/;

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  // A copy into a fresh buffer: `digest` wants a BufferSource, and a view onto
  // an inflated slice of a larger zip buffer is not one TypeScript accepts.
  const digest = await crypto.subtle.digest("SHA-256", new Uint8Array(bytes));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** `hash  path` lines, as `sha256sum -c` reads them. A line that is not one is ignored. */
export function parseSums(text: string): Map<string, string> {
  const sums = new Map<string, string>();
  for (const line of text.split("\n")) {
    const match = /^([0-9a-f]{64}) {2}(.+)$/.exec(line.trimEnd());
    if (match) sums.set(match[2], match[1]);
  }
  return sums;
}

/** The files in the zip, without inflating any of them. */
function listFiles(zip: Uint8Array): string[] {
  const names: string[] = [];
  unzipSync(zip, {
    filter: (file) => {
      if (!file.name.endsWith("/")) names.push(file.name);
      return false;
    },
  });
  return names;
}

/** One file, inflated alone, so memory holds a single payload and not the whole archive. */
function readFile(zip: Uint8Array, name: string): Uint8Array | null {
  const out = unzipSync(zip, { filter: (file) => file.name === name });
  return out[name] ?? null;
}

/**
 * Check an archive against the hash its package was sealed under.
 *
 * Everything in the zip sits under one folder named for the package, so paths
 * are read relative to it. `onProgress` is called after each listed file with
 * how many have been checked of how many there are, and the loop yields between
 * files so a package of thousands of payloads does not freeze the page.
 */
export async function checkArchive(
  archive: ArrayBuffer,
  sealedSha256: string,
  onProgress?: (done: number, total: number) => void,
): Promise<ArchiveCheck> {
  const zip = new Uint8Array(archive);
  const names = listFiles(zip);
  const root = names.find((name) => name.endsWith(`/${MANIFEST}`) || name === MANIFEST);
  const prefix = root ? root.slice(0, root.length - MANIFEST.length) : "";

  const manifest = readFile(zip, `${prefix}${MANIFEST}`);
  const sumsFile = readFile(zip, `${prefix}${SUMS}`);
  if (!manifest || !sumsFile) {
    return {
      manifestSha256: null,
      manifestMatches: false,
      checked: 0,
      mismatched: [],
      missing: [],
      unlisted: [],
      malformed: true,
    };
  }

  const manifestSha256 = await sha256Hex(manifest);
  const sums = parseSums(new TextDecoder().decode(sumsFile));

  const mismatched: string[] = [];
  const missing: string[] = [];
  let checked = 0;
  const total = sums.size;
  for (const [path, expected] of sums) {
    const bytes = readFile(zip, `${prefix}${path}`);
    if (!bytes) missing.push(path);
    else if ((await sha256Hex(bytes)) !== expected) mismatched.push(path);
    checked += 1;
    onProgress?.(checked, total);
    // Let the page paint: inflating and hashing a payload is not instant.
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  const listed = new Set(sums.keys());
  const unlisted = names
    .map((name) => name.slice(prefix.length))
    .filter((path) => path !== SUMS && !listed.has(path));

  return {
    manifestSha256,
    manifestMatches: HEX.test(sealedSha256) && manifestSha256 === sealedSha256,
    checked,
    mismatched,
    missing,
    unlisted,
    malformed: false,
  };
}

/** Whether an archive is exactly what was sealed: the headline and every file under it. */
export function archiveIsGenuine(check: ArchiveCheck): boolean {
  return (
    !check.malformed &&
    check.manifestMatches &&
    check.mismatched.length === 0 &&
    check.missing.length === 0 &&
    check.unlisted.length === 0
  );
}
