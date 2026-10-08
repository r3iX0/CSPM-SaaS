/**
 * Checking an audit archive in the browser (DECISIONS.md §208, §218).
 *
 * What must hold is the whole point of the page: an archive that is what was
 * sealed passes, and every way of not being so is named -- a changed payload, a
 * missing one, an extra one, a manifest that is not the sealed one, and a file
 * that is not one of ours at all. A check that passed any of them would be a
 * seal that proves nothing.
 */
import { strToU8, zipSync } from "fflate";
import { describe, expect, it } from "vitest";

import { archiveIsGenuine, checkArchive, parseSums, sha256Hex } from "../archiveVerify";

const ROOT = "soc-2-type-ii";

const sha = (text: string) => sha256Hex(strToU8(text));

interface Built {
  zip: ArrayBuffer;
  sealed: string;
}

interface Tamper {
  payload?: string;
  drop?: string;
  extra?: boolean;
  noSums?: boolean;
}

/** An archive laid out as the API writes one: one folder, `SHA256SUMS` listing the rest. */
async function archive(tamper: Tamper = {}): Promise<Built> {
  const manifest = '{"package":"sealed"}';
  const files: Record<string, string> = {
    "manifest.json": manifest,
    "gaps.csv": "control,reason\n",
    "evidence/payloads/aaa.json": '{"a":1}',
  };
  const lines = (
    await Promise.all(
      Object.entries(files).map(async ([path, text]) => `${await sha(text)}  ${path}\n`),
    )
  )
    .sort()
    .join("");

  const stored = Object.entries(files)
    .filter(([path]) => path !== tamper.drop)
    .map(([path, text]): [string, string] => [
      path,
      tamper.payload && path === "evidence/payloads/aaa.json" ? tamper.payload : text,
    ]);
  if (tamper.extra) stored.push(["evidence/payloads/zzz.json", "{}"]);
  if (!tamper.noSums) stored.push(["SHA256SUMS", lines]);

  const folder = Object.fromEntries(
    stored.map(([path, text]) => [`${ROOT}/${path}`, strToU8(text)]),
  );
  const bytes = zipSync(folder);
  const zip = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  return { zip, sealed: await sha(manifest) };
}

describe("checkArchive", () => {
  it("passes an archive that is what was sealed", async () => {
    const { zip, sealed } = await archive();
    const check = await checkArchive(zip, sealed);
    expect(check.manifestMatches).toBe(true);
    expect(check.checked).toBe(3);
    expect(archiveIsGenuine(check)).toBe(true);
  });

  it("reports progress as each listed file is read", async () => {
    const { zip, sealed } = await archive();
    const seen: [number, number][] = [];
    await checkArchive(zip, sealed, (done, total) => seen.push([done, total]));
    expect(seen).toEqual([
      [1, 3],
      [2, 3],
      [3, 3],
    ]);
  });

  it("names a payload whose bytes were changed", async () => {
    const { zip, sealed } = await archive({ payload: '{"a":2}' });
    const check = await checkArchive(zip, sealed);
    expect(check.mismatched).toEqual(["evidence/payloads/aaa.json"]);
    expect(archiveIsGenuine(check)).toBe(false);
  });

  it("names a listed file the zip does not hold", async () => {
    const { zip, sealed } = await archive({ drop: "gaps.csv" });
    const check = await checkArchive(zip, sealed);
    expect(check.missing).toEqual(["gaps.csv"]);
    expect(archiveIsGenuine(check)).toBe(false);
  });

  it("names a file the sums do not list", async () => {
    const { zip, sealed } = await archive({ extra: true });
    const check = await checkArchive(zip, sealed);
    expect(check.unlisted).toEqual(["evidence/payloads/zzz.json"]);
    expect(archiveIsGenuine(check)).toBe(false);
  });

  it("fails a manifest that is not the one sealed, though the sums agree with it", async () => {
    // The archive's own sums are consistent here; the headline claim is the
    // sealed hash, which the archive cannot choose.
    const { zip } = await archive();
    const check = await checkArchive(zip, await sha("some other manifest"));
    expect(check.manifestMatches).toBe(false);
    expect(check.mismatched).toEqual([]);
    expect(archiveIsGenuine(check)).toBe(false);
  });

  it("rejects a sealed value that is not a hash", async () => {
    const { zip } = await archive();
    const check = await checkArchive(zip, "not-a-hash");
    expect(check.manifestMatches).toBe(false);
  });

  it("says an archive without SHA256SUMS is not one of ours", async () => {
    const { zip, sealed } = await archive({ noSums: true });
    const check = await checkArchive(zip, sealed);
    expect(check.malformed).toBe(true);
    expect(archiveIsGenuine(check)).toBe(false);
  });
});

describe("parseSums", () => {
  it("reads sha256sum's format and ignores anything else", () => {
    const hash = "a".repeat(64);
    const sums = parseSums(`${hash}  evidence/a b.json\nnot a line\n${"b".repeat(63)}  short\n`);
    expect([...sums]).toEqual([["evidence/a b.json", hash]]);
  });
});
