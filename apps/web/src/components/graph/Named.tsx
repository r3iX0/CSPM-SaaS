/**
 * A sentence with the assets in it set apart: the names are what a reader
 * scans for, the words between them are how they connect (§260).
 */
export function Named({ text, names }: { text: string; names: string[] }) {
  const wanted = [...new Set(names.filter((name) => name.length > 0))].sort(
    (a, b) => b.length - a.length,
  );
  const parts: { text: string; name: boolean }[] = [];
  let rest = text;
  while (rest.length > 0) {
    let at = -1;
    let found = "";
    for (const name of wanted) {
      const index = rest.indexOf(name);
      if (index >= 0 && (at < 0 || index < at)) {
        at = index;
        found = name;
      }
    }
    if (at < 0) {
      parts.push({ text: rest, name: false });
      break;
    }
    if (at > 0) parts.push({ text: rest.slice(0, at), name: false });
    parts.push({ text: found, name: true });
    rest = rest.slice(at + found.length);
  }
  return (
    <>
      {parts.map((part, index) =>
        part.name ? (
          <span key={index} className="font-semibold text-foreground">
            {part.text}
          </span>
        ) : (
          part.text
        ),
      )}
    </>
  );
}
