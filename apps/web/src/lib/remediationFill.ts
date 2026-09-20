/**
 * Filling a fix command's placeholders from the resource it is about.
 *
 * The rules write their CLI with angle-bracket placeholders -- `<rg>`,
 * `<account>` -- because a rule knows the shape of the fix and not the estate.
 * A finding does know the estate: it was raised on one resource, and that
 * resource's provider id states its subscription and resource group outright.
 * Filling those in turns a template the reader has to complete by hand into a
 * command they can check and run.
 *
 * Only what was observed is filled, and only where it cannot mean anything
 * else. The resource's own name fills the placeholder for its own kind --
 * `<account>` on a storage account, `<server>` on a SQL server -- and never a
 * placeholder for some other resource the command also names (`<rule>`,
 * `<user>`, a second `<name>`). Anything not filled stays in angle brackets,
 * which is the rule's original promise: a command never carries a value
 * CloudGuard made up.
 *
 * **Every value here came from somebody else's cloud, and its destination is a
 * shell.** CloudGuard never runs these commands -- the reader copies them --
 * which makes the quoting their problem unless it is handled here, and "the
 * provider's charset makes it hard" is not a property this side can check.
 * So a value is substituted bare only when it is unambiguously a single shell
 * word; anything else is single-quoted, and a value that cannot be quoted
 * safely at that position is left as the placeholder it was, reported as
 * unfilled. A command with a bracket still in it asks the reader for one
 * value. A command with an unquoted name in it asks them to run whatever the
 * name happened to contain.
 */

/** Which placeholders name the resource itself, by the neutral type. */
const OWN_NAME: Record<string, string[]> = {
  storage_account: ["account", "bucket"],
  sql_server: ["server"],
  postgresql_server: ["server"],
  key_vault: ["vault"],
  app_service: ["app"],
  virtual_machine: ["vm"],
  network_security_group: ["nsg"],
  virtual_network: ["vnet"],
};

/** `/subscriptions/{id}/resourceGroups/{rg}/...`, read case-insensitively as ARM does. */
const ARM_ID = /^\/subscriptions\/([^/]+)(?:\/resourceGroups\/([^/]+))?/i;

export function placeholderValues(
  resource: { name: string; resource_type: string; region: string | null },
  providerResourceId?: string | null,
): Record<string, string> {
  const values: Record<string, string> = {};

  for (const key of OWN_NAME[resource.resource_type] ?? []) {
    values[key] = resource.name;
  }
  if (resource.region) values.region = resource.region;

  const arm = providerResourceId ? ARM_ID.exec(providerResourceId) : null;
  if (arm) {
    values["subscription-id"] = arm[1];
    if (arm[2]) values.rg = arm[2];
    values["resource-id"] = providerResourceId as string;
  }

  return values;
}

/**
 * One shell word, needing no quoting: the shape every provider identifier this
 * fills actually has. Letters, digits, and the four punctuation marks that
 * appear in ARM ids, ARNs, regions and resource names -- none of which a shell
 * treats as anything but text.
 */
const BARE_WORD = /^[A-Za-z0-9._:/-]+$/;

/** Single-quoted for a POSIX shell, with embedded quotes broken out. */
function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

/**
 * Whether the placeholder at `index` sits inside a quoted section of the
 * command.
 *
 * Some rules put a placeholder inside a quoted JSON argument -- AWS's
 * `--bucket-logging-status '{"TargetBucket":"<log-bucket>"}'` is the example.
 * Quoting a value there would nest quotes inside quotes and produce a command
 * that is wrong rather than dangerous, so a value that needs quoting is not
 * substituted at such a position at all.
 */
function insideQuotes(command: string, index: number): boolean {
  let single = false;
  let double = false;
  for (let at = 0; at < index; at += 1) {
    const character = command[at];
    if (character === "'" && !double) single = !single;
    else if (character === '"' && !single) double = !double;
  }
  return single || double;
}

/** The command with every known placeholder replaced, and which ones were. */
export function fillPlaceholders(
  command: string,
  values: Record<string, string>,
): { text: string; filled: string[] } {
  const filled = new Set<string>();
  const text = command.replace(
    /<([a-z][a-z-]*)>/g,
    (whole, key: string, index: number) => {
      const value = values[key];
      if (value === undefined) return whole;
      // The ordinary case: a name, a region, an ARM id. Substituted as it
      // stands, so a filled command reads exactly as the rule wrote it.
      if (BARE_WORD.test(value)) {
        filled.add(key);
        return value;
      }
      // Anything else is not a shell word. It can be made one, unless the rule
      // already put this placeholder inside quotes -- in which case the honest
      // answer is the placeholder, for the reader to fill in themselves.
      if (insideQuotes(command, index)) return whole;
      filled.add(key);
      return shellQuote(value);
    },
  );
  return { text, filled: [...filled] };
}
