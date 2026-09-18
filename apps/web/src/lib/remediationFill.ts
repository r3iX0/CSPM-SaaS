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

/** The command with every known placeholder replaced, and which ones were. */
export function fillPlaceholders(
  command: string,
  values: Record<string, string>,
): { text: string; filled: string[] } {
  const filled = new Set<string>();
  const text = command.replace(/<([a-z][a-z-]*)>/g, (whole, key: string) => {
    const value = values[key];
    if (value === undefined) return whole;
    filled.add(key);
    return value;
  });
  return { text, filled: [...filled] };
}
