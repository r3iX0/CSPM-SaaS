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
