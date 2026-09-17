"""App Service rules: what a hosted web app accepts from the internet.

Web apps and function apps are both ``Microsoft.Web/sites`` and both answer on a
public hostname unless somebody turned that off, so every rule here is about the
edge of something already reachable. None of them is about the code running
behind it -- CloudGuard reads the site's settings and nothing it serves.

Two readings, and the rules are split along them. The listing says whether a
site insists on HTTPS and what identity it runs as; the configuration beneath
each site says what TLS it negotiates, whether FTP is open and whether a debugger
can attach. A role predating v7 reads neither, and one whose configuration read
fails for a single site costs that site the three configuration verdicts and
nothing else.
"""

from typing import Any, ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule

_UNREAD_CONFIG = (
    "The app's configuration could not be read. If this persists, the deployed "
    "scanner role may predate the permission that reads it."
)


def _site_evidence(resource: CloudResource) -> dict[str, Any]:
    return {
        "kind": resource.get("kind"),
        "public_network_access": resource.get("public_network_access"),
    }


class AzureAppServiceHttpsRule(SecurityRule):
    rule_id = "AZ-WEB-001"
    name = "Web app accepts plain HTTP"
    description = (
        "An App Service app answers unencrypted HTTP requests instead of redirecting "
        "them to HTTPS. Whatever a client sends on that first request -- a session "
        "cookie, a form, a token -- crosses the network readable."
    )
    category = "compute"
    severity = Severity.MEDIUM
    # A position on the path is needed, as for storage transport. Not higher,
    # because a browser that has been to the site over HTTPS before usually
    # goes back that way; not lower, because the first visit and every API
    # client do not.
    exploitability = 2
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.APP_SERVICE]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.APP_SERVICES,)
    estimated_effort_minutes = 10
    rationale = (
        "A site reachable over HTTP is one downgrade away from handing over its "
        "sessions. The fix is a single switch that makes App Service answer every "
        "HTTP request with a redirect, and no legitimate client needs the plain "
        "response."
    )
    remediation = (
        "Turn on HTTPS Only.\n\n"
        "Azure Portal: App Service > Settings > Configuration > General settings > "
        "HTTPS Only: On > Save.\n\n"
        "Azure CLI:\n"
        "  az webapp update --name <app> --resource-group <rg> --https-only true\n\n"
        "For a function app, `az functionapp update --set httpsOnly=true`."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="https_only",
                equals=True,
                describes="HTTP requests are redirected to HTTPS",
                # Verified against the built-in definition "App Service apps
                # should only be accessible over HTTPS", which matches on it.
                arm_alias="Microsoft.Web/sites/httpsOnly",
                terraform_attribute="https_only",
            ),
        ),
        cli=("az webapp update --name <app> --resource-group <rg> --https-only true",),
        policy_resource_type="Microsoft.Web/sites",
        # Audit rather than Deny. A deployment that sets HTTPS Only in a second
        # step would be refused at its first, and the built-in Microsoft ships
        # for this defaults to Audit for the same reason.
        policy_effect="Audit",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["9.2"],
        "ISO_27001": ["A.8.24"],
        "NIST_CSF": ["PR.DS-2"],
        "GDPR": ["32(1)(a)"],
        "NIST_800_53": ["SC-8"],
        "SOC2": ["CC6.7"],
        "PCI_DSS_4": ["4.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"App Service configuration unavailable: {failure}")

        https_only = resource.get("https_only")
        if https_only is None:
            return RuleResult.unknown("HTTPS Only setting missing from snapshot")

        evidence = {"https_only": https_only, **_site_evidence(resource)}
        if https_only is True:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} answers plain HTTP instead of redirecting to HTTPS",
        )


class AzureAppServiceTlsRule(SecurityRule):
    rule_id = "AZ-WEB-002"
    name = "Web app negotiates TLS below 1.2"
    description = (
        "An App Service app accepts TLS 1.0 or 1.1. Both are deprecated, both have "
        "practical downgrade attacks, and every supported client already speaks 1.2."
    )
    category = "compute"
    severity = Severity.MEDIUM
    exploitability = 2
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.APP_SERVICE]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.APP_SERVICE_CONFIGS,
    )
    estimated_effort_minutes = 10
    rationale = (
        "A minimum version of 1.0 does not mean clients use 1.0; it means an attacker "
        "positioned between them can make them. Raising the floor costs nothing for "
        "any browser or SDK released in the last decade."
    )
    remediation = (
        "Set the minimum inbound TLS version to 1.2.\n\n"
        "Azure Portal: App Service > Settings > Configuration > General settings > "
        "Minimum Inbound TLS Version: 1.2 > Save.\n\n"
        "Azure CLI:\n"
        "  az webapp config set --name <app> --resource-group <rg> --min-tls-version 1.2"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="min_tls_version",
                equals="1.2",
                also_accepts=("1.3",),
                describes="The app negotiates TLS 1.2 or better",
                terraform_attribute="site_config.minimum_tls_version",
            ),
        ),
        cli=(
            "az webapp config set --name <app> --resource-group <rg> --min-tls-version 1.2",
        ),
        notes=(
            "No policy is generated. The setting lives on the site's configuration "
            "child resource rather than on the site, and that alias has not been "
            "verified against a real deployment from here."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["9.3"],
        "ISO_27001": ["A.8.24"],
        "NIST_CSF": ["PR.DS-2"],
        "GDPR": ["32(1)(a)"],
        "NIST_800_53": ["SC-8"],
        "SOC2": ["CC6.7"],
        "PCI_DSS_4": ["4.2.1"],
    }

    ACCEPTABLE: ClassVar[frozenset[str]] = frozenset({"1.2", "1.3"})

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"App Service configuration unavailable: {failure}")

        version = resource.get("min_tls_version")
        if version is None:
            return RuleResult.unknown(_UNREAD_CONFIG)

        evidence = {
            "min_tls_version": version,
            "scm_min_tls_version": resource.get("scm_min_tls_version"),
            **_site_evidence(resource),
        }
        if str(version).strip() in self.ACCEPTABLE:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} accepts TLS {version}, below 1.2",
        )


class AzureAppServiceFtpRule(SecurityRule):
    rule_id = "AZ-WEB-003"
    name = "Web app accepts unencrypted FTP deployments"
    description = (
        "An App Service app accepts deployments over plain FTP. The deployment "
        "credential crosses the network in the clear, and whoever reads it can "
        "replace the site's code."
    )
    category = "compute"
    severity = Severity.HIGH
    # A position on the path, and then code execution on the site: the
    # credential is not a session, it is write access to what the app runs.
    exploitability = 3
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.APP_SERVICE]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.APP_SERVICE_CONFIGS,
    )
    estimated_effort_minutes = 15
    rationale = (
        "FTP is on by default for App Service and almost nobody deploys with it any "
        "more. What it leaves is a second way in to the site's files, authenticated by "
        "a publishing credential that is sent unencrypted every time it is used."
    )
    remediation = (
        "Turn FTP off, or allow FTPS only if something genuinely still deploys that "
        "way.\n\n"
        "Azure Portal: App Service > Settings > Configuration > General settings > "
        "FTP state: Disabled > Save.\n\n"
        "Azure CLI:\n"
        "  az webapp config set --name <app> --resource-group <rg> --ftps-state Disabled"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="ftps_state",
                equals="Disabled",
                also_accepts=("FtpsOnly",),
                describes="FTP is disabled, or allowed only over TLS",
                terraform_attribute="site_config.ftps_state",
            ),
        ),
        cli=(
            "az webapp config set --name <app> --resource-group <rg> --ftps-state Disabled",
        ),
        notes=(
            "No policy is generated, for the reason recorded on AZ-WEB-002: the "
            "setting is on the configuration child resource."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["9.10"],
        "ISO_27001": ["A.8.24", "A.5.17"],
        "NIST_CSF": ["PR.DS-2", "PR.AC-1"],
        "GDPR": ["32(1)(a)", "32(1)(b)"],
        "NIST_800_53": ["SC-8", "CM-7"],
        "SOC2": ["CC6.7", "CC8.1"],
        "PCI_DSS_4": ["4.2.1"],
    }

    SAFE: ClassVar[frozenset[str]] = frozenset({"disabled", "ftpsonly"})

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"App Service configuration unavailable: {failure}")

        state = resource.get("ftps_state")
        if state is None:
            return RuleResult.unknown(_UNREAD_CONFIG)

        evidence = {"ftps_state": state, **_site_evidence(resource)}
        if str(state).strip().lower() in self.SAFE:
            return RuleResult.passed(evidence)
        # Anything else permits plain FTP. ``AllAllowed`` is the only other value
        # Azure publishes; a value it adds later is not one this rule has any
        # reason to believe encrypts.
        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"{resource.name} accepts deployments over unencrypted FTP "
                f"(FTP state: {state})"
            ),
        )


class AzureAppServiceRemoteDebuggingRule(SecurityRule):
    rule_id = "AZ-WEB-004"
    name = "Web app has remote debugging switched on"
    description = (
        "An App Service app has remote debugging enabled, which opens additional ports "
        "on the host so a debugger can attach to the running process."
    )
    category = "compute"
    severity = Severity.MEDIUM
    # A publishing credential or a subscription role still gates attaching, so
    # not anonymous. What it adds is a live process to inspect -- memory,
    # secrets loaded at start-up -- for whoever holds either.
    exploitability = 2
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.APP_SERVICE]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.APP_SERVICE_CONFIGS,
    )
    estimated_effort_minutes = 5
    rationale = (
        "Remote debugging is meant to be switched on for an afternoon. A site on which "
        "it is still on is usually one somebody enabled for an investigation and "
        "forgot, and it stays open to the next person holding a credential."
    )
    remediation = (
        "Turn remote debugging off.\n\n"
        "Azure Portal: App Service > Settings > Configuration > General settings > "
        "Remote debugging: Off > Save.\n\n"
        "Azure CLI:\n"
        "  az webapp config set --name <app> --resource-group <rg> "
        "--remote-debugging-enabled false"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="remote_debugging",
                equals=False,
                describes="Remote debugging is off",
                terraform_attribute="site_config.remote_debugging_enabled",
            ),
        ),
        cli=(
            "az webapp config set --name <app> --resource-group <rg> "
            "--remote-debugging-enabled false",
        ),
        notes=(
            "No policy is generated, for the reason recorded on AZ-WEB-002: the "
            "setting is on the configuration child resource."
        ),
    )
    # No CIS mapping. CIS Azure 2.0 has no control for remote debugging, and
    # attributing this to a neighbouring one would put evidence under a
    # requirement it does not answer.
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.20"],
        "NIST_CSF": ["PR.PT-4"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["CM-7"],
        "SOC2": ["CC6.6"],
        # Inbound traffic restricted to what is necessary: remote debugging
        # opens listener ports that nothing in production needs. Not 2.2.1,
        # which is about having a configuration standard at all -- one setting
        # is evidence toward it, and claiming it would close a backlog item.
        "PCI_DSS_4": ["1.3.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"App Service configuration unavailable: {failure}")

        debugging = resource.get("remote_debugging")
        if debugging is None:
            return RuleResult.unknown(_UNREAD_CONFIG)

        evidence = {"remote_debugging": debugging, **_site_evidence(resource)}
        if debugging is not True:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} accepts remote debugger connections",
        )


class AzureAppServiceIdentityRule(SecurityRule):
    rule_id = "AZ-WEB-005"
    name = "Web app runs without a managed identity"
    description = (
        "An App Service app has no managed identity, so anything it calls -- a "
        "database, a storage account, a key vault -- has to be reached with a secret "
        "stored in the app's settings."
    )
    category = "compute"
    severity = Severity.LOW
    # Not exploitable by itself. It says where the credentials probably are,
    # and that they are the kind that does not expire.
    exploitability = 1
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.APP_SERVICE]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.APP_SERVICES,)
    estimated_effort_minutes = 60
    rationale = (
        "A managed identity is the difference between a connection string in an app "
        "setting and no secret at all. It is Low because an app that calls nothing "
        "needs no identity, and CloudGuard cannot see what the app calls -- but an app "
        "that calls anything and has none is holding a credential somewhere."
    )
    remediation = (
        "Give the app a system-assigned identity, grant that identity the roles it "
        "needs, and remove the secrets it replaces.\n\n"
        "Azure CLI:\n"
        "  az webapp identity assign --name <app> --resource-group <rg>\n\n"
        "Then move each connection string to identity-based access -- Key Vault "
        "references, Entra authentication to Azure SQL, RBAC on storage -- and delete "
        "the setting that held the secret."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="identity_type",
                equals="SystemAssigned",
                also_accepts=("UserAssigned", "SystemAssigned, UserAssigned"),
                describes="The app runs as a managed identity",
            ),
        ),
        cli=("az webapp identity assign --name <app> --resource-group <rg>",),
        notes=(
            "No policy is generated. An identity is only half of the fix -- the "
            "secrets it replaces have to go too -- and a policy that forced one onto "
            "every app would be satisfied by apps still holding every secret."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["9.5"],
        "ISO_27001": ["A.5.17"],
        "NIST_CSF": ["PR.AC-1"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["IA-5"],
        "SOC2": ["CC6.1"],
        "PCI_DSS_4": ["8.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"App Service configuration unavailable: {failure}")

        # Absent is "None" here, not unknown: ARM omits ``identity`` on a site
        # that has never had one, and the listing that omitted it arrived.
        identity = str(resource.get("identity_type") or "None")
        evidence = {"identity_type": identity, **_site_evidence(resource)}
        if "assigned" in identity.lower():
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} has no managed identity to authenticate as",
        )
