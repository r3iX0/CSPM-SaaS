"""Tenant settings the frameworks ask about and no rule answered (section 204).

Every rule here is AGGREGATE over ``RuleContext.controls`` like the tenant
policy rules of section 172, and UNKNOWN whenever its reading failed or never
arrived. Most read Conditional Access and directory settings already collected;
device registration and access reviews read the two Graph permissions section
204 added to consent, and the subscription policy is read from ARM at the
tenant scope.

No policy is generated for any of them: these are directory settings, not
resource properties.
"""

from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, RuleScope, Severity
from app.domain.resource import CloudResource
from app.remediation import RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule

_DIRECTORY_SETTING = (
    "No policy is generated and none can be: this is a directory setting in Entra ID "
    "rather than a resource property, so no policyRule can express it."
)
_CA = (AzureEvidence.CONDITIONAL_ACCESS_POLICIES,)
_LIST_POLICIES = (
    "az rest --method GET --url "
    "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
)
_AUTHENTICATION = {
    "ISO_27001": ["A.5.17"],
    "NIST_CSF": ["PR.AC-7"],
    "GDPR": ["32(1)(b)"],
    "NIST_800_53": ["IA-2"],
    "SOC2": ["CC6.1"],
    "PCI_DSS_4": ["8.4.2"],
}
_ACCESS = {
    "ISO_27001": ["A.5.15", "A.5.18"],
    "NIST_CSF": ["PR.AC-1", "PR.AC-4"],
    "GDPR": ["32(1)(b)"],
    "NIST_800_53": ["AC-2"],
    "SOC2": ["CC6.2"],
    "PCI_DSS_4": ["7.2.1"],
}


def _directory_spec(cli: str = _LIST_POLICIES) -> RemediationSpec:
    return RemediationSpec(expected=(), cli=(cli,), notes=_DIRECTORY_SETTING)


class _TenantSettingRule(SecurityRule):
    """One tenant control, true when the tenant is defended."""

    category = "identity"
    scope = RuleScope.AGGREGATE
    applies_to: ClassVar[list[ResourceType]] = []
    control: ClassVar[str] = ""
    # The control readings shown as evidence, where the verdict combines more
    # than one.
    shown: ClassVar[tuple[str, ...]] = ()
    failure: ClassVar[str] = ""
    remediation_spec: ClassVar[RemediationSpec | None] = None

    def _verdict(self, context: RuleContext) -> bool | None:
        value = context.controls.get(self.control)
        return value if isinstance(value, bool) else None

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Tenant setting unavailable: {failure}")
        verdict = self._verdict(context)
        evidence = {key: context.controls.get(key) for key in self.shown or (self.control,)}
        if verdict is None:
            return RuleResult.unknown(f"The tenant's {self.control} was not read")
        if verdict:
            return RuleResult.passed(evidence)
        return RuleResult.failed(evidence=evidence, message=self.failure)


class AzureAdminMfaPolicyRule(_TenantSettingRule):
    rule_id = "AZ-ID-023"
    name = "Administrators are not required to use multi-factor authentication"
    description = (
        "No security default and no enabled Conditional Access policy requires a second "
        "factor of every user or of the Global Administrator role for every application."
    )
    severity = Severity.HIGH
    exploitability = 4
    estimated_effort_minutes = 30
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.SECURITY_DEFAULTS,
        AzureEvidence.CONDITIONAL_ACCESS_POLICIES,
    )
    control = "administrator_mfa"
    failure = "No policy requires administrators to use a second factor"
    remediation_spec = _directory_spec()
    rationale = (
        "Administrators are the accounts an attacker sprays first. A policy on the roles "
        "themselves covers the next administrator too, before anyone remembers to add "
        "them to a group."
    )
    remediation = (
        "Create a Conditional Access policy: Users: Directory roles (Global "
        "Administrator and the other privileged roles) > Target resources: All cloud "
        "apps > Grant: Require multifactor authentication > On. Or use the 'Require "
        "multifactor authentication for admins' template."
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        **_AUTHENTICATION,
        "CIS_AZURE_2.0": ["1.2.3"],
    }

    def _verdict(self, context: RuleContext) -> bool | None:
        defaults = context.controls.get("security_defaults_enabled")
        policies = context.controls.get("mfa_policies")
        if defaults is None and policies is None:
            return None
        if defaults is True:
            return True
        return any(
            p.get("all_users") or "Global Administrator" in (p.get("role_names") or [])
            for p in policies or []
        )

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Tenant policy unavailable: {failure}")
        verdict = self._verdict(context)
        evidence = {
            "security_defaults_enabled": context.controls.get("security_defaults_enabled"),
            "mfa_policies": [p.get("name") for p in context.controls.get("mfa_policies") or []],
        }
        if verdict is None:
            return RuleResult.unknown(
                "Neither security defaults nor Conditional Access policies were read"
            )
        if verdict:
            return RuleResult.passed(evidence)
        return RuleResult.failed(evidence=evidence, message=self.failure)


class AzureRiskySignInRule(_TenantSettingRule):
    rule_id = "AZ-ID-024"
    name = "Risky sign-ins are not challenged"
    description = (
        "No enabled Conditional Access policy requires a second factor of, or blocks, "
        "every user's sign-ins that Entra ID Protection rates medium risk or higher."
    )
    severity = Severity.MEDIUM
    exploitability = 3
    estimated_effort_minutes = 30
    requires_evidence = _CA
    control = "risky_sign_in_mfa"
    failure = "Sign-ins Entra rates risky are let through without a second factor"
    remediation_spec = _directory_spec()
    rationale = (
        "A sign-in from an anonymising network or with a leaked password is rated risky "
        "as it happens. Challenging it then stops the attacker at the one moment the "
        "tenant knows something is wrong. Needs Entra ID P2."
    )
    remediation = (
        "Create a Conditional Access policy: Users: All users (exclude break-glass) > "
        "Conditions: Sign-in risk: High and Medium > Grant: Require multifactor "
        "authentication > On."
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        **_AUTHENTICATION,
        "CIS_AZURE_2.0": ["1.2.5"],
    }


class AzureLocationPolicyRule(_TenantSettingRule):
    rule_id = "AZ-ID-025"
    name = "No Conditional Access policy considers where a sign-in comes from"
    description = (
        "No enabled Conditional Access policy includes a location condition, so a "
        "sign-in from a country the organization never works from is treated like any "
        "other."
    )
    severity = Severity.LOW
    exploitability = 1
    estimated_effort_minutes = 45
    requires_evidence = _CA
    control = "location_policy"
    failure = "No policy decides anything by where a sign-in comes from"
    remediation_spec = _directory_spec()
    rationale = (
        "Most organizations sign in from a handful of countries. Blocking or challenging "
        "the rest removes the bulk of credential spraying, which comes from wherever is "
        "cheapest to rent."
    )
    remediation = (
        "Define named locations for the countries or networks in use and create a "
        "Conditional Access policy that blocks or requires MFA for sign-ins from "
        "anywhere else."
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        **_ACCESS,
        "CIS_AZURE_2.0": ["1.2.2"],
    }


class AzureBannedPasswordRule(_TenantSettingRule):
    rule_id = "AZ-ID-026"
    name = "No custom banned-password list is enforced"
    description = (
        "Password protection does not enforce a custom list of banned passwords, so "
        "passwords built on the organization's own name, products or city are accepted."
    )
    severity = Severity.LOW
    exploitability = 2
    estimated_effort_minutes = 20
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.GROUP_SETTINGS,)
    control = "banned_password_list"
    failure = "No custom banned-password list is enforced"
    remediation_spec = _directory_spec(
        "az rest --method GET --url https://graph.microsoft.com/v1.0/groupSettings"
    )
    rationale = (
        "The global list stops 'Password1'. Only a custom list stops "
        "'Contoso2026!', which is what a spraying attack against Contoso tries first."
    )
    remediation = (
        "Entra admin centre > Protection > Authentication methods > Password protection > "
        "Enforce custom list: Yes > add the organization's names and terms > Save."
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.5.17"],
        "NIST_CSF": ["PR.AC-1"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["IA-5"],
        "SOC2": ["CC6.1"],
        "PCI_DSS_4": ["8.3.1"],
        "CIS_AZURE_2.0": ["1.7"],
    }


class AzureSessionLifetimeRule(_TenantSettingRule):
    rule_id = "AZ-ID-027"
    name = "No Conditional Access policy limits how long a session lasts"
    description = (
        "No enabled Conditional Access policy sets a sign-in frequency, so a session "
        "lasts as long as its refresh token keeps being used -- up to 90 days."
    )
    severity = Severity.LOW
    exploitability = 1
    estimated_effort_minutes = 20
    requires_evidence = _CA
    control = "sign_in_frequency_limited"
    failure = "No policy makes sessions sign in again after a set time"
    remediation_spec = _directory_spec()
    rationale = (
        "A stolen session cookie is worth as long as the session lasts. A sign-in "
        "frequency for administrators and unmanaged devices bounds it."
    )
    remediation = (
        "Create a Conditional Access policy for administrators and unmanaged devices > "
        "Session: Sign-in frequency: 4 to 12 hours > On."
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        **_ACCESS,
        "NIS2": ["11.6.2.e"],
    }


class AzureAuthenticatorContextRule(_TenantSettingRule):
    rule_id = "AZ-ID-028"
    name = "Authenticator notifications hide the application or location"
    description = (
        "Microsoft Authenticator is enabled with its push notifications set not to show "
        "which application is asking or where the sign-in is from."
    )
    severity = Severity.LOW
    exploitability = 2
    estimated_effort_minutes = 15
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.AUTHENTICATION_METHODS_POLICY,
    )
    control = "authenticator_context"
    shown = ("authenticator_app_context", "authenticator_location_context")
    failure = "Authenticator push notifications hide which app or where a sign-in is from"
    remediation_spec = _directory_spec(
        "az rest --method GET --url "
        "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"
    )
    rationale = (
        "MFA fatigue works because a prompt looks like every other prompt. Showing the "
        "application and the location makes a prompt from another country for an app "
        "the user is not opening one they decline."
    )
    remediation = (
        "Entra admin centre > Protection > Authentication methods > Microsoft "
        "Authenticator > Configure > Show application name and Show geographic location: "
        "Microsoft managed or Enabled > Save."
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        **_AUTHENTICATION,
        "MITRE_ATTACK": ["T1621"],
    }

    def _verdict(self, context: RuleContext) -> bool | None:
        app = context.controls.get("authenticator_app_context")
        location = context.controls.get("authenticator_location_context")
        if app is False or location is False:
            return False
        if app is None or location is None:
            return None
        return True


class AzureDeviceRegistrationMfaRule(_TenantSettingRule):
    rule_id = "AZ-ID-029"
    name = "Joining a device does not require multi-factor authentication"
    description = (
        "Neither the device registration policy nor a Conditional Access policy on the "
        "'Register or join devices' action requires a second factor to join or register "
        "a device."
    )
    severity = Severity.MEDIUM
    exploitability = 2
    estimated_effort_minutes = 20
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.DEVICE_REGISTRATION_POLICY,
        AzureEvidence.CONDITIONAL_ACCESS_POLICIES,
    )
    control = "device_registration_mfa"
    failure = "A device can be joined to the directory with a password alone"
    remediation_spec = _directory_spec(
        "az rest --method GET --url "
        "https://graph.microsoft.com/v1.0/policies/deviceRegistrationPolicy"
    )
    rationale = (
        "A joined device is trusted: policies that require a compliant or joined device "
        "accept it. Joining one with a stolen password turns that trust into the "
        "attacker's."
    )
    remediation = (
        "Create a Conditional Access policy: User actions: Register or join devices > "
        "Grant: Require multifactor authentication > On, and set 'Require Multifactor "
        "Authentication to register or join devices' to No so the policy decides."
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        **_AUTHENTICATION,
        "CIS_AZURE_2.0": ["1.22"],
        "CIS_AZURE_6.0": ["5.1.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        by_policy = context.controls.get("device_registration_mfa_by_policy")
        setting = context.controls.get("device_registration_mfa")
        evidence = {
            "device_registration_mfa_by_policy": by_policy,
            "device_registration_mfa": setting,
        }
        # Either one answers yes on its own, so a failed read of the other does
        # not take that answer away.
        if by_policy is True or str(setting).lower() == "required":
            return RuleResult.passed(evidence)
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Tenant setting unavailable: {failure}")
        if by_policy is None or setting is None:
            return RuleResult.unknown("The device registration settings were not read")
        return RuleResult.failed(evidence=evidence, message=self.failure)


class AzureSubscriptionMoveRule(_TenantSettingRule):
    rule_id = "AZ-ID-030"
    name = "Subscriptions can be moved into or out of the directory"
    description = (
        "The tenant's subscription policy lets users move subscriptions out of the "
        "directory, or bring subscriptions in from another one."
    )
    severity = Severity.MEDIUM
    exploitability = 2
    estimated_effort_minutes = 15
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.SUBSCRIPTION_POLICY,)
    control = "subscription_moves_blocked"
    shown = ("subscriptions_may_leave", "subscriptions_may_enter")
    failure = "Users may move subscriptions into or out of the directory"
    remediation_spec = _directory_spec(
        "az rest --method GET --url "
        "https://management.azure.com/providers/Microsoft.Subscription/policies/default"
        "?api-version=2021-10-01"
    )
    rationale = (
        "A subscription moved out takes its data beyond every policy, log and person "
        "watching it. One moved in arrives with whatever its last tenant left in it. "
        "Microsoft made blocking both the default in May 2026."
    )
    remediation = (
        "Azure portal > Subscriptions > Manage policies > Subscription leaving Microsoft "
        "Entra ID directory: Permit no one, and Subscription entering Microsoft Entra ID "
        "directory: Permit no one. Needs a Global Administrator with elevated access."
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        **_ACCESS,
        "CIS_AZURE_2.0": ["1.25"],
        "CIS_AZURE_6.0": ["5.6"],
    }

    def _verdict(self, context: RuleContext) -> bool | None:
        leave = context.controls.get("subscriptions_may_leave")
        enter = context.controls.get("subscriptions_may_enter")
        if leave is None or enter is None:
            return None
        return not (leave or enter)


class AzureGuestAccessReviewRule(_TenantSettingRule):
    rule_id = "AZ-ID-031"
    name = "No access review covers guest accounts"
    description = (
        "No active access review has guests in its scope, so a guest keeps whatever "
        "access it was given until somebody remembers to remove it."
    )
    severity = Severity.LOW
    exploitability = 1
    estimated_effort_minutes = 60
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.ACCESS_REVIEWS,)
    control = "guest_access_reviews"
    failure = "No access review covers guest accounts"
    remediation_spec = _directory_spec(
        "az rest --method GET --url "
        "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions"
    )
    rationale = (
        "Guests outlast the projects they were invited for. A recurring review is the "
        "only routine that asks whether each one still needs to be here. Needs Entra ID "
        "P2 or Governance."
    )
    remediation = (
        "Entra admin centre > Identity governance > Access reviews > New access review > "
        "Review type: Teams + Groups or Applications, Guest users only > Recurrence: "
        "Quarterly > Auto-apply results."
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        **_ACCESS,
        "CIS_AZURE_2.0": ["1.4"],
    }


RULES = (
    AzureAdminMfaPolicyRule(),
    AzureRiskySignInRule(),
    AzureLocationPolicyRule(),
    AzureBannedPasswordRule(),
    AzureSessionLifetimeRule(),
    AzureAuthenticatorContextRule(),
    AzureDeviceRegistrationMfaRule(),
    AzureSubscriptionMoveRule(),
    AzureGuestAccessReviewRule(),
)
