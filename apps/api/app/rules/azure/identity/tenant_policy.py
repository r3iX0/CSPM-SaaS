"""Tenant-wide directory settings (DECISIONS.md section 172).

Two readings of the tenant, neither of them an asset. Conditional Access says
which doors ask for a second factor; the authorization policy says what an
ordinary user and a guest may do in the directory. Both are facts about the
tenant rather than about anything in it, so every rule here is AGGREGATE,
reads ``RuleContext.controls``, and is UNKNOWN whenever the reading is absent --
a tenant whose policy was never read is one Cleave cannot speak for.

No policy is generated for any of them: these are Entra settings, not resource
properties, and no ``policyRule`` can express them.
"""

from typing import Any, ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, RuleScope, Severity
from app.domain.resource import CloudResource
from app.remediation import RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule

_DIRECTORY_SETTING = (
    "No policy is generated and none can be: this is a directory setting in Entra ID "
    "rather than a resource property, so no policyRule can express it."
)

# The application Conditional Access calls "Windows Azure Service Management
# API": the Azure portal, Azure CLI, PowerShell and ARM itself.
AZURE_MANAGEMENT_APP = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
ADMIN_PORTALS = "microsoftadminportals"

# The guest role Graph names *Restricted Guest User* -- guests see only their own
# directory objects (authorizationPolicy, guestUserRoleId).
RESTRICTED_GUEST_ROLE = "2af84b1e-32c8-42b7-82bc-daa82404023b"
MEMBER_ROLE = "a0b1b346-4d3e-4e8b-98f8-753987be4970"
LEGACY_USER_CONSENT = "managepermissiongrantsforself.microsoft-user-default-legacy"


def _patch(body: str) -> str:
    return (
        "az rest --method PATCH --url "
        "https://graph.microsoft.com/v1.0/policies/authorizationPolicy "
        f"--body '{body}'"
    )


class _TenantRule(SecurityRule):
    category = "identity"
    scope = RuleScope.AGGREGATE
    applies_to: ClassVar[list[ResourceType]] = []


class _MfaForAppRule(_TenantRule):
    """An enabled Conditional Access policy requires MFA of every user for one
    application, or security defaults are on."""

    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.SECURITY_DEFAULTS,
        AzureEvidence.CONDITIONAL_ACCESS_POLICIES,
    )
    targets: ClassVar[frozenset[str]] = frozenset()
    door: ClassVar[str] = ""

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Tenant policy unavailable: {failure}")
        defaults = context.controls.get("security_defaults_enabled")
        protected = context.controls.get("mfa_protected_apps")
        if defaults is None and protected is None:
            return RuleResult.unknown(
                "Neither security defaults nor Conditional Access policies were read"
            )
        evidence: dict[str, Any] = {
            "security_defaults_enabled": defaults,
            "mfa_protected_apps": protected,
        }
        # Security defaults challenge every administrator at every sign-in and
        # every user reaching Azure management.
        if defaults is True:
            return RuleResult.passed(evidence)
        if set(protected or []) & ({"all"} | self.targets):
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"No enabled policy requires a second factor of every user for {self.door}",
        )


class AzureManagementMfaRule(_MfaForAppRule):
    rule_id = "AZ-ID-013"
    name = "Azure management does not require multi-factor authentication"
    description = (
        "No security default and no enabled Conditional Access policy requires a second "
        "factor of every user signing in to Azure management -- the portal, Azure CLI, "
        "PowerShell and the Resource Manager API."
    )
    severity = Severity.HIGH
    exploitability = 4
    estimated_effort_minutes = 45
    targets: ClassVar[frozenset[str]] = frozenset({AZURE_MANAGEMENT_APP})
    door = "Azure management"
    rationale = (
        "Azure management is where a stolen password becomes control of the estate: "
        "every resource, role and key is one API call away. It is the one door where "
        "a second factor protects everything behind it at once."
    )
    remediation = (
        "Create a Conditional Access policy: Users: All users (exclude one break-glass "
        "account) > Target resources: Windows Azure Service Management API > Grant: "
        "Require multifactor authentication > On. On Entra ID Free, enable security "
        "defaults instead."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "az rest --method GET --url "
            "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
        ),
        notes=_DIRECTORY_SETTING,
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.5.17"],
        "NIST_CSF": ["PR.AC-7"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["IA-2"],
        "SOC2": ["CC6.1"],
        "PCI_DSS_4": ["8.4.2"],
    }


class AzureAdminPortalMfaRule(_MfaForAppRule):
    rule_id = "AZ-ID-014"
    name = "Microsoft admin portals do not require multi-factor authentication"
    description = (
        "No security default and no enabled Conditional Access policy requires a second "
        "factor of every user reaching the Microsoft admin portals -- the Entra, "
        "Microsoft 365, Exchange and other administration centres."
    )
    severity = Severity.MEDIUM
    exploitability = 3
    estimated_effort_minutes = 30
    targets: ClassVar[frozenset[str]] = frozenset({ADMIN_PORTALS})
    door = "the Microsoft admin portals"
    rationale = (
        "The admin portals are where directory roles are used. A policy on the portals "
        "themselves covers every administrator, including ones assigned a role "
        "tomorrow that no per-role policy names yet."
    )
    remediation = (
        "Create a Conditional Access policy: Users: All users (exclude one break-glass "
        "account) > Target resources: Microsoft Admin Portals > Grant: Require "
        "multifactor authentication > On."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "az rest --method GET --url "
            "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
        ),
        notes=_DIRECTORY_SETTING,
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.5.17", "A.8.2"],
        "NIST_CSF": ["PR.AC-7"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["IA-2"],
        "SOC2": ["CC6.1"],
        "PCI_DSS_4": ["8.4.2"],
    }


class _AuthorizationRule(_TenantRule):
    """One setting of the tenant's authorization policy."""

    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.AUTHORIZATION_POLICY,
    )

    def _policy(self, context: RuleContext) -> dict[str, Any] | RuleResult:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Authorization policy unavailable: {failure}")
        policy = context.controls.get("authorization_policy")
        if not isinstance(policy, dict):
            return RuleResult.unknown("The tenant's authorization policy was not read")
        return policy


class AzureUserConsentRule(_AuthorizationRule):
    rule_id = "AZ-ID-015"
    name = "Users can consent to any application"
    description = (
        "Ordinary users may grant any application access to organization data on their "
        "own behalf -- the legacy default consent policy is assigned -- so one click on "
        "a convincing consent screen hands a stranger's app their mailbox and files."
    )
    severity = Severity.HIGH
    exploitability = 4
    estimated_effort_minutes = 60
    rationale = (
        "Consent phishing needs no password and survives a password reset: the "
        "attacker's app holds a token of its own. Limiting user consent to verified "
        "publishers asking for low-impact permissions removes the whole technique."
    )
    remediation = (
        "Entra admin centre > Enterprise applications > Consent and permissions > User "
        "consent settings > Allow user consent for apps from verified publishers, for "
        "selected permissions (or Do not allow user consent), and set up the admin "
        "consent workflow so requests reach someone."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            _patch(
                '{"defaultUserRolePermissions":{"permissionGrantPoliciesAssigned":'
                '["ManagePermissionGrantsForSelf.microsoft-user-default-low"]}}'
            ),
        ),
        notes=_DIRECTORY_SETTING,
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.5.15", "A.8.2"],
        "NIST_CSF": ["PR.AC-4"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
        "NIST_800_53": ["AC-3", "AC-6"],
        "SOC2": ["CC6.1", "CC6.3"],
        "PCI_DSS_4": ["7.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        policy = self._policy(context)
        if isinstance(policy, RuleResult):
            return policy
        grants = policy.get("user_consent_policies")
        if grants is None:
            return RuleResult.unknown("The policy did not state its user consent setting")
        evidence = {"user_consent_policies": grants}
        if LEGACY_USER_CONSENT in {str(g).lower() for g in grants}:
            return RuleResult.failed(
                evidence=evidence,
                message="Users can consent to any application on their own behalf",
            )
        return RuleResult.passed(evidence)


class AzureUsersRegisterAppsRule(_AuthorizationRule):
    rule_id = "AZ-ID-016"
    name = "Any user can register applications"
    description = (
        "Ordinary users may create application registrations, each an identity that "
        "can hold credentials and be granted access, owned by whoever made it."
    )
    severity = Severity.MEDIUM
    exploitability = 2
    estimated_effort_minutes = 30
    rationale = (
        "Every registration is a principal with its own secrets. Letting anyone create "
        "them makes the tenant's identities impossible to inventory and gives a "
        "compromised account a place to plant a credential that outlives it."
    )
    remediation = (
        "Entra admin centre > Users > User settings > Users can register applications > "
        "No, and give the people who build integrations the Application Developer role."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(_patch('{"defaultUserRolePermissions":{"allowedToCreateApps":false}}'),),
        notes=_DIRECTORY_SETTING,
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.5.15", "A.5.16"],
        "NIST_CSF": ["PR.AC-1", "PR.AC-4"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["AC-2", "AC-6"],
        "SOC2": ["CC6.2"],
        "PCI_DSS_4": ["7.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        policy = self._policy(context)
        if isinstance(policy, RuleResult):
            return policy
        allowed = policy.get("users_can_create_apps")
        if allowed is None:
            return RuleResult.unknown("The policy did not state whether users can register apps")
        evidence = {"users_can_create_apps": allowed}
        if allowed is False:
            return RuleResult.passed(evidence)
        return RuleResult.failed(evidence=evidence, message="Any user can register applications")


class AzureGuestInviteRule(_AuthorizationRule):
    rule_id = "AZ-ID-017"
    name = "Any member can invite guests"
    description = (
        "Guest invitations are open to every member -- or to everyone, guests included "
        "-- rather than to administrators and the Guest Inviter role."
    )
    severity = Severity.MEDIUM
    exploitability = 2
    estimated_effort_minutes = 30
    rationale = (
        "An invitation is how an outside identity becomes a principal the tenant's "
        "roles and groups can be granted to. Left to everyone, the tenant's guest list "
        "is whatever any compromised account made it."
    )
    remediation = (
        "Entra admin centre > External Identities > External collaboration settings > "
        "Guest invite settings > Only users assigned to specific admin roles can invite "
        "guest users."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(_patch('{"allowInvitesFrom":"adminsAndGuestInviters"}'),),
        notes=_DIRECTORY_SETTING,
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.5.16", "A.5.18"],
        "NIST_CSF": ["PR.AC-1"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["AC-2"],
        "SOC2": ["CC6.2"],
        "PCI_DSS_4": ["7.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        policy = self._policy(context)
        if isinstance(policy, RuleResult):
            return policy
        invites = policy.get("allow_invites_from")
        if invites is None:
            return RuleResult.unknown("The policy did not state who can invite guests")
        evidence = {"allow_invites_from": invites}
        if str(invites).lower() in {"none", "adminsandguestinviters"}:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"Guest invitations are open to {invites}",
        )


class AzureGuestDirectoryAccessRule(_AuthorizationRule):
    rule_id = "AZ-ID-018"
    name = "Guests can read the directory"
    description = (
        "Guests are not held to the Restricted Guest User role, so they can enumerate "
        "users, groups and memberships rather than seeing only their own objects."
    )
    severity = Severity.MEDIUM
    exploitability = 2
    estimated_effort_minutes = 20
    rationale = (
        "The directory is the map of the organization: who administers what, which "
        "groups hold which roles. A guest account -- the easiest kind to obtain -- "
        "should not be able to read it."
    )
    remediation = (
        "Entra admin centre > External Identities > External collaboration settings > "
        "Guest user access > Guest user access is restricted to properties and "
        "memberships of their own directory objects."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(_patch(f'{{"guestUserRoleId":"{RESTRICTED_GUEST_ROLE}"}}'),),
        notes=_DIRECTORY_SETTING,
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.5.15", "A.8.3"],
        "NIST_CSF": ["PR.AC-4"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
        "NIST_800_53": ["AC-3", "AC-6"],
        "SOC2": ["CC6.1"],
        "PCI_DSS_4": ["7.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        policy = self._policy(context)
        if isinstance(policy, RuleResult):
            return policy
        role = policy.get("guest_user_role_id")
        if role is None:
            return RuleResult.unknown("The policy did not state the guest role")
        evidence = {"guest_user_role_id": role}
        if str(role).lower() == RESTRICTED_GUEST_ROLE:
            return RuleResult.passed(evidence)
        member_like = str(role).lower() == MEMBER_ROLE
        return RuleResult.failed(
            evidence=evidence,
            # Only the Guest User default is a step down from the class tag's
            # worst case, which is guests holding the same access as members.
            exploitability=None if member_like else 1,
            message=(
                "Guests have the same directory access as members"
                if member_like
                else "Guests can read users, groups and memberships across the directory"
            ),
        )


class AzureUserCreationRightsRule(_AuthorizationRule):
    rule_id = "AZ-ID-019"
    name = "Any user can create tenants or security groups"
    description = (
        "Ordinary users may create new Entra tenants, security groups, or both -- "
        "directory objects that then exist outside any administrator's decision."
    )
    severity = Severity.LOW
    exploitability = 1
    estimated_effort_minutes = 20
    rationale = (
        "A tenant created by an employee holds company data under no one's governance; "
        "a security group created by anyone can later be granted access by someone who "
        "assumed an administrator made it."
    )
    remediation = (
        "Entra admin centre > Users > User settings > Restrict non-admin users from "
        "creating tenants > Yes; and Groups > General > Users can create security "
        "groups > No."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            _patch(
                '{"defaultUserRolePermissions":{"allowedToCreateTenants":false,'
                '"allowedToCreateSecurityGroups":false}}'
            ),
        ),
        notes=_DIRECTORY_SETTING,
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.5.15"],
        "NIST_CSF": ["PR.AC-4"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["AC-6", "CM-7"],
        "SOC2": ["CC6.2"],
        "PCI_DSS_4": ["7.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        policy = self._policy(context)
        if isinstance(policy, RuleResult):
            return policy
        tenants = policy.get("users_can_create_tenants")
        groups = policy.get("users_can_create_security_groups")
        if tenants is None and groups is None:
            return RuleResult.unknown("The policy did not state either creation right")
        evidence = {
            "users_can_create_tenants": tenants,
            "users_can_create_security_groups": groups,
        }
        allowed = [
            noun
            for noun, value in (("tenants", tenants), ("security groups", groups))
            if value is True
        ]
        if allowed:
            return RuleResult.failed(
                evidence=evidence,
                message=f"Any user can create {' and '.join(allowed)}",
            )
        if tenants is None or groups is None:
            return RuleResult.unknown("The policy stated only one of the two creation rights")
        return RuleResult.passed(evidence)


class AzureStrongAuthenticationRule(_TenantRule):
    rule_id = "AZ-ID-020"
    name = "No strong sign-in method is offered, or registration is not campaigned"
    description = (
        "The tenant's authentication methods policy enables none of Microsoft "
        "Authenticator, FIDO2 security keys or certificate-based sign-in, or its "
        "registration campaign is switched off -- so users are left on SMS and voice, "
        "or never asked to set a second factor up at all."
    )
    severity = Severity.MEDIUM
    exploitability = 2
    estimated_effort_minutes = 60
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.AUTHENTICATION_METHODS_POLICY,
    )
    rationale = (
        "A second factor only protects accounts that registered one, and SMS and voice "
        "codes are phished and intercepted routinely. The strong methods and the "
        "campaign that prompts people to use them are what make MFA real."
    )
    remediation = (
        "Entra admin centre > Protection > Authentication methods > Policies: enable "
        "Microsoft Authenticator (and passkeys / FIDO2 where you can), then Registration "
        "campaign > Enabled for all users, targeting Microsoft Authenticator."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "az rest --method GET --url "
            "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy",
        ),
        notes=_DIRECTORY_SETTING,
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.5.17"],
        "NIST_CSF": ["PR.AC-7"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["IA-2", "IA-5"],
        "SOC2": ["CC6.1"],
        "PCI_DSS_4": ["8.4.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Authentication methods policy unavailable: {failure}")
        methods = context.controls.get("authentication_methods")
        if not isinstance(methods, dict):
            return RuleResult.unknown("The authentication methods policy was not read")
        strong = methods.get("strong_methods_enabled") or []
        campaign = methods.get("registration_campaign")
        evidence = {"strong_methods_enabled": strong, "registration_campaign": campaign}
        problems = []
        if not strong:
            problems.append("no strong sign-in method is enabled")
        # ``default`` is Microsoft-managed and on for users still relying on SMS
        # and voice; only an explicit ``disabled`` switches the prompting off.
        if campaign == "disabled":
            problems.append("the registration campaign is switched off")
        if not problems:
            return RuleResult.passed(evidence)
        return RuleResult.failed(evidence=evidence, message="; ".join(problems).capitalize())


class AzureM365GroupCreationRule(_TenantRule):
    rule_id = "AZ-ID-021"
    name = "Any user can create Microsoft 365 groups"
    description = (
        "Every user may create Microsoft 365 groups, each with a mailbox, a SharePoint "
        "site and a Teams team -- a place to share data that no administrator created."
    )
    severity = Severity.LOW
    exploitability = 1
    estimated_effort_minutes = 30
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.GROUP_SETTINGS,)
    rationale = (
        "Unrestricted group creation scatters organization data across sites and teams "
        "that nobody reviews, often with guests added by whoever made them."
    )
    remediation = (
        "Restrict creation to a named security group: set EnableGroupCreation to false "
        "and GroupCreationAllowedGroupId to that group in the Group.Unified directory "
        "setting (Microsoft Graph or the Microsoft Graph PowerShell module)."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=("az rest --method GET --url https://graph.microsoft.com/v1.0/groupSettings",),
        notes=_DIRECTORY_SETTING,
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.5.15"],
        "NIST_CSF": ["PR.AC-4"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["AC-6", "CM-7"],
        "SOC2": ["CC6.2"],
        "PCI_DSS_4": ["7.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Directory settings unavailable: {failure}")
        open_to_all = context.controls.get("m365_group_creation_open")
        if open_to_all is None:
            return RuleResult.unknown("The directory settings were not read")
        evidence = {"m365_group_creation_open": open_to_all}
        if open_to_all is False:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence, message="Any user can create Microsoft 365 groups"
        )



class AzureTrustedLocationRule(_TenantRule):
    """Section 176. A trusted IP range lets Conditional Access tell the office
    network from everywhere else -- for sign-in risk, for MFA registration, for a
    policy that blocks sign-ins from anywhere but there."""

    rule_id = "AZ-ID-022"
    name = "No trusted named location is defined"
    description = (
        "The tenant has no named location marked trusted with IP ranges, so Conditional "
        "Access cannot treat the organization's own networks differently from any "
        "other address on the internet."
    )
    severity = Severity.LOW
    exploitability = 1
    estimated_effort_minutes = 30
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.NAMED_LOCATIONS,)
    rationale = (
        "Without a trusted location every sign-in looks alike to Conditional Access: an "
        "administrator at their desk and a password sprayed from a botnet are judged "
        "the same way, and Identity Protection has no known-good network to weigh risk "
        "against."
    )
    remediation = (
        "Define the organization's egress ranges as a trusted named location.\n\n"
        "Microsoft Entra admin center: Protection > Conditional Access > Named locations "
        "> IP ranges location > add the ranges > Mark as trusted location > Create."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "az rest --method POST --url "
            "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations "
            "--body @trusted-location.json",
        ),
        notes=_DIRECTORY_SETTING,
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.20"],
        "NIST_CSF": ["PR.AC-3"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["AC-17"],
        "SOC2": ["CC6.6"],
        "PCI_DSS_4": ["8.4.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Named locations unavailable: {failure}")
        trusted = context.controls.get("trusted_named_locations")
        if trusted is None:
            return RuleResult.unknown("The tenant's named locations were not read")
        evidence = {"trusted_named_locations": trusted}
        if trusted:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence, message="No named location is marked trusted"
        )
