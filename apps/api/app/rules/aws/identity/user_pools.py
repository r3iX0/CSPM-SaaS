"""Cognito user pools: an application's own sign-in (DECISIONS.md section 177).

Four checks the catalogue filed as reading activity records. They read the
pool's configuration -- its threat protection mode, what that protection does
with a risky sign-in, and the web ACL in front of it -- and nothing a user did.
Threat protection needs the pool on Cognito's Plus tier, which is billed per
active user; the remediation says so.

Like every AWS rule, none of this has been read from a live account
(``docs/AWS_INTEGRATION.md`` section 1).
"""

from typing import Any

from app.connectors.aws.evidence import AwsEvidence
from app.core.enums import Provider, ResourceType, Severity
from app.rules.property import PropertySpec, property_rule

_SIGN_IN = {
    "ISO_27001": ["A.5.17", "A.8.16"],
    "NIST_CSF_2.0": ["PR.AA-03", "DE.CM-01"],
    "GDPR": ["32(1)(b)"],
    "NIST_800_53": ["IA-2", "SI-4"],
    "SOC2": ["CC6.1"],
    "PCI_DSS_4": ["8.3.1"],
}
_POOLS = (AwsEvidence.COGNITO_USER_POOLS,)
_ENFORCED = (("threat_protection_mode", "enforced"),)
_UPDATE = (
    "aws cognito-idp set-risk-configuration --user-pool-id <pool-id> "
    "--cli-input-json file://risk-configuration.json"
)


def _challenges_every_level(actions: Any) -> bool:
    # Blocking or requiring MFA stops a risky sign-in; MFA_IF_CONFIGURED lets a
    # user with no second factor straight through.
    if not isinstance(actions, dict):
        return False
    return all(
        str(actions.get(level) or "").upper() in {"BLOCK", "MFA_REQUIRED"}
        for level in ("low", "medium", "high")
    )


SPECS = (
    PropertySpec(
        rule_id="AWS-COG-001",
        name="User pool threat protection is not enforced",
        description=(
            "The Cognito user pool's threat protection is off or only auditing, so "
            "sign-ins with leaked passwords or from risky contexts are let through."
        ),
        rationale=(
            "A user pool's sign-in faces the internet by design and is sprayed with "
            "breached passwords like any other. Enforced threat protection is what "
            "blocks or challenges those sign-ins; audit mode only records them."
        ),
        remediation=(
            "Move the pool to the Plus tier and set threat protection to full "
            "function.\n\n"
            "  aws cognito-idp update-user-pool --user-pool-id <pool-id> \\\n"
            "    --user-pool-tier PLUS \\\n"
            "    --user-pool-add-ons AdvancedSecurityMode=ENFORCED\n\n"
            "Plus is billed per monthly active user."
        ),
        cli=(
            "aws cognito-idp update-user-pool --user-pool-id <pool-id> --user-pool-tier "
            "PLUS --user-pool-add-ons AdvancedSecurityMode=ENFORCED",
        ),
        severity=Severity.MEDIUM,
        exploitability=3,
        category="identity",
        resource_type=ResourceType.USER_POOL,
        evidence=_POOLS,
        field="threat_protection_mode",
        safe="ENFORCED",
        describes="Threat protection runs in full-function (ENFORCED) mode",
        failure="does not enforce threat protection",
        mappings=_SIGN_IN,
        provider=Provider.AWS,
    ),
    PropertySpec(
        rule_id="AWS-COG-002",
        name="User pool does not block sign-ins with compromised credentials",
        description=(
            "Threat protection is enforced but takes no action when a user signs in "
            "with a password found in a breach."
        ),
        rationale=(
            "A password known to be leaked is the one attackers try first. Detecting "
            "it and letting the sign-in through leaves the account to whoever has the "
            "breach list."
        ),
        remediation=(f"Set the compromised-credentials action to BLOCK.\n\n  {_UPDATE}"),
        cli=(_UPDATE,),
        severity=Severity.MEDIUM,
        exploitability=3,
        category="identity",
        resource_type=ResourceType.USER_POOL,
        evidence=(*_POOLS, AwsEvidence.COGNITO_RISK_CONFIGURATIONS),
        field="compromised_credentials_action",
        safe="BLOCK",
        describes="Sign-ins with compromised credentials are blocked",
        failure="lets sign-ins with compromised credentials through",
        mappings=_SIGN_IN,
        # AWS-COG-001 reports a pool whose protection is not enforced.
        applies_when=_ENFORCED,
        provider=Provider.AWS,
    ),
    PropertySpec(
        rule_id="AWS-COG-003",
        name="User pool lets risky sign-ins through unchallenged",
        description=(
            "Threat protection is enforced, but at some risk level a suspicious "
            "sign-in is allowed without being blocked or required to pass MFA."
        ),
        rationale=(
            "Adaptive authentication is only as strong as its weakest level. The "
            "catalogue asked for BLOCK at every level; requiring MFA is accepted here "
            "too, since it stops the attacker and not the user."
        ),
        remediation=(
            "Set the account-takeover action to BLOCK or MFA_REQUIRED at low, medium "
            "and high risk.\n\n"
            f"  {_UPDATE}"
        ),
        cli=(_UPDATE,),
        severity=Severity.MEDIUM,
        exploitability=3,
        category="identity",
        resource_type=ResourceType.USER_POOL,
        evidence=(*_POOLS, AwsEvidence.COGNITO_RISK_CONFIGURATIONS),
        field="account_takeover_actions",
        passes=_challenges_every_level,
        why_no_expected_state=(
            "Two actions pass at each of three levels, so there is no one value to expect."
        ),
        describes="Every risk level blocks the sign-in or requires MFA",
        failure="lets risky sign-ins through without a challenge",
        mappings=_SIGN_IN,
        applies_when=_ENFORCED,
        provider=Provider.AWS,
    ),
    PropertySpec(
        rule_id="AWS-COG-004",
        name="User pool has no web ACL in front of it",
        description=(
            "No AWS WAF web ACL is associated with the user pool, so its hosted sign-in "
            "and public API endpoints take every request that reaches them."
        ),
        rationale=(
            "A web ACL rate-limits and filters sign-in traffic before Cognito sees it, "
            "which is where a credential-stuffing run is cheapest to stop."
        ),
        remediation=(
            "Associate a regional web ACL with the pool.\n\n"
            "  aws wafv2 associate-web-acl --web-acl-arn <web-acl-arn> \\\n"
            "    --resource-arn <user-pool-arn>"
        ),
        cli=(
            "aws wafv2 associate-web-acl --web-acl-arn <web-acl-arn> "
            "--resource-arn <user-pool-arn>",
        ),
        severity=Severity.LOW,
        exploitability=3,
        category="network",
        resource_type=ResourceType.USER_POOL,
        evidence=(*_POOLS, AwsEvidence.COGNITO_WEB_ACLS),
        field="web_acl_attached",
        safe=True,
        describes="A WAF web ACL is associated with the pool",
        failure="has no web ACL in front of it",
        mappings={
            "ISO_27001": ["A.8.20"],
            "NIST_CSF_2.0": ["PR.IR-01"],
            "GDPR": ["32(1)(b)"],
            "NIST_800_53": ["SC-7"],
            "SOC2": ["CC6.6"],
            "PCI_DSS_4": ["6.5.1"],
        },
        provider=Provider.AWS,
    ),
)

RULES = tuple(property_rule(spec) for spec in SPECS)
