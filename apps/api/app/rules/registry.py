"""The rule registry — the single source of truth for what CloudGuard checks.

The ``rules`` database table is a read-mirror of this list, synced at startup.
Adding a rule means adding it here and writing its tests; it never means
inserting a database row (RULE_ENGINE.md section 4).

``RULE_REGISTRY`` is the native engine's list. The Prowler checks the scanner
service runs are registered beside it, not in it (``app/prowler/rules.py``), and
:func:`catalogue_rules` is the two together (DECISIONS.md section 150).
"""

from app.prowler.rules import get_prowler_rule, prowler_rules
from app.rules.aws.compute.exposure import AwsInstanceMetadataRule
from app.rules.aws.database.exposure import (
    AwsDatabaseEncryptionRule,
    AwsDatabasePatchingRule,
    AwsPublicDatabaseRule,
)
from app.rules.aws.identity.credentials import (
    AwsAccessAnalyzerRule,
    AwsAdministratorPolicyRule,
    AwsExpiredCertificateRule,
    AwsPasswordPolicyRule,
    AwsRootAccessKeyRule,
    AwsRootMfaRule,
    AwsStaleAccessKeyRule,
    AwsSupportRoleRule,
    AwsUserWithoutMfaRule,
)
from app.rules.aws.logging.trails import (
    AwsBucketPolicyChangeMonitoringRule,
    AwsCloudTrailCoverageRule,
    AwsConfigChangeMonitoringRule,
    AwsConfigRecorderRule,
    AwsConsoleAuthFailureMonitoringRule,
    AwsConsoleSignInWithoutMfaMonitoringRule,
    AwsEbsDefaultEncryptionRule,
    AwsFlowLogRule,
    AwsGatewayChangeMonitoringRule,
    AwsIamPolicyChangeMonitoringRule,
    AwsKeyDisableMonitoringRule,
    AwsNetworkAclChangeMonitoringRule,
    AwsOrganizationsChangeMonitoringRule,
    AwsRootUsageMonitoringRule,
    AwsRouteTableChangeMonitoringRule,
    AwsSecurityGroupChangeMonitoringRule,
    AwsTrailBucketLoggingRule,
    AwsTrailChangeMonitoringRule,
    AwsTrailEncryptionRule,
    AwsTrailValidationRule,
    AwsUnauthorizedApiMonitoringRule,
    AwsVpcChangeMonitoringRule,
)
from app.rules.aws.network.exposure import (
    AwsDefaultSecurityGroupRule,
    AwsOpenNetworkAclRule,
    AwsPublicDatabasePortRule,
    AwsPublicRdpRule,
    AwsPublicSshRule,
)
from app.rules.aws.posture.coverage import AwsGuardDutyRule, AwsSecurityHubRule
from app.rules.aws.secrets.keys import AwsKeyRotationRule
from app.rules.aws.storage.public_access import (
    AwsBucketEncryptionRule,
    AwsBucketTransportRule,
    AwsPublicBucketRule,
)
from app.rules.azure.compute.disks import AzureUnmanagedDiskRule
from app.rules.azure.compute.exposure import (
    AzureExposedComputeRule,
    AzureUnguardedVmRule,
)
from app.rules.azure.database.encryption import AzureDatabaseEncryptionRule
from app.rules.azure.database.public_access import (
    AzureDatabaseAuditingRule,
    AzureDatabasePrivateConnectivityRule,
    AzurePublicDatabaseRule,
)
from app.rules.azure.database.transport import (
    AzurePostgresTlsRule,
    AzureSqlEntraAdminRule,
    AzureSqlTlsRule,
)
from app.rules.azure.identity.credentials import (
    AzureLongLivedApplicationCredentialRule,
)
from app.rules.azure.identity.dormant import AzureDormantPrivilegedAccountRule
from app.rules.azure.identity.mfa import (
    AzureLegacyAuthenticationRule,
    AzureMfaRule,
    AzureTenantMfaEnforcementRule,
    AzureUserWithoutMfaRule,
)
from app.rules.azure.identity.privileged import (
    AzureDisabledPrivilegedUserRule,
    AzureGuestPrivilegedUserRule,
    AzurePrivilegedUserRule,
)
from app.rules.azure.logging.diagnostics import (
    AzureActivityLogExportRule,
    AzureCriticalResourceLoggingRule,
    AzureLoggingRule,
)
from app.rules.azure.network.exposure import (
    AzureOpenNsgRule,
    AzurePublicRdpRule,
    AzurePublicSmbRule,
    AzurePublicSqlPortRule,
    AzurePublicSshRule,
    AzurePublicUdpRule,
    AzurePublicWinRmRule,
    AzureSensitivePublicAddressRule,
)
from app.rules.azure.posture.defender import (
    AzureExposedVulnerableMachineRule,
    AzureMissingEndpointProtectionRule,
)
from app.rules.azure.posture.plans import AzureDefenderPlansRule
from app.rules.azure.rbac.privilege import (
    AzureBroadScopeAssignmentRule,
    AzureDangerousCustomRoleRule,
    AzureExcessiveOwnersRule,
    AzurePersonWithSubscriptionControlRule,
    AzureRoleGrantingIdentityRule,
    AzureWorkloadWithSubscriptionControlRule,
)
from app.rules.azure.secrets.key_vault import (
    AzureKeyVaultAccessModelRule,
    AzureKeyVaultDeletionRule,
    AzureKeyVaultNetworkRule,
)
from app.rules.azure.storage.data_protection import (
    AzureBlobSoftDeleteRule,
    AzureStorageCrossTenantReplicationRule,
)
from app.rules.azure.storage.public_access import (
    AzurePublicStorageRule,
    AzureStorageEncryptionRule,
    AzureStorageTransportRule,
)
from app.rules.azure.web.app_service import (
    AzureAppServiceFtpRule,
    AzureAppServiceHttpsRule,
    AzureAppServiceIdentityRule,
    AzureAppServiceRemoteDebuggingRule,
    AzureAppServiceTlsRule,
)
from app.rules.base import SecurityRule

RULE_REGISTRY: list[SecurityRule] = [
    AzureMfaRule(),
    AzureUserWithoutMfaRule(),
    AzureTenantMfaEnforcementRule(),
    AzureLegacyAuthenticationRule(),
    AzureGuestPrivilegedUserRule(),
    AzureDisabledPrivilegedUserRule(),
    AzurePrivilegedUserRule(),
    AzureDormantPrivilegedAccountRule(),
    AzureLongLivedApplicationCredentialRule(),
    AzurePublicRdpRule(),
    AzurePublicSshRule(),
    AzurePublicWinRmRule(),
    AzurePublicSqlPortRule(),
    AzurePublicSmbRule(),
    AzureSensitivePublicAddressRule(),
    AzureOpenNsgRule(),
    AzurePublicStorageRule(),
    AzureStorageEncryptionRule(),
    AzureStorageTransportRule(),
    AzurePublicDatabaseRule(),
    AzureDatabasePrivateConnectivityRule(),
    AzureDatabaseAuditingRule(),
    AzureDatabaseEncryptionRule(),
    AzureLoggingRule(),
    AzureCriticalResourceLoggingRule(),
    AzureActivityLogExportRule(),
    AzureExposedComputeRule(),
    AzureUnguardedVmRule(),
    AzurePersonWithSubscriptionControlRule(),
    AzureWorkloadWithSubscriptionControlRule(),
    AzureRoleGrantingIdentityRule(),
    AzureExcessiveOwnersRule(),
    AzureBroadScopeAssignmentRule(),
    AzureDangerousCustomRoleRule(),
    AzureKeyVaultDeletionRule(),
    AzureKeyVaultNetworkRule(),
    AzureExposedVulnerableMachineRule(),
    AzureMissingEndpointProtectionRule(),
    # Role v7 and the checks on evidence already collected, batched as one
    # release (DECISIONS.md section 89).
    AzurePublicUdpRule(),
    AzureStorageCrossTenantReplicationRule(),
    AzureBlobSoftDeleteRule(),
    AzureSqlTlsRule(),
    AzureSqlEntraAdminRule(),
    AzurePostgresTlsRule(),
    AzureKeyVaultAccessModelRule(),
    AzureUnmanagedDiskRule(),
    AzureDefenderPlansRule(),
    AzureAppServiceHttpsRule(),
    AzureAppServiceTlsRule(),
    AzureAppServiceFtpRule(),
    AzureAppServiceRemoteDebuggingRule(),
    AzureAppServiceIdentityRule(),
    # AWS. Separate rules over the same neutral resource types, never one rule
    # branching on provider: ``remediation`` is snapshot-copied onto every
    # finding, and ``aws s3api put-public-access-block`` is not a variant of
    # ``az storage account update`` (MULTI_CLOUD.md section 6).
    AwsPublicBucketRule(),
    AwsBucketEncryptionRule(),
    AwsBucketTransportRule(),
    AwsPublicSshRule(),
    AwsPublicRdpRule(),
    AwsPublicDatabasePortRule(),
    AwsOpenNetworkAclRule(),
    AwsDefaultSecurityGroupRule(),
    AwsPublicDatabaseRule(),
    AwsDatabaseEncryptionRule(),
    AwsDatabasePatchingRule(),
    AwsUserWithoutMfaRule(),
    AwsRootAccessKeyRule(),
    AwsRootMfaRule(),
    AwsStaleAccessKeyRule(),
    AwsPasswordPolicyRule(),
    AwsAdministratorPolicyRule(),
    AwsExpiredCertificateRule(),
    AwsAccessAnalyzerRule(),
    AwsSupportRoleRule(),
    AwsInstanceMetadataRule(),
    AwsKeyRotationRule(),
    AwsCloudTrailCoverageRule(),
    AwsTrailValidationRule(),
    AwsTrailEncryptionRule(),
    AwsTrailBucketLoggingRule(),
    AwsConfigRecorderRule(),
    AwsFlowLogRule(),
    AwsUnauthorizedApiMonitoringRule(),
    AwsRootUsageMonitoringRule(),
    # The rest of CIS AWS section 4. One shape, thirteen events.
    AwsConsoleSignInWithoutMfaMonitoringRule(),
    AwsIamPolicyChangeMonitoringRule(),
    AwsTrailChangeMonitoringRule(),
    AwsConsoleAuthFailureMonitoringRule(),
    AwsKeyDisableMonitoringRule(),
    AwsBucketPolicyChangeMonitoringRule(),
    AwsConfigChangeMonitoringRule(),
    AwsSecurityGroupChangeMonitoringRule(),
    AwsNetworkAclChangeMonitoringRule(),
    AwsGatewayChangeMonitoringRule(),
    AwsRouteTableChangeMonitoringRule(),
    AwsVpcChangeMonitoringRule(),
    AwsOrganizationsChangeMonitoringRule(),
    AwsEbsDefaultEncryptionRule(),
    AwsGuardDutyRule(),
    AwsSecurityHubRule(),
]


def enabled_rules() -> list[SecurityRule]:
    """The rules the native engine evaluates. Never the Prowler checks."""
    return list(RULE_REGISTRY)


def catalogue_rules() -> list[SecurityRule]:
    """Every rule Cleave can raise a finding for, from either engine.

    What the ``rules`` mirror, the compliance view and a finding's rule lookup
    read. The native engine reads :func:`enabled_rules` instead: a Prowler
    check's verdict comes from the scanner's capture, never from evaluating it
    here (DECISIONS.md section 150).
    """
    return [*RULE_REGISTRY, *prowler_rules()]


def get_rule(rule_id: str) -> SecurityRule | None:
    native = next((r for r in RULE_REGISTRY if r.rule_id == rule_id), None)
    return native if native is not None else get_prowler_rule(rule_id)


def _assert_unique_rule_ids() -> None:
    """A duplicate rule_id would silently overwrite findings for another rule,
    since findings are keyed on (organization, rule_id, resource)."""
    seen: set[str] = set()
    for rule in catalogue_rules():
        if rule.rule_id in seen:
            raise RuntimeError(f"Duplicate rule_id in registry: {rule.rule_id}")
        seen.add(rule.rule_id)


_assert_unique_rule_ids()
