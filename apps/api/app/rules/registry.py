"""The rule registry — the single source of truth for what CloudGuard checks.

The ``rules`` database table is a read-mirror of this list, synced at startup.
Adding a rule means adding it here and writing its tests; it never means
inserting a database row (RULE_ENGINE.md section 4).
"""

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
from app.rules.aws.identity.user_pools import RULES as USER_POOL_RULES
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
from app.rules.azure.analytics.databricks import (
    AzureDatabricksManagedServicesKeyRule,
    AzureDatabricksNoPublicIpRule,
    AzureDatabricksPublicNetworkRule,
    AzureDatabricksVnetInjectionRule,
)
from app.rules.azure.compute.disks import AzureUnmanagedDiskRule
from app.rules.azure.compute.exposure import (
    AzureExposedComputeRule,
    AzureLinuxPasswordSignInRule,
    AzureUnguardedVmRule,
)
from app.rules.azure.configuration import RULES as CONFIGURATION_RULES
from app.rules.azure.containers.kubernetes import (
    AzureClusterLocalAccountsRule,
    AzureClusterNetworkPolicyRule,
    AzureClusterNodePublicIpRule,
    AzureClusterPublicApiRule,
    AzureClusterRbacRule,
)
from app.rules.azure.containers.registry import (
    AzureRegistryAdminUserRule,
    AzureRegistryPrivateEndpointRule,
    AzureRegistryPublicNetworkRule,
)
from app.rules.azure.database.cosmos import (
    AzureCosmosLocalAuthRule,
    AzureCosmosPrivateEndpointRule,
    AzureCosmosPublicNetworkRule,
    AzureCosmosTlsRule,
)
from app.rules.azure.database.defences import RULES as SQL_DEFENCE_RULES
from app.rules.azure.database.encryption import AzureDatabaseEncryptionRule
from app.rules.azure.database.public_access import (
    AzureDatabaseAuditingRule,
    AzureDatabasePrivateConnectivityRule,
    AzurePublicDatabaseRule,
)
from app.rules.azure.database.transport import (
    AzureMySqlSecureTransportRule,
    AzureMySqlTlsVersionRule,
    AzurePostgresTlsRule,
    AzureSqlEntraAdminRule,
    AzureSqlTlsRule,
)
from app.rules.azure.hardening import RULES as HARDENING_RULES
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
from app.rules.azure.identity.tenant_hardening import RULES as TENANT_HARDENING_RULES
from app.rules.azure.identity.tenant_policy import (
    AzureAdminPortalMfaRule,
    AzureGuestDirectoryAccessRule,
    AzureGuestInviteRule,
    AzureM365GroupCreationRule,
    AzureManagementMfaRule,
    AzureStrongAuthenticationRule,
    AzureTrustedLocationRule,
    AzureUserConsentRule,
    AzureUserCreationRightsRule,
    AzureUsersRegisterAppsRule,
)
from app.rules.azure.logging.alerts import RULES as ALERT_RULES
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
    AzurePublicWebRule,
    AzurePublicWinRmRule,
    AzureSensitivePublicAddressRule,
)
from app.rules.azure.network.monitoring import RULES as NETWORK_MONITORING_RULES
from app.rules.azure.posture.defender import (
    AzureExposedVulnerableMachineRule,
    AzureMissingEndpointProtectionRule,
    AzureMissingVulnerabilityAssessmentRule,
)
from app.rules.azure.posture.plans import AzureDefenderPlansRule
from app.rules.azure.posture.settings import RULES as DEFENDER_SETTING_RULES
from app.rules.azure.rbac.privilege import (
    AzureBroadScopeAssignmentRule,
    AzureDangerousCustomRoleRule,
    AzureExcessiveOwnersRule,
    AzureLockAdministratorRoleRule,
    AzurePersonWithSubscriptionControlRule,
    AzureRoleGrantingIdentityRule,
    AzureSingleOwnerRule,
    AzureWorkloadWithSubscriptionControlRule,
)
from app.rules.azure.resilience import RULES as RESILIENCE_RULES
from app.rules.azure.search.search_service import AzureSearchPublicNetworkRule
from app.rules.azure.secrets.contents import RULES as VAULT_CONTENT_RULES
from app.rules.azure.secrets.key_vault import (
    AzureKeyVaultAccessModelRule,
    AzureKeyVaultDeletionRule,
    AzureKeyVaultNetworkRule,
)
from app.rules.azure.storage.access_and_logging import RULES as STORAGE_ACCESS_RULES
from app.rules.azure.storage.data_protection import (
    AzureBlobSoftDeleteRule,
    AzureStorageCrossTenantReplicationRule,
)
from app.rules.azure.storage.hygiene import RULES as STORAGE_HYGIENE_RULES
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
    AzureFunctionAppPublicRule,
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
    # The types role v9 reads (DECISIONS.md sections 169 and 170).
    AzureClusterPublicApiRule(),
    AzureClusterLocalAccountsRule(),
    AzureClusterRbacRule(),
    AzureClusterNodePublicIpRule(),
    AzureClusterNetworkPolicyRule(),
    AzureRegistryAdminUserRule(),
    AzureRegistryPublicNetworkRule(),
    AzureCosmosPublicNetworkRule(),
    AzureCosmosLocalAuthRule(),
    AzureCosmosTlsRule(),
    AzureDatabricksPublicNetworkRule(),
    AzureDatabricksNoPublicIpRule(),
    AzureDatabricksVnetInjectionRule(),
    AzureSearchPublicNetworkRule(),
    # Section 171.
    AzureRegistryPrivateEndpointRule(),
    AzureCosmosPrivateEndpointRule(),
    AzureDatabricksManagedServicesKeyRule(),
    AzureFunctionAppPublicRule(),
    AzureLinuxPasswordSignInRule(),
    # Section 172.
    AzureMySqlSecureTransportRule(),
    AzureMySqlTlsVersionRule(),
    AzureManagementMfaRule(),
    AzureAdminPortalMfaRule(),
    AzureUserConsentRule(),
    AzureUsersRegisterAppsRule(),
    AzureGuestInviteRule(),
    AzureGuestDirectoryAccessRule(),
    AzureUserCreationRightsRule(),
    # Section 173.
    AzureStrongAuthenticationRule(),
    AzureM365GroupCreationRule(),
    # Section 174: Tier 2, declared as property specs.
    *STORAGE_HYGIENE_RULES,
    # Section 175, and section 176's machine, disk and web app specs.
    *CONFIGURATION_RULES,
    # Section 176: the rest of Tier 2, under role v11.
    *DEFENDER_SETTING_RULES,
    AzureMissingVulnerabilityAssessmentRule(),
    *ALERT_RULES,
    *NETWORK_MONITORING_RULES,
    *VAULT_CONTENT_RULES,
    *SQL_DEFENCE_RULES,
    AzureTrustedLocationRule(),
    # Section 177: the misfiled checks and Tier 3.
    *RESILIENCE_RULES,
    # Section 204: the compliance controls a rule could answer and none did.
    *STORAGE_ACCESS_RULES,
    *HARDENING_RULES,
    *TENANT_HARDENING_RULES,
    AzurePublicWebRule(),
    AzureLockAdministratorRoleRule(),
    AzureSingleOwnerRule(),
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
    # Section 177: Cognito user pools, under policy v5.
    *USER_POOL_RULES,
]


def enabled_rules() -> list[SecurityRule]:
    """The rules the engine evaluates."""
    return list(RULE_REGISTRY)


def get_rule(rule_id: str) -> SecurityRule | None:
    return next((r for r in RULE_REGISTRY if r.rule_id == rule_id), None)


def _assert_unique_rule_ids() -> None:
    """A duplicate rule_id would silently overwrite findings for another rule,
    since findings are keyed on (organization, rule_id, resource)."""
    seen: set[str] = set()
    for rule in RULE_REGISTRY:
        if rule.rule_id in seen:
            raise RuntimeError(f"Duplicate rule_id in registry: {rule.rule_id}")
        seen.add(rule.rule_id)


_assert_unique_rule_ids()
