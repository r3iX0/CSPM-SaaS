"""Managed Kubernetes cluster rules (DECISIONS.md section 170).

A cluster is judged on what its ARM record states: who can reach its API
server, whether anything signs in around the directory, whether its own
authorization model is on, and what its nodes and pods can reach. Nothing here
reads inside the cluster -- no pod, no Kubernetes role binding -- because the
scanner holds no credential to it and never asks for one.

No policy is generated for any of these. Azure Policy has aliases for most of
the settings, and none has been verified from here; the rule about unverified
strings in ``remediation/spec.py`` applies (section 170).
"""

from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import Comparison, ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule

_NO_POLICY = (
    "No Azure Policy definition is generated: the policy aliases for this setting "
    "have not been verified yet (DECISIONS.md section 170)."
)

_MAPPINGS_EXPOSURE: dict[str, list[str]] = {
    "ISO_27001": ["A.8.20", "A.8.22"],
    "NIST_CSF": ["PR.AC-3", "PR.AC-5"],
    "GDPR": ["5(1)(f)", "32(1)(b)"],
    "NIST_800_53": ["SC-7", "AC-17"],
    "SOC2": ["CC6.1", "CC6.6"],
    "PCI_DSS_4": ["1.3.1", "1.4.1"],
}


class _ClusterRule(SecurityRule):
    """What every cluster rule shares: its type, its evidence, and its guard."""

    category = "compute"
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.KUBERNETES_CLUSTER]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.KUBERNETES_CLUSTERS,
    )

    def _unreadable(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | None:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Cluster configuration unavailable: {failure}")
        return None


class AzureClusterPublicApiRule(_ClusterRule):
    rule_id = "AZ-AKS-001"
    name = "Kubernetes API server answers the whole internet"
    description = (
        "A managed Kubernetes cluster's API server accepts connections from any "
        "address. It is private to no network and limited to no address range, so "
        "a stolen kubeconfig or a leaked token works from anywhere."
    )
    severity = Severity.HIGH
    # A credential is still needed. The API server is the control plane of every
    # workload on the cluster, and kubeconfigs are copied onto laptops and into
    # pipelines as a matter of routine.
    exploitability = 4
    estimated_effort_minutes = 60
    rationale = (
        "The API server is where every workload on the cluster is created, read and "
        "deleted. Left open, the only thing between the internet and it is whatever "
        "credential leaks next -- and cluster credentials travel: CI runners, "
        "developer laptops, shared kubeconfig files."
    )
    remediation = (
        "Limit the API server to the networks that operate the cluster.\n\n"
        "The lightest change is authorized IP ranges: only the named addresses can "
        "reach the API server. The strongest is a private cluster, whose API server "
        "has no public address at all -- which has to be planned, because everything "
        "that deploys to the cluster must then reach it privately.\n\n"
        "Azure CLI:\n"
        "  az aks update --name <cluster> --resource-group <rg> \\\n"
        "    --api-server-authorized-ip-ranges <cidr>"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="authorized_ip_ranges",
                equals=None,
                comparison=Comparison.NOT_EMPTY,
                example="203.0.113.0/24",
                describes="The API server accepts only named address ranges",
                terraform_attribute="api_server_access_profile.authorized_ip_ranges",
            ),
        ),
        cli=(
            "az aks update --name <cluster> --resource-group <rg> "
            "--api-server-authorized-ip-ranges <cidr>",
        ),
        notes=_NO_POLICY,
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = _MAPPINGS_EXPOSURE

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        blocked = self._unreadable(resource, context)
        if blocked or resource is None:
            return blocked or RuleResult.not_applicable("Rule is per-resource")

        ranges = resource.get("authorized_ip_ranges") or []
        evidence = {
            "private_cluster": resource.get("private_cluster"),
            "public_network_access": resource.get("public_network_access"),
            "authorized_ip_ranges": ranges,
            "fqdn": resource.get("fqdn"),
        }
        # Any one boundary is enough: a private cluster has no public API
        # server, public access off answers nobody, and named ranges answer
        # only them. A cluster whose record states none of them was created
        # with the defaults, which is the public one (section 169).
        if resource.get("private_cluster") is True:
            return RuleResult.passed(evidence)
        if str(resource.get("public_network_access") or "").lower() == "disabled":
            return RuleResult.passed(evidence)
        if ranges:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name}'s API server accepts connections from any address",
        )


class AzureClusterLocalAccountsRule(_ClusterRule):
    rule_id = "AZ-AKS-002"
    name = "Kubernetes cluster keeps local admin accounts"
    description = (
        "The cluster still issues its local cluster-admin credential. Whoever holds "
        "it is an administrator of the cluster without the directory being asked -- "
        "no multi-factor authentication, no Conditional Access, no sign-in record."
    )
    severity = Severity.HIGH
    exploitability = 3
    estimated_effort_minutes = 45
    rationale = (
        "A local admin kubeconfig is a static credential with no expiry, and it "
        "bypasses everything the directory enforces. Disabling it makes every "
        "sign-in to the cluster an Entra sign-in, subject to the tenant's own rules."
    )
    remediation = (
        "Disable local accounts, after confirming the cluster is integrated with "
        "Microsoft Entra ID and that the people and pipelines that operate it can "
        "sign in that way.\n\n"
        "Azure CLI:\n"
        "  az aks update --name <cluster> --resource-group <rg> --disable-local-accounts"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="local_accounts_disabled",
                equals=True,
                describes="Local accounts are disabled; every sign-in goes through Entra ID",
                terraform_attribute="local_account_disabled",
            ),
        ),
        cli=(
            "az aks update --name <cluster> --resource-group <rg> --disable-local-accounts",
        ),
        notes=_NO_POLICY,
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.5.15", "A.5.17"],
        "NIST_CSF": ["PR.AC-1", "PR.AC-7"],
        "GDPR": ["25", "32(1)(b)"],
        "NIST_800_53": ["IA-2", "AC-2"],
        "SOC2": ["CC6.1", "CC6.2"],
        "PCI_DSS_4": ["8.2.1", "8.4.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        blocked = self._unreadable(resource, context)
        if blocked or resource is None:
            return blocked or RuleResult.not_applicable("Rule is per-resource")

        disabled = resource.get("local_accounts_disabled")
        evidence = {
            "local_accounts_disabled": disabled,
            "entra_integrated": resource.get("entra_integrated"),
        }
        if disabled is True:
            return RuleResult.passed(evidence)
        # Absent is the service default, which keeps local accounts.
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} still issues its local cluster-admin credential",
        )


class AzureClusterRbacRule(_ClusterRule):
    rule_id = "AZ-AKS-003"
    name = "Kubernetes RBAC is disabled"
    description = (
        "The cluster runs without Kubernetes role-based access control, so anyone "
        "who can authenticate to it can do anything inside it."
    )
    severity = Severity.HIGH
    exploitability = 4
    estimated_effort_minutes = 240
    rationale = (
        "Without RBAC there is no least privilege inside the cluster: a pipeline "
        "that deploys one service can read every secret in every namespace."
    )
    remediation = (
        "Kubernetes RBAC cannot be switched on for an existing cluster. Create a "
        "replacement with RBAC enabled -- the default for every cluster created "
        "today -- and move workloads onto it.\n\n"
        "Azure CLI:\n"
        "  az aks create --name <cluster> --resource-group <rg> --enable-aad \\\n"
        "    --enable-azure-rbac"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="rbac_enabled",
                equals=True,
                describes="Kubernetes role-based access control is enabled",
                terraform_attribute="role_based_access_control_enabled",
            ),
        ),
        cli=(
            "az aks create --name <cluster> --resource-group <rg> --enable-aad "
            "--enable-azure-rbac",
        ),
        notes=_NO_POLICY,
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.5.15", "A.8.2"],
        "NIST_CSF": ["PR.AC-4"],
        "GDPR": ["25", "32(1)(b)"],
        "NIST_800_53": ["AC-3", "AC-6"],
        "SOC2": ["CC6.1", "CC6.3"],
        "PCI_DSS_4": ["7.2.1", "7.2.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        blocked = self._unreadable(resource, context)
        if blocked or resource is None:
            return blocked or RuleResult.not_applicable("Rule is per-resource")

        enabled = resource.get("rbac_enabled")
        if enabled is None:
            return RuleResult.unknown("The cluster's record does not say whether RBAC is on")
        evidence = {"rbac_enabled": enabled, "azure_rbac": resource.get("azure_rbac")}
        if enabled is True:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} runs without Kubernetes RBAC",
        )


class AzureClusterNodePublicIpRule(_ClusterRule):
    rule_id = "AZ-AKS-004"
    name = "Kubernetes nodes have public IP addresses"
    description = (
        "A node pool gives each of its machines a public IP address, so the nodes "
        "themselves answer the internet on whatever their network rules allow."
    )
    severity = Severity.MEDIUM
    exploitability = 3
    estimated_effort_minutes = 120
    rationale = (
        "Cluster nodes run every pod scheduled on them and hold the kubelet "
        "identity. A public address on each one turns a network rule mistake into "
        "direct access to the machines the whole cluster runs on."
    )
    remediation = (
        "Recreate the node pool without node public IPs and reach the internet "
        "through the cluster's load balancer or a NAT gateway instead. The setting "
        "cannot be changed on an existing pool.\n\n"
        "Azure CLI:\n"
        "  az aks nodepool add --cluster-name <cluster> --resource-group <rg> \\\n"
        "    --name <pool>"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="node_public_ip_pools",
                equals=None,
                comparison=Comparison.NONE_MATCHING,
                example="edge",
                describes="No node pool assigns public IP addresses to its nodes",
            ),
        ),
        cli=(
            "az aks nodepool add --cluster-name <cluster> --resource-group <rg> "
            "--name <pool>",
        ),
        notes=_NO_POLICY,
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = _MAPPINGS_EXPOSURE

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        blocked = self._unreadable(resource, context)
        if blocked or resource is None:
            return blocked or RuleResult.not_applicable("Rule is per-resource")

        pools = resource.get("node_public_ip_pools")
        if pools is None:
            return RuleResult.unknown("The cluster's node pools are not in the snapshot")
        evidence = {"node_public_ip_pools": pools}
        if not pools:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"{resource.name} gives public IP addresses to the nodes of "
                f"{', '.join(str(pool) for pool in pools)}"
            ),
        )


class AzureClusterNetworkPolicyRule(_ClusterRule):
    rule_id = "AZ-AKS-005"
    name = "Kubernetes cluster has no network policy engine"
    description = (
        "The cluster runs no network policy engine, so every pod can reach every "
        "other pod and nothing a team writes to restrict that is enforced."
    )
    severity = Severity.MEDIUM
    exploitability = 2
    estimated_effort_minutes = 180
    rationale = (
        "Without network policy one compromised pod can reach the database pods, "
        "the internal APIs and the metrics endpoints of every other service on the "
        "cluster. Policies can only be written once an engine enforces them."
    )
    remediation = (
        "Enable a network policy engine -- Azure, Calico or Cilium -- and then write "
        "policies that allow only the traffic each service needs.\n\n"
        "Azure CLI:\n"
        "  az aks update --name <cluster> --resource-group <rg> --network-policy azure"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=("az aks update --name <cluster> --resource-group <rg> --network-policy azure",),
        notes=(
            "Any of three engines satisfies this -- Azure, Calico or Cilium -- which "
            "a single expected value cannot state, and turning one on is the start of "
            "the work rather than the end of it: the policies are written per service."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.20", "A.8.22"],
        "NIST_CSF": ["PR.AC-5"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["SC-7"],
        "SOC2": ["CC6.6"],
        "PCI_DSS_4": ["1.2.1", "1.3.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        blocked = self._unreadable(resource, context)
        if blocked or resource is None:
            return blocked or RuleResult.not_applicable("Rule is per-resource")

        policy = resource.get("network_policy")
        evidence = {"network_policy": policy}
        if policy and str(policy).lower() != "none":
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} enforces no network policy between pods",
        )
