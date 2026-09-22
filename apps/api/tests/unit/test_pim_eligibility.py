"""Roles a principal could activate rather than holds (DECISIONS.md §130).

Privileged Identity Management turns standing access into access on request.
An eligible Owner holds nothing until they activate -- and activating can need
MFA, a reason or somebody's approval, none of which CloudGuard reads. So an
eligibility is listed, with what activating it would give, and is never walked
as a route. These pin both halves: the access view names eligible holders, and
the traversal, the lens and the rules never mistake them for standing access.
"""

from typing import Any

from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import NormalizedState, RawSnapshot
from app.core.enums import AccessKind, Level, Provider, RelationshipType, ResourceType
from app.domain.resource import CloudResource
from app.graph import AssetGraph

SUB_ID = "00000000-0000-0000-0000-00000000000c"
SUB = f"/subscriptions/{SUB_ID}"
RG = f"{SUB}/resourceGroups/rg-data"
LEDGER = f"{RG}/providers/Microsoft.Storage/storageAccounts/ledger"
OWNER_ID = f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/owner"
READER_ID = f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/reader"


def definitions() -> list[dict[str, Any]]:
    return [
        {
            "id": OWNER_ID,
            "properties": {"roleName": "Owner", "permissions": [{"actions": ["*"]}]},
        },
        {
            "id": READER_ID,
            "properties": {"roleName": "Reader", "permissions": [{"actions": ["*/read"]}]},
        },
    ]


def eligibility(principal: str, role: str, scope: str, status: str = "Provisioned") -> dict:
    return {
        "properties": {
            "principalId": principal,
            "principalType": "User",
            "roleDefinitionId": role,
            "scope": scope,
            "status": status,
        }
    }


def assignment(principal: str, role: str, scope: str) -> dict:
    return {
        "properties": {
            "principalId": principal,
            "principalType": "User",
            "roleDefinitionId": role,
            "scope": scope,
        }
    }


def snapshot(**data: Any) -> NormalizedState:
    return AzureNormalizer().normalize(
        RawSnapshot(
            provider=Provider.AZURE,
            tenant_id="t",
            subscription_id=SUB_ID,
            data={
                "storage_accounts": [
                    {
                        "id": LEDGER,
                        "name": "ledger",
                        "location": "westeurope",
                        "tags": {"data_classification": "restricted"},
                        "properties": {},
                    }
                ],
                "role_definitions": definitions(),
                **data,
            },
        )
    )


def exposed_user(**metadata: Any) -> CloudResource:
    return CloudResource(
        provider_resource_id="/users/u-1",
        resource_type=ResourceType.USER,
        name="Arben K",
        public_exposure=Level.HIGH,
        metadata={"identity_id": "u-1", **metadata},
    )


def graph_of(state: NormalizedState, *extra: CloudResource) -> AssetGraph:
    return AssetGraph.build([*state.resources, *extra], state.relationships)


def test_an_eligible_role_is_recorded_apart_from_the_roles_held() -> None:
    state = snapshot(
        role_assignments=[],
        role_eligibilities=[
            eligibility("u-1", OWNER_ID, SUB),
            eligibility("u-1", OWNER_ID, RG, status="Revoked"),
        ],
    )
    principal = next(r for r in state.resources if r.provider_resource_id == "/principals/u-1")
    # Not in ``roles``: the rules judge standing access, and PIM is their fix.
    assert "roles" not in principal.metadata
    (entry,) = principal.metadata["eligible_roles"]
    assert entry["role"] == "Owner"
    assert entry["eligible"] is True
    drawn = {r for s, r, _ in state.relationships if s == "/principals/u-1"}
    assert drawn == {RelationshipType.ELIGIBLE_FOR}


def test_an_eligible_owner_is_listed_and_never_walked() -> None:
    state = snapshot(role_assignments=[], role_eligibilities=[eligibility("u-1", OWNER_ID, SUB)])
    graph = graph_of(state, exposed_user())
    assert graph.attack_paths() == []

    (holder,) = graph.access_to(LEDGER)
    assert holder.eligible
    assert not holder.controls
    assert holder.role == "Owner"
    assert AccessKind.READ_DATA in holder.kinds

    (grant,) = graph.access_of("/users/u-1")
    assert grant.eligible
    assert {a.provider_resource_id for a in grant.controlled} == {LEDGER}


def test_an_eligible_role_does_not_widen_the_role_held_beside_it() -> None:
    """Reader held, Owner eligible, same scope: the lens is Reader's."""
    state = snapshot(
        role_assignments=[assignment("u-1", READER_ID, SUB)],
        role_eligibilities=[eligibility("u-1", OWNER_ID, SUB)],
    )
    graph = graph_of(state, exposed_user())
    assert graph.attack_paths() == []
    held = {(h.role, h.eligible) for h in graph.access_to(LEDGER)}
    assert held == {("Reader", False), ("Owner", True)}


# ---------------------------------------------------------------- directory
def directory(**data: Any) -> NormalizedState:
    return AzureNormalizer().normalize(
        RawSnapshot(provider=Provider.AZURE, tenant_id="t", subscription_id=None, data=data)
    )


def directory_eligibility(
    principal: str, role: str, scope: str = "/", kind: str = "user"
) -> dict[str, Any]:
    return {
        "principalId": principal,
        "directoryScopeId": scope,
        "roleDefinition": {"displayName": role},
        "principal": {"@odata.type": f"#microsoft.graph.{kind}"},
    }


def test_an_eligible_global_administrator_is_recorded_not_empowered() -> None:
    state = directory(
        users=[{"id": "u-1", "displayName": "A"}],
        directory_role_eligibilities=[
            directory_eligibility("u-1", "Global Administrator"),
            # Scoped to an administrative unit: no power over the tenant.
            directory_eligibility(
                "u-1", "Application Administrator", scope="/administrativeUnits/x"
            ),
            directory_eligibility(
                "sp-1", "Privileged Role Administrator", kind="servicePrincipal"
            ),
        ],
    )
    by_id = {r.provider_resource_id: r for r in state.resources}
    user = by_id["/users/u-1"]
    assert user.metadata["directory_powers"] == []
    assert user.metadata["eligible_directory_roles"] == ["Global Administrator"]
    assert user.metadata["eligible_directory_powers"] == [
        {"power": "control_all_scopes", "via": "Global Administrator"}
    ]
    principal = by_id["/principals/sp-1"]
    assert principal.metadata["directory_powers"] == []
    assert principal.metadata["eligible_directory_powers"][0]["power"] == "control_all_scopes"


def test_an_eligible_global_administrator_is_listed_on_every_subscription() -> None:
    state = snapshot(role_assignments=[], role_eligibilities=[])
    graph = graph_of(
        state,
        exposed_user(
            eligible_directory_powers=[
                {"power": "control_all_scopes", "via": "Global Administrator"}
            ]
        ),
    )
    assert graph.attack_paths() == []
    assert not any(r is RelationshipType.CAN_TAKE_OVER for _, r, _ in graph.links())
    (holder,) = graph.access_to(LEDGER)
    assert (holder.role, holder.eligible, holder.through_directory) == (
        "Global Administrator",
        True,
        True,
    )
    (grant,) = graph.access_of("/users/u-1")
    assert grant.eligible
    assert grant.through_directory
