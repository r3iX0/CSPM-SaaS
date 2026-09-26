"""One identity, one node, and a group's role reaching its members (DECISIONS.md §126).

A scan normalizes the directory and each subscription separately, so a person
arrived twice: once as a directory account with a way in and no roles, once as
a stand-in with the roles and no way in. A group holding a role was a stand-in
too, named by the start of its id and reaching nobody. These pin the join that
makes each identity one node, the membership edges that let a group's role
reach its members, the collection that reads them, and the access view that
names them.
"""

from typing import Any

import httpx

from app.connectors.azure.access import access_profile
from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.azure.plan import AzurePlanBuilder
from app.connectors.base import NormalizedState, RawSnapshot
from app.connectors.collection import CollectionTask
from app.core.enums import Level, Provider, RelationshipType, ResourceType
from app.domain.resource import CloudResource
from app.graph import AssetGraph

BLOB_READER: dict[str, Any] = {
    "actions": [],
    "dataActions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
}

SUB = "/sub-a"
LEDGER = "/sub-a/ledger"
USER = "/users/u-1"
STUB = "/principals/u-1"
GROUP = "/principals/g-1"


def definition(block: dict[str, Any]) -> dict[str, Any]:
    return {"id": "role", "properties": {"roleName": "Role", "permissions": [block]}}


def role(name: str, target: str, block: dict[str, Any]) -> dict[str, Any]:
    return {
        "role": name,
        "scope": target,
        "target": target,
        "grants_role_assignment": False,
        "conditional": False,
        "inherited_from": None,
        "access": access_profile(definition(block)),
    }


def node(
    rid: str,
    kind: ResourceType,
    *,
    name: str | None = None,
    exposure: Level = Level.UNKNOWN,
    sensitivity: Level = Level.UNKNOWN,
    metadata: dict[str, Any] | None = None,
) -> CloudResource:
    return CloudResource(
        provider_resource_id=rid,
        resource_type=kind,
        name=name or rid.rsplit("/", 1)[-1],
        public_exposure=exposure,
        data_sensitivity=sensitivity,
        metadata=metadata or {},
    )


def scopes() -> list[CloudResource]:
    return [
        node(SUB, ResourceType.SUBSCRIPTION),
        node(LEDGER, ResourceType.STORAGE_ACCOUNT, sensitivity=Level.CRITICAL),
    ]


def directory_user() -> CloudResource:
    return node(
        USER,
        ResourceType.USER,
        name="Arben K",
        exposure=Level.HIGH,
        metadata={"identity_id": "u-1", "user_type": "Member"},
    )


def test_a_person_read_in_two_captures_is_one_node_with_a_route() -> None:
    stub = node(
        STUB,
        ResourceType.SERVICE_PRINCIPAL,
        metadata={
            "identity_id": "u-1",
            "stub": True,
            "roles": [role("Storage Blob Data Reader", SUB, BLOB_READER)],
        },
    )
    edges = [
        (SUB, RelationshipType.CONTAINS, LEDGER),
        (STUB, RelationshipType.GRANTS_ROLE, SUB),
    ]
    graph = AssetGraph.build([*scopes(), stub, directory_user()], edges)

    assert STUB not in graph.nodes
    assert graph.resolve(STUB) == USER
    assert graph.nodes[USER].name == "Arben K"
    assert graph.nodes[USER].metadata["user_type"] == "Member"
    assert "stub" not in graph.nodes[USER].metadata
    # The account is the way in, and now it holds the role.
    (path,) = graph.attack_paths()
    assert path.entry.provider_resource_id == USER
    assert path.target.provider_resource_id == LEDGER
    # A page opened on the stand-in is answered about the person.
    assert [g.role for g in graph.access_of(STUB)] == ["Storage Blob Data Reader"]
    # And the stand-in's own copy was not changed by the join.
    assert "roles" not in directory_user().metadata


def test_a_principal_minted_in_two_subscriptions_keeps_both_sets_of_roles() -> None:
    other_sub, other_ledger = "/sub-b", "/sub-b/ledger"

    def copy(scope: str) -> CloudResource:
        return node(
            STUB,
            ResourceType.SERVICE_PRINCIPAL,
            metadata={
                "identity_id": "u-1",
                "stub": True,
                "roles": [role("Blob reader", scope, BLOB_READER)],
            },
        )

    graph = AssetGraph.build(
        [
            *scopes(),
            node(other_sub, ResourceType.SUBSCRIPTION),
            node(other_ledger, ResourceType.STORAGE_ACCOUNT, sensitivity=Level.HIGH),
            copy(SUB),
            copy(other_sub),
        ],
        [
            (SUB, RelationshipType.CONTAINS, LEDGER),
            (other_sub, RelationshipType.CONTAINS, other_ledger),
            (STUB, RelationshipType.GRANTS_ROLE, SUB),
            (STUB, RelationshipType.GRANTS_ROLE, other_sub),
        ],
    )
    assert {r.provider_resource_id for r in graph.blast_radius(STUB)} == {LEDGER, other_ledger}
    assert len(graph.nodes[STUB].metadata["roles"]) == 2


MEMBERS: list[dict[str, Any]] = [
    {"id": "u-1", "kind": "user", "name": "Arben K"},
    {"id": "u-2", "kind": "user", "name": "Somebody Else"},
    {"id": "g-2", "kind": "group", "name": "Nested"},
]


def grouped(members: list[dict[str, Any]] | None = MEMBERS) -> AssetGraph:
    group = node(
        GROUP,
        ResourceType.GROUP,
        name="Data readers",
        metadata={
            "identity_id": "g-1",
            "stub": True,
            "members": members,
            "roles": [role("Storage Blob Data Reader", SUB, BLOB_READER)],
        },
    )
    return AssetGraph.build(
        [*scopes(), directory_user(), group],
        [
            (SUB, RelationshipType.CONTAINS, LEDGER),
            (GROUP, RelationshipType.GRANTS_ROLE, SUB),
        ],
    )


def test_a_group_role_reaches_its_members_through_a_membership_edge() -> None:
    graph = grouped()
    (path,) = graph.attack_paths()
    assert path.entry.provider_resource_id == USER
    assert [step.relationship for step in path.steps] == [
        RelationshipType.MEMBER_OF,
        RelationshipType.GRANTS_ROLE,
        RelationshipType.CONTAINS,
    ]
    # Taking the person out of the group closes it.
    closed = graph.link_severance()[(USER, RelationshipType.MEMBER_OF.value, GROUP)]
    assert [p.target.provider_resource_id for p in closed] == [LEDGER]


def test_a_group_holder_names_its_members_drawn_and_unread() -> None:
    (holder,) = grouped().access_to(LEDGER)
    assert holder.principal.provider_resource_id == GROUP
    assert holder.members is not None
    assert [m.provider_resource_id for m in holder.members] == [USER]
    # Read as a name only; a nested group's people are already listed.
    assert holder.unlisted_members == ("Somebody Else",)


def test_a_group_whose_members_were_not_read_does_not_claim_nobody() -> None:
    graph = grouped(None)
    (holder,) = graph.access_to(LEDGER)
    assert holder.members is None
    assert graph.attack_paths() == []


def test_a_person_sees_the_roles_they_hold_through_a_group() -> None:
    (grant,) = grouped().access_of(USER)
    assert grant.via is not None and grant.via.provider_resource_id == GROUP
    assert [a.provider_resource_id for a in grant.controlled] == [LEDGER]


# --------------------------------------------------------------- normalizer
SUB_ID = "00000000-0000-0000-0000-00000000000b"


def normalize(data: dict[str, Any]) -> NormalizedState:
    return AzureNormalizer().normalize(
        RawSnapshot(provider=Provider.AZURE, tenant_id="t", subscription_id=SUB_ID, data=data)
    )


def assignment(principal_id: str, principal_type: str) -> dict[str, Any]:
    return {
        "properties": {
            "principalId": principal_id,
            "principalType": principal_type,
            "roleDefinitionId": "def-reader",
            "scope": f"/subscriptions/{SUB_ID}",
        }
    }


def test_a_role_holding_group_is_a_group_with_its_members_recorded() -> None:
    state = normalize(
        {
            "role_definitions": [
                {"id": "def-reader", "properties": {"roleName": "Reader", "permissions": []}}
            ],
            "role_assignments": [assignment("g-1", "Group"), assignment("g-9", "Group")],
            "role_group_members": {
                "g-1": {
                    "display_name": "Platform admins",
                    "members": [
                        {"id": "u-1", "type": "#microsoft.graph.user", "display_name": "Arben"},
                        {"id": "d-1", "type": "#microsoft.graph.device", "display_name": "pc"},
                    ],
                }
            },
        }
    )
    groups = {
        r.provider_resource_id: r
        for r in state.resources
        if r.resource_type is ResourceType.GROUP
    }
    read = groups["/principals/g-1"]
    assert read.name == "Platform admins"
    assert read.metadata["identity_id"] == "g-1"
    assert read.metadata["members"] == [{"id": "u-1", "kind": "user", "name": "Arben"}]
    # Its read failed: named by its id, membership unknown rather than empty.
    unread = groups["/principals/g-9"]
    assert unread.name == "Group g-9"
    assert unread.metadata["members"] is None


def test_a_directory_account_carries_the_id_assignments_name_it_by() -> None:
    state = normalize({"users": [{"id": "u-1", "displayName": "Arben"}]})
    (user,) = [r for r in state.resources if r.resource_type is ResourceType.USER]
    assert user.metadata["identity_id"] == "u-1"


# --------------------------------------------------------------- collection
class FakeTokens:
    tenant_id = "t"

    def arm_token(self) -> str:
        return "arm"

    def graph_token(self) -> str:
        return "graph"


def graph_answering(fail: tuple[str, ...] = ()) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if any(fragment in path for fragment in fail):
            return httpx.Response(403, json={"error": {"message": "denied"}})
        if path.endswith("/transitiveMembers"):
            return httpx.Response(
                200,
                json={
                    "value": [
                        {"@odata.type": "#microsoft.graph.user", "id": "u-1", "displayName": "A"}
                    ]
                },
            )
        if path.endswith("/groups"):
            return httpx.Response(200, json={"value": [{"id": "g-1", "displayName": "Admins"}]})
        return httpx.Response(404, json={"error": {"message": "unexpected"}})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def task(client: httpx.AsyncClient) -> CollectionTask:
    builder = AzurePlanBuilder(FakeTokens(), SUB_ID, client)  # type: ignore[arg-type]
    return builder._role_group_members_task()


COLLECTED = {
    "role_assignments": [
        assignment("g-1", "Group"),
        assignment("sp-1", "ServicePrincipal"),
    ]
}


async def test_only_groups_that_hold_a_role_are_read() -> None:
    result = await task(graph_answering()).run(COLLECTED)
    assert result.partial_reason is None
    assert result.data == {
        "role_group_members": {
            "g-1": {
                "display_name": "Admins",
                "members": [{"id": "u-1", "type": "#microsoft.graph.user", "display_name": "A"}],
            }
        }
    }


async def test_no_role_holding_group_means_no_call() -> None:
    result = await task(graph_answering(fail=("/",))).run(
        {"role_assignments": [assignment("sp-1", "ServicePrincipal")]}
    )
    assert result.data == {"role_group_members": {}}
    assert result.partial_reason is None


async def test_a_group_whose_members_could_not_be_read_is_absent_and_said() -> None:
    result = await task(graph_answering(fail=("transitiveMembers",))).run(COLLECTED)
    assert result.data == {"role_group_members": {}}
    assert result.partial_reason is not None
    assert "1 of 1" in result.partial_reason


def test_everyone_in_a_group_is_one_route_said_once() -> None:
    """A group of a hundred readers is one pattern, not a hundred routes (§123)."""
    from app.graph.patterns import PatternKind, route_patterns

    second = node(
        "/users/u-2",
        ResourceType.USER,
        exposure=Level.HIGH,
        metadata={"identity_id": "u-2"},
    )
    group = node(
        GROUP,
        ResourceType.GROUP,
        metadata={
            "identity_id": "g-1",
            "stub": True,
            "members": MEMBERS[:1] + [{"id": "u-2", "kind": "user", "name": "B"}],
            "roles": [role("Storage Blob Data Reader", SUB, BLOB_READER)],
        },
    )
    graph = AssetGraph.build(
        [*scopes(), directory_user(), second, group],
        [(SUB, RelationshipType.CONTAINS, LEDGER), (GROUP, RelationshipType.GRANTS_ROLE, SUB)],
    )
    patterns, loose = route_patterns(graph.attack_paths())
    assert [(p.kind, p.size) for p in patterns] == [(PatternKind.MANY_ENTRIES, 2)]
    assert loose == []
