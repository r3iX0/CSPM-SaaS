"""How a cut is said and, where one command does it, made (DECISIONS.md section 246).

The sentence is neutral and built from the link's own facts; the command is the
provider's, written only where the link names exactly one thing to remove.
"""

from app.connectors.aws.connector import AwsConnector
from app.connectors.azure.connector import AzureConnector
from app.connectors.azure.cuts import cut_commands
from app.core.enums import Provider, RelationshipType, ResourceType
from app.domain.resource import CloudResource
from app.graph import PathStep
from app.schemas.attack_path import SignInOut
from app.services.cut_fix import cut_sentence
from app.services.inspect import sign_in

SCOPE = "/subscriptions/s/resourceGroups/rg-data"


def principal(**metadata: object) -> CloudResource:
    return CloudResource(
        provider_resource_id="/principals/p-1",
        resource_type=ResourceType.SERVICE_PRINCIPAL,
        name="mi-payments",
        provider=Provider.AZURE,
        metadata=dict(metadata),
    )


def machine(name: str) -> CloudResource:
    return CloudResource(
        provider_resource_id=f"/vm/{name}",
        resource_type=ResourceType.VIRTUAL_MACHINE,
        name=name,
    )


GROUP = CloudResource(
    provider_resource_id=SCOPE,
    resource_type=ResourceType.RESOURCE_GROUP,
    name="rg-data",
    provider=Provider.AZURE,
)


def role(name: str, scope: str = SCOPE) -> dict[str, object]:
    return {"role": name, "scope": scope, "target": SCOPE}


# ------------------------------------------------------------------- sentence
def test_a_role_cut_names_the_roles_it_removes() -> None:
    holder = principal(roles=[role("Owner"), role("Reader")])
    step = PathStep(holder, RelationshipType.GRANTS_ROLE, GROUP)
    assert cut_sentence(step) == "Remove the Owner and Reader roles from mi-payments on rg-data."


def test_a_role_cut_with_no_recorded_role_says_access() -> None:
    step = PathStep(principal(), RelationshipType.GRANTS_ROLE, GROUP)
    assert cut_sentence(step) == (
        "Remove the role assignments that give mi-payments access to rg-data."
    )


def test_a_runs_as_cut_offers_the_role_beyond_it() -> None:
    """Detaching an identity may break the workload, so the role is the other way."""
    step = PathStep(machine("vm-web"), RelationshipType.HAS_IDENTITY, principal())
    assert "or remove the roles mi-payments holds" in cut_sentence(step)


def test_a_network_cut_is_a_path_to_close() -> None:
    step = PathStep(machine("a"), RelationshipType.NETWORK_ACCESS, machine("b"))
    assert cut_sentence(step) == "Close the network path from a to b."


# ------------------------------------------------------------------- commands
def test_a_role_cut_deletes_each_assignment_by_assignee_role_and_scope() -> None:
    holder = principal(principal_id="0000-p", roles=[role("Owner"), role("Key Vault Secrets User")])
    commands = cut_commands(holder, RelationshipType.GRANTS_ROLE, GROUP)
    assert commands == [
        f"az role assignment delete --assignee 0000-p --role Owner --scope {SCOPE}",
        "az role assignment delete --assignee 0000-p --role 'Key Vault Secrets User' "
        f"--scope {SCOPE}",
    ]


def test_an_inherited_assignment_is_deleted_where_it_was_made() -> None:
    root = "/providers/Microsoft.Management/managementGroups/corp"
    holder = principal(principal_id="0000-p", roles=[role("Owner", scope=root)])
    [command] = cut_commands(holder, RelationshipType.GRANTS_ROLE, GROUP)
    assert command.endswith(f"--scope {root}")


def test_no_command_is_guessed_without_an_object_id_or_a_role_name() -> None:
    nameless = principal(roles=[role("Owner")])
    assert cut_commands(nameless, RelationshipType.GRANTS_ROLE, GROUP) == []
    unknown = principal(principal_id="0000-p", roles=[role("Unknown role")])
    assert cut_commands(unknown, RelationshipType.GRANTS_ROLE, GROUP) == []


def test_a_network_or_identity_cut_has_no_single_command() -> None:
    holder = principal(principal_id="0000-p")
    assert cut_commands(holder, RelationshipType.NETWORK_ACCESS, GROUP) == []
    assert cut_commands(holder, RelationshipType.HAS_IDENTITY, GROUP) == []


def test_the_command_comes_from_the_connector_and_aws_offers_none() -> None:
    """AWS has never run against a live account, so it names no command yet."""
    holder = principal(principal_id="0000-p", roles=[role("Owner")])
    assert AzureConnector.cut_commands(holder, RelationshipType.GRANTS_ROLE, GROUP)
    assert AwsConnector.cut_commands(holder, RelationshipType.GRANTS_ROLE, GROUP) == []


# ------------------------------------------------------------------ inspector
def test_an_account_with_no_sign_in_reading_is_not_said_to_be_dormant() -> None:
    """No reading is not "never signed in" (DECISIONS.md section 254)."""
    unread = CloudResource(
        provider_resource_id="/users/u-1", resource_type=ResourceType.USER, name="u"
    )
    read = CloudResource(
        provider_resource_id="/users/u-2",
        resource_type=ResourceType.USER,
        name="u",
        metadata={"sign_in_activity_read": True, "last_sign_in": None},
    )
    assert sign_in(unread) == SignInOut(read=False, last_sign_in=None, days_since=None)
    assert sign_in(read) == SignInOut(read=True, last_sign_in=None, days_since=None)
    assert sign_in(machine("vm")) is None
