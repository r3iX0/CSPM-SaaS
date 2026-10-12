"""Opening a cut's pull request against a stubbed GitHub (DECISIONS.md §258).

The worker reads everything before GitHub is asked, so ``open_on_github`` takes
a ``Job`` and GitHub's answers: these prove what it deletes and opens, what it
declines, and what the reviewer is told. The deletion itself is
``test_cut_removal``.
"""

from typing import Any
from uuid import uuid4

import pytest

from app.core.config import settings
from app.core.enums import RelationshipType
from app.integrations import github
from app.remediation.iac.cut import AssignmentTarget
from app.remediation.iac.pull_request import block_key
from app.services import cut_pull_requests as service
from app.services.cut_fix import cut_key
from app.services.cut_pull_requests import Job

SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourcegroups/rg"
APP = f"{SCOPE}/providers/microsoft.authorization/roleassignments/app"
SHARED_0, SHARED_1 = (
    f"{SCOPE}/providers/microsoft.authorization/roleassignments/shared-{n}" for n in (0, 1)
)
FILES = {
    "infra/main.tf": """\
resource "azurerm_role_assignment" "app" {
  scope                = azurerm_resource_group.rg.id
  role_definition_name = "Owner"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

resource "azurerm_role_assignment" "shared" {
  count                = 2
  scope                = azurerm_resource_group.rg.id
  role_definition_name = "Reader"
  principal_id         = var.principals[count.index]
}
""",
}
CUT = {
    "sentence": "Remove the Owner role from mi-app on rg.",
    "detail": "mi-app can act over rg (Owner)",
}


def _job(**fields: Any) -> Job:
    return Job(
        pull_request_id=uuid4(),
        repository="contoso/infra",
        attempts=1,
        cut=CUT,
        targets=fields.get(
            "targets", [AssignmentTarget(APP, "azurerm_role_assignment.app", "infra")]
        ),
        instances=fields.get("instances", {}),
        installations=fields.get("installations", {7}),
    )


@pytest.fixture
def gh(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"installation": 7, "files": ("head-sha", FILES), "opened": []}
    monkeypatch.setattr(settings, "app_url", "https://app.cleave.test")

    async def repository_installation(full_name: str) -> int | None:
        return state["installation"]

    async def repository(full_name: str, installation_id: int) -> github.Repository:
        return github.Repository(42, full_name, "main")

    async def installation_token(installation_id: int) -> str:
        return "installation-token"

    async def terraform_files(full_name: str, branch: str, token: str) -> Any:
        return state["files"]

    async def open_pull_request(full_name: str, **kwargs: Any) -> github.OpenedPullRequest:
        state["opened"].append(kwargs)
        return github.OpenedPullRequest(23, f"https://github.com/{full_name}/pull/23")

    for name, stub in {
        "repository_installation": repository_installation,
        "repository": repository,
        "installation_token": installation_token,
        "terraform_files": terraform_files,
        "open_pull_request": open_pull_request,
    }.items():
        monkeypatch.setattr(github, name, stub)
    return state


async def test_a_cut_opens_one_pull_request_deleting_its_block(gh: dict[str, Any]) -> None:
    job = _job()
    result = await service.open_on_github(job)

    assert result.opened is not None
    [opened] = gh["opened"]
    assert opened["branch"] == f"cloudguard/cut-{str(job.pull_request_id)[:8]}"
    assert opened["title"] == "Cleave: Remove the Owner role from mi-app on rg"
    text = opened["files"]["infra/main.tf"]
    assert '"Owner"' not in text
    assert '"Reader"' in text


async def test_the_body_says_what_was_deleted_and_that_a_merge_proves_nothing(
    gh: dict[str, Any],
) -> None:
    await service.open_on_github(_job())
    body = gh["opened"][0]["body"]
    assert "`azurerm_role_assignment.app` in `infra/main.tf`" in body
    assert "only when a scan no longer sees the link" in body
    assert "https://app.cleave.test/attack-paths" in body


async def test_a_shared_block_is_not_deleted_and_nothing_opens(gh: dict[str, Any]) -> None:
    job = _job(
        targets=[AssignmentTarget(SHARED_0, "azurerm_role_assignment.shared[0]", "infra")],
        instances={block_key("infra", "azurerm_role_assignment.shared"): {SHARED_0, SHARED_1}},
    )
    result = await service.open_on_github(job)

    assert result.opened is None
    assert result.declined == "No role assignment block this cut covers could be deleted."
    assert result.removal.outcomes[0].reason == "count_or_for_each"
    assert gh["opened"] == []


async def test_an_installation_no_longer_linked_opens_nothing(gh: dict[str, Any]) -> None:
    result = await service.open_on_github(_job(installations={99}))
    assert result.opened is None
    assert "no longer linked" in (result.declined or "")


def test_an_escalation_line_is_keyed_as_its_assignment() -> None:
    """Both lines are one assignment, so one pull request (§127)."""
    assert cut_key("a", RelationshipType.CAN_GRANT_ROLES, "b") == cut_key(
        "a", RelationshipType.GRANTS_ROLE, "b"
    )
