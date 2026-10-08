"""Opening a rule's fix pull request against a stubbed GitHub (DECISIONS.md §232).

The worker reads everything it needs before GitHub is asked, so ``open_on_github``
takes a ``Job`` and GitHub's answers; these prove what it opens, what it declines
and what the reviewer is told. The planning itself is ``test_pull_request_plan``.
"""

from typing import Any
from uuid import uuid4

import pytest

from app.core.config import settings
from app.integrations import github
from app.remediation.iac.pull_request import Target
from app.services import pull_requests as service
from app.services.pull_requests import Job

SUB = "/subscriptions/00000000-0000-0000-0000-000000000001/resourcegroups/rg/providers/"
LOGS = f"{SUB}microsoft.storage/storageaccounts/logs"
FILES = {
    "infra/main.tf": """\
resource "azurerm_storage_account" "logs" {
  name            = "${var.prefix}logs"
  min_tls_version = "TLS1_0"
}
""",
}


def _job(**fields: Any) -> Job:
    target = Target(uuid4(), LOGS, "azurerm_storage_account.logs", "infra")
    return Job(
        pull_request_id=uuid4(),
        organization_id=uuid4(),
        rule_id="AZ-STO-002",
        repository="contoso/infra",
        attempts=1,
        targets=fields.get("targets", [target]),
        instances={},
        failing={LOGS},
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
        return github.OpenedPullRequest(17, f"https://github.com/{full_name}/pull/17")

    for name, stub in {
        "repository_installation": repository_installation,
        "repository": repository,
        "installation_token": installation_token,
        "terraform_files": terraform_files,
        "open_pull_request": open_pull_request,
    }.items():
        monkeypatch.setattr(github, name, stub)
    return state


async def test_an_edit_opens_one_pull_request_from_its_own_branch(gh: dict[str, Any]) -> None:
    job = _job()
    result = await service.open_on_github(job)

    assert result.opened == github.OpenedPullRequest(17, "https://github.com/contoso/infra/pull/17")
    [opened] = gh["opened"]
    assert (opened["base"], opened["base_sha"]) == ("main", "head-sha")
    assert opened["branch"] == f"cloudguard/fix-az-sto-002-{str(job.pull_request_id)[:8]}"
    assert 'min_tls_version = "TLS1_2"' in opened["files"]["infra/main.tf"]


async def test_the_body_says_what_was_edited_and_where_to_follow_it(gh: dict[str, Any]) -> None:
    await service.open_on_github(_job())
    body = gh["opened"][0]["body"]
    assert "`azurerm_storage_account.logs` in `infra/main.tf`" in body
    assert "only when a scan observes the change" in body
    assert "https://app.cleave.test/remediation?rule=AZ-STO-002" in body


async def test_an_installation_no_longer_linked_opens_nothing(gh: dict[str, Any]) -> None:
    result = await service.open_on_github(_job(installations={99}))
    assert result.opened is None and result.declined
    assert gh["opened"] == []


async def test_a_repository_too_large_to_read_is_declined(gh: dict[str, Any]) -> None:
    gh["files"] = "The repository is too large for GitHub to list in one tree."
    result = await service.open_on_github(_job())
    assert result.declined == gh["files"]
    assert gh["opened"] == []


async def test_nothing_editable_opens_nothing(gh: dict[str, Any]) -> None:
    moved = [Target(uuid4(), LOGS, "azurerm_storage_account.gone", "infra")]
    result = await service.open_on_github(_job(targets=moved))
    assert result.opened is None
    assert [(o.edited, o.reason) for o in result.plan.outcomes] == [(False, "index_stale")]
    assert gh["opened"] == []
