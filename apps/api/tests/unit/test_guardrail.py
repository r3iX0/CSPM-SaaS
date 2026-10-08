"""The pull-request guardrail: a plan cut to what rules read, judged, and reported (§234).

A plan upload holds only allowlisted arguments, or is refused whole. A failure
counts against the pull request only where the change brings it; an unknown
value is never a pass. GitHub is stubbed: these prove the decisions, not the wire.
"""

from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.errors import CodeHostError, PermissionDenied, ValidationFailed
from app.integrations import github
from app.integrations.github_oidc import ActionsIdentity
from app.main import app
from app.remediation.iac.guardrail import (
    GuardedRule,
    InvalidPlan,
    Judged,
    PlannedResource,
    Verdict,
    allowlist,
    conclusion,
    judge,
    resources_from_upload,
)
from app.remediation.iac.terraform import Change, Renamed, RuleChanges
from app.schemas.code_integration import GuardrailPlanIn, PlannedResourceIn
from app.services import guardrail as service
from app.services.code_integrations import LinkedRepository

TLS = GuardedRule(
    "AZ-STO-002",
    "Storage accounts require TLS 1.2",
    "HIGH",
    RuleChanges(
        resource_types=("azurerm_storage_account",),
        changes=(Change("min_tls_version", '"TLS1_2"', ('"TLS1_3"',)),),
    ),
)
NETWORK = GuardedRule(
    "AZ-STO-005",
    "Storage accounts deny by default",
    "MEDIUM",
    RuleChanges(
        resource_types=("azurerm_storage_account",),
        changes=(
            Change("network_rules.default_action", '"Deny"'),
            Change("public_network_access_enabled", "false"),
        ),
    ),
)
LOCAL_AUTH = GuardedRule(
    "AZ-COS-002",
    "Cosmos DB refuses keys",
    "HIGH",
    RuleChanges(
        resource_types=("azurerm_cosmosdb_account",),
        changes=(
            Change(
                "local_authentication_disabled",
                "true",
                renamed=(Renamed(4, "local_authentication_enabled", "false"),),
            ),
        ),
    ),
)
RULES = (TLS, NETWORK, LOCAL_AUTH)


def _resource(
    after: dict[str, Any],
    *,
    actions: tuple[str, ...] = ("create",),
    before: dict[str, Any] | None = None,
    unknown: frozenset[str] = frozenset(),
    address: str = "azurerm_storage_account.logs",
) -> PlannedResource:
    return PlannedResource(
        address=address,
        type=address.rsplit(".", 2)[-2],
        actions=actions,
        after=after,
        before=before or {},
        unknown=unknown,
    )


def _one(resource: PlannedResource, rule: GuardedRule = TLS) -> Judged:
    [judged] = judge([resource], [rule])
    return judged


# ---------------------------------------------------------------- allowlist
def test_the_allowlist_is_every_name_a_rule_reads_per_type() -> None:
    assert allowlist(RULES) == {
        "azurerm_cosmosdb_account": [
            "local_authentication_disabled",
            "local_authentication_enabled",
        ],
        "azurerm_storage_account": [
            "min_tls_version",
            "network_rules.default_action",
            "public_network_access_enabled",
        ],
    }


def _upload(**resource: Any) -> list[dict[str, Any]]:
    return [
        {
            "address": "azurerm_storage_account.logs",
            "type": "azurerm_storage_account",
            "actions": ["create"],
            "after": {"min_tls_version": "TLS1_0"},
            **resource,
        }
    ]


def test_an_upload_of_allowlisted_values_is_read() -> None:
    [resource] = resources_from_upload(_upload(unknown=["min_tls_version"]), allowlist(RULES))
    assert resource.after == {"min_tls_version": "TLS1_0"}
    assert resource.unknown == {"min_tls_version"}


@pytest.mark.parametrize(
    "resource",
    [
        {"after": {"primary_access_key": "secret"}},
        {"before": {"tags.owner": "me"}},
        {"unknown": ["primary_connection_string"]},
        {"after": {"min_tls_version": {"nested": True}}},
        {"after": {"min_tls_version": "x" * 1001}},
        {"actions": ["destroy"]},
        {"type": "azurerm_key_vault"},
        {"address": "aws_s3_bucket.logs", "type": "aws_s3_bucket"},
        {"values": {}},
    ],
    ids=[
        "an_argument_no_rule_reads",
        "a_prior_value_no_rule_reads",
        "an_unknown_no_rule_reads",
        "not_one_value",
        "a_value_longer_than_one",
        "an_action_terraform_does_not_write",
        "a_type_the_address_is_not",
        "another_provider",
        "a_field_the_action_does_not_send",
    ],
)
def test_anything_else_refuses_the_whole_upload(resource: dict[str, Any]) -> None:
    with pytest.raises(InvalidPlan):
        resources_from_upload(_upload(**resource), allowlist(RULES))


def test_an_address_twice_refuses_the_upload() -> None:
    with pytest.raises(InvalidPlan):
        resources_from_upload(_upload() * 2, allowlist(RULES))


# -------------------------------------------------------------------- judging
def test_a_new_resource_that_fails_brings_the_failure() -> None:
    judged = _one(_resource({"min_tls_version": "TLS1_0"}))
    assert (judged.verdict, judged.introduced) == (Verdict.FAIL, True)
    assert (judged.attribute, judged.planned, judged.expected) == (
        "min_tls_version",
        '"TLS1_0"',
        '"TLS1_2"',
    )


def test_a_value_the_rule_also_accepts_passes() -> None:
    assert _one(_resource({"min_tls_version": "TLS1_3"})).verdict is Verdict.PASS


def test_a_change_that_breaks_a_passing_resource_brings_the_failure() -> None:
    resource = _resource(
        {"min_tls_version": "TLS1_0"}, actions=("update",), before={"min_tls_version": "TLS1_2"}
    )
    assert _one(resource).introduced


def test_a_failure_the_resource_already_had_is_not_the_changes() -> None:
    resource = _resource(
        {"min_tls_version": "TLS1_0"}, actions=("update",), before={"min_tls_version": "TLS1_0"}
    )
    judged = _one(resource)
    assert (judged.verdict, judged.introduced) == (Verdict.FAIL, False)
    assert conclusion([judged]) == "success"


@pytest.mark.parametrize("actions", [("no-op",), ("delete",), ("read",)])
def test_a_resource_the_plan_does_not_create_or_change_is_the_scans(
    actions: tuple[str, ...],
) -> None:
    assert judge([_resource({"min_tls_version": "TLS1_0"}, actions=actions)], RULES) == []


def test_a_replacement_is_judged_as_the_new_resource() -> None:
    resource = _resource(
        {"min_tls_version": "TLS1_0"},
        actions=("delete", "create"),
        before={"min_tls_version": "TLS1_0"},
    )
    assert _one(resource).introduced


def test_a_value_known_only_after_apply_is_unknown_never_a_pass() -> None:
    judged = _one(_resource({}, unknown=frozenset({"min_tls_version"})))
    assert (judged.verdict, judged.introduced) == (Verdict.UNKNOWN, False)


def test_an_absent_value_is_unknown() -> None:
    assert _one(_resource({})).verdict is Verdict.UNKNOWN


def test_one_failing_argument_fails_the_rule() -> None:
    resource = _resource(
        {"network_rules.default_action": "Deny", "public_network_access_enabled": True}
    )
    judged = _one(resource, NETWORK)
    assert (judged.verdict, judged.attribute, judged.planned) == (
        Verdict.FAIL,
        "public_network_access_enabled",
        "true",
    )


def test_a_renamed_argument_is_read_under_its_newest_name() -> None:
    resource = _resource(
        {"local_authentication_enabled": True, "local_authentication_disabled": False},
        address="azurerm_cosmosdb_account.db",
    )
    judged = _one(resource, LOCAL_AUTH)
    assert (judged.verdict, judged.attribute, judged.expected) == (
        Verdict.FAIL,
        "local_authentication_enabled",
        "false",
    )


def test_an_older_name_alone_still_decides() -> None:
    resource = _resource(
        {"local_authentication_disabled": True}, address="azurerm_cosmosdb_account.db"
    )
    assert _one(resource, LOCAL_AUTH).verdict is Verdict.PASS


# -------------------------------------------------------------------- service
IDENTITY = ActionsIdentity(42, "contoso/infra", "refs/pull/7/merge", "m" * 40)
PLAN = GuardrailPlanIn(
    working_directory="infra",
    resources=[
        PlannedResourceIn(
            address="azurerm_storage_account.logs",
            type="azurerm_storage_account",
            actions=["create"],
            after={"min_tls_version": "TLS1_0"},
        )
    ],
)


@pytest.fixture
def gh(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setattr(settings, "fix_prs_enabled", True)
    for name in (
        "github_app_id",
        "github_app_slug",
        "github_app_client_id",
        "github_app_client_secret",
        "github_app_private_key",
        "github_app_webhook_secret",
    ):
        monkeypatch.setattr(settings, name, "set")
    state: dict[str, Any] = {"head": "h" * 40, "checks": [], "refuse_check": False}

    async def linked_repository(identity: ActionsIdentity) -> LinkedRepository:
        state["asked"] = identity
        return LinkedRepository(7, github.Repository(42, "contoso/infra", "main"), uuid4())

    async def installation_token(installation_id: int) -> str:
        return "installation-token"

    async def pull_request_head(full_name: str, number: int, token: str) -> str | None:
        state["pull_request"] = number
        return state["head"]

    async def create_check_run(full_name: str, **fields: Any) -> str:
        if state["refuse_check"]:
            raise CodeHostError("GitHub refused to report the check (403).")
        state["checks"].append(fields)
        return "https://github.com/contoso/infra/runs/1"

    monkeypatch.setattr(service, "linked_repository", linked_repository)
    monkeypatch.setattr(service, "guarded_rules", lambda: RULES)
    monkeypatch.setattr(github, "installation_token", installation_token)
    monkeypatch.setattr(github, "pull_request_head", pull_request_head)
    monkeypatch.setattr(github, "create_check_run", create_check_run)
    return state


async def test_a_plan_is_reported_on_the_pull_requests_head_commit(gh: dict[str, Any]) -> None:
    out = await service.take_plan(IDENTITY, PLAN)
    [check] = gh["checks"]
    assert gh["pull_request"] == 7
    assert (check["head_sha"], check["conclusion"]) == ("h" * 40, "failure")
    assert check["name"] == "Cleave guardrail: infra (default)"
    assert "| AZ-STO-002 Storage accounts require TLS 1.2 | HIGH |" in check["summary"]
    assert (out.conclusion, out.check_run_url) == (
        "failure",
        "https://github.com/contoso/infra/runs/1",
    )
    assert [(v.rule_id, v.verdict, v.introduced) for v in out.verdicts] == [
        ("AZ-STO-002", "FAIL", True),
        ("AZ-STO-005", "UNKNOWN", False),
    ]


@pytest.mark.parametrize("ref", ["refs/heads/main", "refs/pull/7/head", "refs/tags/v1"])
async def test_only_a_pull_requests_plan_is_judged(gh: dict[str, Any], ref: str) -> None:
    identity = ActionsIdentity(42, "contoso/infra", ref, "m" * 40)
    with pytest.raises(PermissionDenied):
        await service.take_plan(identity, PLAN)
    assert "asked" not in gh


async def test_a_plan_holding_more_is_refused_before_github_is_asked(gh: dict[str, Any]) -> None:
    resource = PLAN.resources[0].model_copy(update={"after": {"primary_access_key": "secret"}})
    with pytest.raises(ValidationFailed):
        await service.take_plan(IDENTITY, PLAN.model_copy(update={"resources": [resource]}))
    assert "asked" not in gh


async def test_a_closed_pull_request_is_not_reported(gh: dict[str, Any]) -> None:
    gh["head"] = None
    with pytest.raises(ValidationFailed):
        await service.take_plan(IDENTITY, PLAN)
    assert gh["checks"] == []


async def test_a_refused_check_run_still_answers_the_job(gh: dict[str, Any]) -> None:
    gh["refuse_check"] = True
    out = await service.take_plan(IDENTITY, PLAN)
    assert (out.conclusion, out.check_run_url) == ("failure", None)
    assert out.check_run_detail is not None and "403" in out.check_run_detail


def test_a_value_cannot_break_the_summarys_table() -> None:
    judged = judge([_resource({"min_tls_version": "a|b"})], [TLS])
    assert "a\\|b" in service.check_summary(judged, [TLS])


def test_a_plan_without_a_token_is_refused_over_http() -> None:
    response = TestClient(app).post("/api/v1/iac-guardrail/plans", json={"resources": []})
    assert response.status_code == 401


def test_the_allowlist_is_read_without_a_token(gh: dict[str, Any]) -> None:
    response = TestClient(app).get("/api/v1/iac-guardrail/allowlist")
    assert response.status_code == 200
    assert "min_tls_version" in response.json()["data"]["attributes"]["azurerm_storage_account"]
