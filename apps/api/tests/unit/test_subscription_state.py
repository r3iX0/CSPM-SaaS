"""A subscription Azure has switched off is named once, ahead of every gap it caused.

A disabled subscription disables its storage accounts, and each account then fails its own
read; the scan said "account is disabled" five times and never why (DECISIONS.md section 200).
"""

import pytest

from app.connectors.azure import plan as plan_module
from app.connectors.azure.client import AzureApiError
from app.connectors.azure.collector import explain_subscription_state
from app.connectors.base import RawSnapshot
from app.core.enums import Provider

BLOB_GAP = "blob recovery settings could not be read for 5 of 5 storage accounts."


def _snapshot(state: str | None) -> RawSnapshot:
    snapshot = RawSnapshot(provider=Provider.AZURE, tenant_id="t", subscription_id="s")
    if state is not None:
        snapshot.data["subscription"] = {"subscriptionId": "s", "state": state}
    snapshot.errors["storage"] = BLOB_GAP
    snapshot.gaps["storage_blob_services"] = BLOB_GAP
    return snapshot


@pytest.mark.parametrize(
    ("state", "says"),
    [
        ("Disabled", "Azure has disabled this subscription"),
        ("Warned", "Azure has warned this subscription"),
        ("PastDue", "payment is past due"),
        ("Deleted", "has been deleted"),
        ("SomethingNew", "not active"),
    ],
)
def test_a_subscription_that_is_not_enabled_explains_every_gap(state: str, says: str) -> None:
    snapshot = _snapshot(state)

    explain_subscription_state(snapshot)

    for message in (snapshot.errors["storage"], snapshot.gaps["storage_blob_services"]):
        assert message.startswith(f"Subscription state is {state}:")
        assert says in message
        assert f"(underlying error: {BLOB_GAP})" in message


@pytest.mark.parametrize("state", ["Enabled", "enabled", None])
def test_an_enabled_or_unread_subscription_leaves_the_gaps_as_they_were(
    state: str | None,
) -> None:
    snapshot = _snapshot(state)

    explain_subscription_state(snapshot)

    assert snapshot.errors["storage"] == BLOB_GAP
    assert snapshot.gaps["storage_blob_services"] == BLOB_GAP


def test_nothing_is_added_where_nothing_failed() -> None:
    snapshot = RawSnapshot(provider=Provider.AZURE, tenant_id="t", subscription_id="s")
    snapshot.data["subscription"] = {"state": "Disabled"}

    explain_subscription_state(snapshot)

    assert snapshot.errors == {}
    assert snapshot.gaps == {}


@pytest.mark.parametrize(
    "message",
    [
        "Azure API returned 400: AccountIsDisabled: Operation is not allowed for account st1",
        "Azure API returned 400: ContainerOperationFailure: The specified account is disabled.",
    ],
)
def test_a_disabled_storage_account_is_named_as_its_state(message: str) -> None:
    failures: list[Exception] = [AzureApiError(message, status_code=400)] * 5

    reason = plan_module._per_resource_reason(
        "blob recovery settings", "storage accounts", failures, 5, ("a/read",)
    )

    assert "Azure has disabled these storage accounts" in reason
    assert "deployed before" not in reason


def test_a_mix_of_disabled_and_other_failures_quotes_the_first() -> None:
    failures: list[Exception] = [
        AzureApiError("Azure API returned 400: AccountIsDisabled", status_code=400),
        AzureApiError("Azure API returned 404: ResourceNotFound", status_code=404),
    ]

    reason = plan_module._per_resource_reason(
        "file share settings", "storage accounts", failures, 2, ("a/read",)
    )

    assert "The first failure: Azure API returned 400: AccountIsDisabled" in reason
