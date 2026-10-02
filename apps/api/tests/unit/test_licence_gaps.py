"""Readings a tenant's licence rules out, and the role version a refusal names.

Three things a customer saw on one scan (DECISIONS.md section 196): the vault
keys read blamed on "a scanner role deployed before v12" when v11 introduced
it, sign-in activity refused for a P1/P2 licence, and PIM's eligible roles
refused with a raw ``AadPremiumLicenseRequired``. A licence is not a grant, so
the last two are recorded as UNAVAILABLE -- still untrustworthy, so their rules
stay UNKNOWN and never PASS -- rather than as failures somebody could fix.
"""

import uuid
from types import SimpleNamespace

import httpx
import jwt
import pytest

from app.connectors.azure import plan as plan_module
from app.connectors.azure.auth import REQUIRED_GRAPH_PERMISSIONS
from app.connectors.azure.client import AzureApiError
from app.connectors.azure.plan import PIM_LICENCE, SIGN_IN_LICENCE, AzurePlanBuilder
from app.connectors.azure.rbac import ROLE_VERSION, first_version_granting
from app.connectors.base import RawSnapshot
from app.connectors.collection import (
    CollectionRun,
    CollectionTask,
    ReadingUnavailable,
    TaskOutcome,
)
from app.connectors.evidence import EvidenceCategory, EvidenceKey
from app.core.enums import Provider
from app.services.scan import collection as scan_collection

PIM_REFUSAL = (
    "Azure API returned 400: AadPremiumLicenseRequired: The tenant needs to have "
    "Microsoft Entra ID P2 or Microsoft Entra ID Governance license."
)


class FakeTokens:
    def graph_token(self) -> str:
        # Consented in full: the only thing missing is the licence.
        return jwt.encode(
            {"roles": list(REQUIRED_GRAPH_PERMISSIONS)}, "irrelevant", algorithm="HS256"
        )


class Refusing:
    """An ARM or Graph client whose every call is refused the same way."""

    def __init__(self, message: str, status: int) -> None:
        self.message = message
        self.status = status
        self.truncated: set[str] = set()

    def __getattr__(self, name: str):
        async def refuse(*args, **kwargs):
            raise AzureApiError(self.message, status_code=self.status)

        return refuse


def _builder(subscription_id: str | None = None) -> AzurePlanBuilder:
    return AzurePlanBuilder(
        tokens=FakeTokens(), subscription_id=subscription_id, http_client=httpx.AsyncClient()
    )


async def _run(task: CollectionTask) -> Exception:
    with pytest.raises(Exception) as raised:
        await task.run({})
    return raised.value


# ------------------------------------------------------------------- the executor
class Key(EvidenceKey):
    LICENSED = "licensed"

    @property
    def category(self) -> EvidenceCategory:
        return EvidenceCategory.IDENTITY


async def test_a_licence_refusal_is_recorded_as_unavailable_not_failed() -> None:
    async def run(collected: dict):
        raise ReadingUnavailable("Needs a licence this tenant does not have.")

    report = await CollectionRun([CollectionTask(key=Key.LICENSED, run=run)]).execute({})
    result = report.results["licensed"]

    assert result.outcome is TaskOutcome.UNAVAILABLE
    assert result.detail == "Needs a licence this tenant does not have."
    # Never a pass: the rules that needed it report UNKNOWN.
    assert not result.is_trustworthy
    assert report.key_problems() == {"licensed": "Needs a licence this tenant does not have."}


# ------------------------------------------------------------- PIM, both halves
async def test_arm_refusing_pim_for_a_licence_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(plan_module, "ArmClient", lambda *a, **kw: Refusing(PIM_REFUSAL, 400))
    task = next(
        t for t in _builder("sub-1").build_account_plan() if t.key.value == "role_eligibilities"
    )

    raised = await _run(task)

    assert isinstance(raised, ReadingUnavailable)
    assert str(raised) == PIM_LICENCE


async def test_any_other_arm_refusal_of_pim_stays_a_failure(monkeypatch) -> None:
    monkeypatch.setattr(
        plan_module,
        "ArmClient",
        lambda *a, **kw: Refusing("Access denied. AuthorizationFailed", 403),
    )
    task = next(
        t for t in _builder("sub-1").build_account_plan() if t.key.value == "role_eligibilities"
    )

    raised = await _run(task)

    assert isinstance(raised, AzureApiError)
    assert not isinstance(raised, ReadingUnavailable)


async def test_graph_refusing_pim_names_pim_not_sign_in_activity(monkeypatch) -> None:
    """The directory half used to be reworded as the sign-in activity licence."""
    monkeypatch.setattr(plan_module, "GraphClient", lambda *a, **kw: Refusing(PIM_REFUSAL, 400))
    task = next(
        t
        for t in _builder().build_directory_plan()
        if t.key.value == "directory_role_eligibilities"
    )

    raised = await _run(task)

    assert isinstance(raised, ReadingUnavailable)
    assert str(raised) == PIM_LICENCE
    assert "Sign-in" not in str(raised)


async def test_sign_in_activity_names_its_own_licence(monkeypatch) -> None:
    monkeypatch.setattr(
        plan_module,
        "GraphClient",
        lambda *a, **kw: Refusing(
            "Access denied. Neither tenant is B2C or tenant doesn't have premium license", 403
        ),
    )
    task = next(
        t for t in _builder().build_directory_plan() if t.key.value == "user_sign_in_activity"
    )

    raised = await _run(task)

    assert isinstance(raised, ReadingUnavailable)
    assert str(raised) == SIGN_IN_LICENCE


# ---------------------------------------------------------- the version a hint names
def test_a_refused_read_names_the_version_that_introduced_it() -> None:
    assert first_version_granting("Microsoft.KeyVault/vaults/keys/read") == "v11"
    assert first_version_granting("Microsoft.Sql/servers/auditingSettings/read") == "v4"


def test_an_action_no_role_grants_yet_names_the_current_version() -> None:
    assert first_version_granting("Microsoft.Example/unreleased/read") == ROLE_VERSION


async def test_the_vault_keys_hint_names_v11(monkeypatch) -> None:
    monkeypatch.setattr(plan_module, "ArmClient", lambda *a, **kw: Refusing("Access denied.", 403))
    task = next(
        t for t in _builder("sub-1").build_account_plan() if t.key.value == "key_vault_keys"
    )

    produced = await task.run({"key_vaults": [{"id": "/vaults/one"}]})

    assert produced.partial_reason is not None
    assert "deployed before v11" in produced.partial_reason


# --------------------------------------------------------------- role drift
async def test_role_drift_leaves_a_licence_gap_alone(monkeypatch) -> None:
    """Prefixing "redeploy the role" to a licence refusal sends the customer
    to fix a role that could never serve it."""
    monkeypatch.setattr(
        scan_collection,
        "degraded_categories",
        lambda connection: {
            EvidenceCategory.AUTHORIZATION: "Redeploy the role.",
            EvidenceCategory.SECRETS: "Redeploy the role.",
        },
    )

    class Session:
        async def get(self, model, key):
            return SimpleNamespace(id=key, role_version="v7")

    snapshot = RawSnapshot(provider=Provider.AZURE, tenant_id="t", subscription_id="s")
    snapshot.errors = {
        "authorization": "role_eligibilities: " + PIM_LICENCE,
        "secrets": "key_vault_keys: Access denied.",
    }
    snapshot.gaps = {"role_eligibilities": PIM_LICENCE, "key_vault_keys": "Access denied."}
    snapshot.coverage = {
        "role_eligibilities": {"key": "role_eligibilities", "outcome": "UNAVAILABLE"},
        "key_vault_keys": {"key": "key_vault_keys", "outcome": "PARTIAL"},
    }
    account = SimpleNamespace(connection_id=uuid.uuid4(), provider=Provider.AZURE)

    await scan_collection.explain_role_drift(Session(), account, snapshot)  # type: ignore[arg-type]

    assert snapshot.gaps["role_eligibilities"] == PIM_LICENCE
    assert snapshot.errors["authorization"] == "role_eligibilities: " + PIM_LICENCE
    assert snapshot.gaps["key_vault_keys"].startswith("Redeploy the role.")
    assert snapshot.errors["secrets"].startswith("Redeploy the role.")
