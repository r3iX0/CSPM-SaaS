"""The ASSESS step's decision table, and the run it drives, without a cloud.

The store, the runner and the heartbeat are fakes; everything between them --
which outcome settles how, when a capture is written, what is retried -- is
the code under test.
"""

import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest

from cloudguard_scanner.capture import RunOutcome
from cloudguard_scanner.catalog import ScannerCatalog, load
from cloudguard_scanner.config import Settings
from cloudguard_scanner.heartbeat import Heartbeat
from cloudguard_scanner.runner import ScopeNotRunnable, provider_arguments, run
from cloudguard_scanner.store import LeaseLost, Scope, Step
from cloudguard_scanner.tasks import ReusedProcess, execute, refuse_reused_process

CATALOG = Path(__file__).resolve().parents[3] / "apps/api/app/prowler/data/catalog.json"

SETTINGS = Settings(
    redis_url="redis://x",
    database_url="postgresql://x",
    azure_client_id="client",
    azure_client_secret="secret",
    aws_access_key_id="AKIA",
    aws_secret_access_key="shh",
    catalog_path=CATALOG,
    soft_time_limit=10,
    time_limit=20,
    run_budget=5,
)

AZURE_ACCOUNT = Scope(
    provider="azure",
    tenant_id="tenant",
    subscription_id="sub",
    reference={},
    directory=False,
    cloud_account_id=uuid4(),
    connection_id=uuid4(),
)


@dataclass
class FakeStore:
    step_row: Step | None
    scope_row: Scope | None = AZURE_ACCOUNT
    status: str = "DISCOVERING"
    captures: list[RunOutcome] = field(default_factory=list)
    settled: list[tuple[str, str | None]] = field(default_factory=list)
    lose_on_write: bool = False

    def owner(self, scan_id: UUID) -> UUID:
        return UUID(int=1)

    def step(self, organization_id: UUID, step_id: UUID) -> Step | None:
        return self.step_row

    def scan_status(self, organization_id: UUID, scan_id: UUID) -> str:
        return self.status

    def scope(self, organization_id: UUID, step: Step) -> Scope | None:
        return self.scope_row

    def write_capture(
        self, organization_id: UUID, step: Step, scope: Scope, run: RunOutcome, **_: Any
    ) -> None:
        if self.lose_on_write:
            raise LeaseLost("taken")
        self.captures.append(run)

    def finish(
        self, organization_id: UUID, step: Step, status: str, error: str | None = None
    ) -> bool:
        self.settled.append((status, error))
        return True

    def fail_or_retry(self, organization_id: UUID, step: Step, error: str) -> str:
        decided = "PENDING" if step.attempt < step.max_attempts else "FAILED"
        self.settled.append((decided, error))
        return decided


class Beat:
    def __init__(self, *_: Any, alive: bool = True) -> None:
        self._alive = alive

    def alive(self) -> bool:
        return self._alive

    def __enter__(self) -> "Beat":
        return self

    def __exit__(self, *_: Any) -> None:
        return None


def _step(attempt: int = 1, kind: str = "ASSESS", status: str = "RUNNING") -> Step:
    return Step(uuid4(), uuid4(), kind, uuid4(), status, attempt, max(3, attempt))


def _catalog() -> ScannerCatalog:
    def entry(enabled: bool, scope: str, service: str) -> dict[str, Any]:
        return {"enabled": enabled, "provider": "azure", "scope": scope, "service": service}

    return ScannerCatalog(
        prowler_version="5.43.0",
        checks={
            "storage_a": entry(True, "account", "storage"),
            "entra_b": entry(True, "directory", "entra"),
            "secret_c": entry(False, "account", "app"),
        },
    )


def _execute(
    store: FakeStore,
    runner: Any,
    *,
    version: str = "5.43.0",
    beat: Any = Beat,
    attempt: int | None = None,
) -> str:
    return execute(
        uuid4(),
        uuid4(),
        store=store,  # type: ignore[arg-type]
        catalog=_catalog(),
        config=SETTINGS,
        prowler_version=version,
        attempt=attempt,
        runner=runner,
        heartbeat=beat,
    )


def _never(*_: Any, **__: Any) -> RunOutcome:
    pytest.fail("the run started")


def test_a_clean_run_is_stored_then_succeeds() -> None:
    store = FakeStore(_step())
    seen: dict[str, Any] = {}

    def runner(scope: Scope, checks: list[str], config: Settings, **_: Any) -> RunOutcome:
        seen["checks"] = checks
        return RunOutcome(requested=checks, completed=checks)

    assert _execute(store, runner) == "SUCCEEDED"
    # The account step runs the account checks, never the directory's, never
    # a disabled one.
    assert seen["checks"] == ["storage_a"]
    assert len(store.captures) == 1
    assert store.settled == [("SUCCEEDED", None)]


def test_a_step_that_is_no_longer_ours_is_left_alone() -> None:
    for step in (None, _step(status="SUCCEEDED"), _step(kind="COLLECT")):
        store = FakeStore(step)
        assert _execute(store, _never) == "NOT_OURS"
        assert store.settled == []


def test_a_message_for_an_earlier_attempt_is_left_alone() -> None:
    # The reaper gave attempt 1 up while its message sat on the queue, and the
    # step now runs as attempt 2 under a message of its own. The stale copy
    # would pass attempt 2's fence if it read the attempt off the row.
    store = FakeStore(_step(attempt=2))
    assert _execute(store, _never, attempt=1) == "NOT_OURS"
    assert store.settled == [] and store.captures == []


def test_a_message_for_the_current_attempt_runs() -> None:
    def runner(scope: Scope, checks: list[str], *_: Any, **__: Any) -> RunOutcome:
        return RunOutcome(requested=checks, completed=checks)

    assert _execute(FakeStore(_step(attempt=2)), runner, attempt=2) == "SUCCEEDED"


def test_the_run_is_given_a_deadline_inside_its_budget() -> None:
    seen: dict[str, Any] = {}

    def runner(scope: Scope, checks: list[str], *_: Any, **kwargs: Any) -> RunOutcome:
        seen["deadline"] = kwargs["deadline"]
        return RunOutcome(requested=checks, completed=checks)

    before = time.time()
    _execute(FakeStore(_step()), runner)
    assert before + SETTINGS.run_budget - 1 <= seen["deadline"] <= time.time() + SETTINGS.run_budget


def test_a_step_taken_before_the_run_starts_runs_nothing() -> None:
    class Refusing(FakeStore):
        def renew(self, *_: Any) -> bool:
            return False

    store = Refusing(_step())
    assert _execute(store, _never, beat=Heartbeat) == "LOST"
    assert store.captures == [] and store.settled == []


def test_the_first_renewal_is_made_before_the_run() -> None:
    renewed: list[int] = []

    class Renewing(FakeStore):
        def renew(self, organization_id: UUID, step_id: UUID, attempt: int) -> bool:
            renewed.append(attempt)
            return True

    def runner(scope: Scope, checks: list[str], *_: Any, **__: Any) -> RunOutcome:
        # The queue lease has already been replaced by the ordinary one.
        assert renewed == [4]
        return RunOutcome(requested=checks, completed=checks)

    assert _execute(Renewing(_step(attempt=4)), runner, beat=Heartbeat) == "SUCCEEDED"


def test_a_mismatched_prowler_fails_without_running() -> None:
    store = FakeStore(_step())
    assert _execute(store, _never, version="5.44.0") == "FAILED"
    assert "5.44.0" in (store.settled[0][1] or "")


def test_a_cancelled_scan_is_skipped() -> None:
    store = FakeStore(_step(), status="CANCELLED")
    assert _execute(store, _never) == "SKIPPED"


def test_a_refused_scope_is_recorded_and_not_retried() -> None:
    store = FakeStore(_step(attempt=1))

    def runner(*_: Any, **__: Any) -> RunOutcome:
        raise ScopeNotRunnable("This account has no external id.")

    assert _execute(store, runner) == "FAILED"
    assert store.captures[0].errors["fatal"] == "This account has no external id."
    assert store.settled[0][0] == "FAILED"


def test_a_provider_that_would_not_start_is_recorded_and_retried() -> None:
    store = FakeStore(_step(attempt=1))

    def runner(scope: Scope, checks: list[str], *_: Any, **__: Any) -> RunOutcome:
        return RunOutcome(requested=checks, errors={"fatal": "ClientAuthenticationError: nope"})

    assert _execute(store, runner) == "PENDING"
    assert store.captures and store.captures[0].outcome == "FAILED"


def test_a_lost_lease_writes_nothing_and_settles_nothing() -> None:
    def runner(scope: Scope, checks: list[str], *_: Any, **__: Any) -> RunOutcome:
        return RunOutcome(requested=checks)

    store = FakeStore(_step())
    assert _execute(store, runner, beat=lambda *a: Beat(alive=False)) == "LOST"
    assert store.captures == [] and store.settled == []

    store = FakeStore(_step(), lose_on_write=True)
    assert _execute(store, runner) == "LOST"
    assert store.settled == []


def test_an_unexpected_error_is_retried_until_attempts_run_out() -> None:
    def runner(*_: Any, **__: Any) -> RunOutcome:
        raise RuntimeError("boom")

    assert _execute(FakeStore(_step(attempt=1)), runner) == "PENDING"
    store = FakeStore(_step(attempt=3))
    assert _execute(store, runner) == "FAILED"
    assert "boom" in (store.settled[0][1] or "")


# ------------------------------------------------------------------ runner


def test_run_records_a_provider_that_will_not_start_as_fatal() -> None:
    def provider(*_: Any) -> Any:
        raise PermissionError("AADSTS7000215: invalid client secret")

    outcome = run(
        AZURE_ACCOUNT, ["a"], SETTINGS, keep_going=lambda: True, provider_factory=provider
    )
    assert outcome.outcome == "FAILED"
    assert "invalid client secret" in outcome.errors["fatal"]


class FakeScan:
    def __init__(self, finding: Any) -> None:
        self.finding = finding

    def scan(self) -> Iterator[tuple[float, list[Any]]]:
        yield 50.0, [self.finding]
        yield 100.0, []

    def get_completed_checks(self) -> set[str]:
        return {"a", "b"}


def test_run_collects_results_and_stops_when_the_lease_goes() -> None:
    finding = SimpleNamespace(
        check_id="a",
        status="FAIL",
        status_extended="bad",
        resource_uid="/x",
        resource_name="x",
        region="westeurope",
        resource_tags={},
        resource_details="",
    )
    outcome = run(
        AZURE_ACCOUNT,
        ["a", "b"],
        SETTINGS,
        keep_going=lambda: True,
        provider_factory=lambda *_: object(),
        scan_factory=lambda *_: FakeScan(finding),
    )
    assert outcome.completed == ["a", "b"]
    assert outcome.results[0]["resource_uid"] == "/x"

    with pytest.raises(LeaseLost):
        run(
            AZURE_ACCOUNT,
            ["a"],
            SETTINGS,
            keep_going=lambda: False,
            provider_factory=lambda *_: object(),
            scan_factory=lambda *_: FakeScan(finding),
        )


def test_provider_arguments_refuse_what_the_api_refuses() -> None:
    aws = Scope(
        "aws", "o-1", "123456789012", {"role_arn": "arn:aws:iam::1:role/r"}, False, uuid4(), uuid4()
    )
    with pytest.raises(ScopeNotRunnable, match="external id"):
        provider_arguments(aws, SETTINGS)

    ok = Scope(
        "aws",
        "o-1",
        "1",
        {"role_arn": "arn:aws:iam::1:role/r", "external_id": "e"},
        False,
        uuid4(),
        uuid4(),
    )
    arguments = provider_arguments(ok, SETTINGS)
    assert arguments["external_id"] == "e"
    assert arguments["role_session_name"] == "cleave-extended-checks"

    azure = provider_arguments(AZURE_ACCOUNT, SETTINGS)
    assert azure["subscription_ids"] == ["sub"]
    # Credentials are passed to the constructor, never read from the environment.
    assert azure["sp_env_auth"] is False


def test_a_process_that_already_loaded_a_prowler_client_refuses() -> None:
    name = "prowler.providers.azure.services.storage.storage_client"
    sys.modules[name] = SimpleNamespace()  # type: ignore[assignment]
    try:
        with pytest.raises(ReusedProcess):
            refuse_reused_process()
    finally:
        del sys.modules[name]


# ----------------------------------------------------------------- catalog


def test_the_catalogue_splits_directory_checks_from_account_checks() -> None:
    catalog = load(CATALOG)
    account = catalog.checks_for("azure", directory=False)
    directory = catalog.checks_for("azure", directory=True)
    assert directory and all(check.startswith("entra_") for check in directory)
    assert not set(account) & set(directory)
    # Excluded checks are never requested.
    assert "network_public_ip_shodan" not in account
    assert catalog.checks_for("aws", directory=True) == []


@contextmanager
def _prowler() -> Iterator[Any]:
    try:
        from prowler.lib.check.models import CheckMetadata
    except ImportError:  # pragma: no cover - CI installs it
        pytest.skip("Prowler is not installed")
    yield CheckMetadata


def test_every_catalogued_check_exists_in_the_installed_prowler() -> None:
    """The catalogue and the image must come from one Prowler release, or a
    step asks for a check Prowler refuses (ScanInvalidCheckError)."""
    with _prowler() as metadata:
        catalog = load(CATALOG)
        for provider in ("azure", "aws"):
            installed = set(metadata.get_bulk(provider))
            wanted = set(catalog.checks_for(provider, directory=False)) | set(
                catalog.checks_for(provider, directory=True)
            )
            assert wanted <= installed, sorted(wanted - installed)[:5]


class ManyChecks:
    """A run of three checks, one yielded at a time."""

    def __init__(self) -> None:
        self.done: set[str] = set()

    def scan(self) -> Iterator[tuple[float, list[Any]]]:
        for check in ("a", "b", "c"):
            self.done.add(check)
            yield 0.0, []

    def get_completed_checks(self) -> set[str]:
        return self.done


def test_run_stops_at_its_deadline_and_keeps_what_it_finished() -> None:
    # Prowler catches every exception a check raises, Celery's soft time limit
    # included, so the deadline between checks is what stops a run cleanly.
    ticks = iter([0.0, 10.0, 20.0])
    outcome = run(
        AZURE_ACCOUNT,
        ["a", "b", "c"],
        SETTINGS,
        keep_going=lambda: True,
        deadline=5.0,
        clock=lambda: next(ticks),
        provider_factory=lambda *_: object(),
        scan_factory=lambda *_: ManyChecks(),
    )
    assert outcome.completed == ["a", "b"]
    assert "time budget" in outcome.errors["stopped"]
    assert outcome.outcome == "PARTIAL"


# ------------------------------------------------------------------ store


def test_the_database_url_takes_the_apis_form_and_never_echoes_it() -> None:
    from cloudguard_scanner.store import connection_url

    secret = "hunter2secret"
    good = f"postgresql+asyncpg://cloudguard_scanner.ref:{secret}@db.example:5432/postgres"
    assert connection_url(good).startswith("postgresql://cloudguard_scanner.ref:")

    refused = [
        "",
        f"mysql://cloudguard_scanner:{secret}@db/x",
        # An unencoded slash: libpq reads the user name as the host.
        f"postgresql://cloudguard_scanner.ref:{secret}/x@db.example:5432/postgres",
        f"postgresql://postgres.ref:{secret}@db.example:5432/postgres",
    ]
    for url in refused:
        with pytest.raises(RuntimeError) as error:
            connection_url(url)
        assert secret not in str(error.value)

    encoded = f"postgresql://cloudguard_scanner.ref:{secret}%2Fx@db.example:5432/postgres"
    assert connection_url(encoded) == encoded
