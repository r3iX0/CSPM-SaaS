"""One Prowler run over one scope: the only module that touches Prowler.

Prowler is driven through the interface its own API service uses --
``prowler.lib.scan.scan.Scan(provider, checks).scan()`` yielding progress and
findings per check -- rather than through its CLI, so a run reports progress
between checks, stops between checks when its lease is gone, and never writes a
file (``api/src/backend/tasks/jobs/scan.py`` in Prowler's repository).

Credentials go to the provider's constructor and nowhere else. They are never
placed in ``os.environ`` (which every later import in this process could read)
and never on a command line (which ``ps`` shows every user on the host).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

from cloudguard_scanner.capture import ErrorCapture, RunOutcome, serialize
from cloudguard_scanner.config import Settings
from cloudguard_scanner.store import LeaseLost, Scope

log = logging.getLogger("cloudguard_scanner")

# What Prowler's AWS provider names its assumed-role session. Visible in the
# customer's CloudTrail, so it says who is calling.
ROLE_SESSION_NAME = "cleave-extended-checks"


class ScopeNotRunnable(Exception):
    """The scope cannot be assessed as configured. Not worth retrying."""


def provider_arguments(scope: Scope, settings: Settings) -> dict[str, Any]:
    """The keyword arguments for Prowler's provider, from the scope's row.

    Separate from :func:`build_provider` so the refusals below are testable
    without Prowler reaching a cloud.
    """
    if scope.provider == "azure":
        if not settings.azure_client_id or not settings.azure_client_secret:
            raise ScopeNotRunnable(
                "Cleave's Entra application credentials are not configured on the "
                "scanner service (AZURE_CLIENT_ID / AZURE_CLIENT_SECRET)."
            )
        if not scope.tenant_id:
            raise ScopeNotRunnable("This connection has no tenant to authenticate against.")
        return {
            "az_cli_auth": False,
            "sp_env_auth": False,
            "browser_auth": False,
            "managed_identity_auth": False,
            "tenant_id": scope.tenant_id,
            "client_id": settings.azure_client_id,
            "client_secret": settings.azure_client_secret,
            # The directory step lists no subscription; it runs only the
            # Entra checks, which read the tenant through Graph.
            "subscription_ids": [scope.subscription_id] if scope.subscription_id else [],
        }

    if scope.provider == "aws":
        role_arn = str(scope.reference.get("role_arn") or "")
        external_id = str(scope.reference.get("external_id") or "")
        if not role_arn:
            raise ScopeNotRunnable("This account has no scanner role to assume.")
        if not external_id:
            # The same refusal the API's RoleAssumer makes: a role assumed
            # without an external id is the confused-deputy case the external
            # id exists to close (DECISIONS.md section 73).
            raise ScopeNotRunnable(
                "This account has no external id. Cleave will not assume a role without one."
            )
        if not settings.aws_access_key_id or not settings.aws_secret_access_key:
            raise ScopeNotRunnable(
                "Cleave's own AWS credentials are not configured on the scanner service."
            )
        return {
            "role_arn": role_arn,
            "external_id": external_id,
            "role_session_name": ROLE_SESSION_NAME,
            "aws_access_key_id": settings.aws_access_key_id,
            "aws_secret_access_key": settings.aws_secret_access_key,
        }

    raise ScopeNotRunnable(f"The extended checks do not cover {scope.provider}.")


def build_provider(scope: Scope, settings: Settings) -> Any:  # pragma: no cover - needs a cloud
    arguments = provider_arguments(scope, settings)
    if scope.provider == "azure":
        from prowler.providers.azure.azure_provider import AzureProvider

        return AzureProvider(**arguments)
    from prowler.providers.aws.aws_provider import AwsProvider

    return AwsProvider(**arguments)


def _prowler_scan(provider: Any, checks: list[str]) -> Any:  # pragma: no cover - needs a cloud
    from prowler.lib.scan.scan import Scan

    return Scan(provider=provider, checks=checks)


def run(
    scope: Scope,
    checks: list[str],
    settings: Settings,
    *,
    keep_going: Callable[[], bool],
    deadline: float | None = None,
    clock: Callable[[], float] = time.time,
    provider_factory: Callable[[Scope, Settings], Any] = build_provider,
    scan_factory: Callable[[Any, list[str]], Any] = _prowler_scan,
) -> RunOutcome:
    """Run ``checks`` over ``scope`` and return what Prowler said and logged.

    A provider that will not initialise -- credentials refused, the role not
    assumable -- is a *fatal* run: recorded with its reason, so the API can say
    why every check for this scope is unknown. It is not raised, because the
    reason is the useful output.

    ``keep_going`` is asked between checks. When the lease has gone, the run
    stops there and raises :class:`LeaseLost`: another worker has the step,
    and every further check would be a duplicate of its work.

    ``deadline`` (a ``clock()`` value) is asked at the same points. Past it the
    run stops and returns what it finished, with ``errors["stopped"]`` saying
    why: the checks it never reached are not completed, so they read UNKNOWN,
    and the capture is PARTIAL. A retry would stop at the same place, so this
    is a result rather than a failure (DECISIONS.md section 151).
    """
    outcome = RunOutcome(requested=list(checks))
    capture = ErrorCapture(checks)
    root = logging.getLogger()
    root.addHandler(capture)
    try:
        try:
            provider = provider_factory(scope, settings)
        except ScopeNotRunnable:
            raise
        except Exception as error:
            outcome.errors = capture.summary(
                fatal=f"{type(error).__name__}: {str(error)[:500]}"
            )
            return outcome

        scan = scan_factory(provider, checks)
        stopped: str | None = None
        for _progress, findings in scan.scan():
            outcome.results.extend(serialize(finding) for finding in findings)
            if not keep_going():
                raise LeaseLost("the lease was lost mid-run")
            if deadline is not None and clock() >= deadline:
                stopped = (
                    "The run reached its time budget and stopped; the checks it had "
                    "not reached were not assessed."
                )
                break

        outcome.completed = sorted(scan.get_completed_checks())
        outcome.errors = capture.summary(stopped=stopped)
        return outcome
    finally:
        root.removeHandler(capture)
