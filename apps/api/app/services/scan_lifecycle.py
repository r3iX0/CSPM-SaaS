"""How a scan ends.

A scan used to be ended by five writers, each setting its own subset of
``status``, ``completed_at``, ``error_message`` and ``lease_until``, and one of
them left the lease behind. This module is the one place that says what an
ending sets. It mutates the row it is handed and persists nothing: a fenced step
commits through ``ScanWriter``, a request commits its own transaction, and the
reaper commits its batch, so the caller keeps the transaction (DECISIONS.md
section 65, 108).
"""

from datetime import UTC, datetime
from typing import Any

from app.core.enums import ScanStatus
from app.core.logging import get_logger
from app.models.scan import Scan

log = get_logger(__name__)

# What a customer reads on the scans page; a stack trace or a step's whole error
# is not for it.
MESSAGE_LIMIT = 2000


def terminal_fields(
    status: ScanStatus,
    message: str | None = None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The columns an ending sets, for a caller that writes with ``UPDATE``.

    ``error_message`` is left out when there is nothing to say, so an ending
    that says nothing does not blank what an earlier one said.

    Raises ``ValueError`` for a status that is still running: a half-ended scan
    is the state this module exists to prevent.
    """
    if not status.is_terminal:
        raise ValueError(f"{status.value!r} is not an ending")
    fields: dict[str, Any] = {
        "status": status,
        "completed_at": now or datetime.now(UTC),
        "lease_until": None,
    }
    if message is not None:
        fields["error_message"] = message[:MESSAGE_LIMIT]
    return fields


def close(
    scan: Scan,
    status: ScanStatus,
    *,
    message: str | None = None,
    now: datetime | None = None,
) -> None:
    """End a scan in ``status``: stamp when, say why, and let go of the lease.

    A cancelled scan stays cancelled -- its steps may still be settling and a
    worker mid-collection only finds out when it next checks, so a late ending
    must not undo what the customer asked for. Settling the same ending again
    keeps ``completed_at``: the orchestrator settles a scan every time a step
    does, and a later settle must not move it. A different ending is a new
    event and is dated as one.
    """
    # Validated before the cancelled early return, so a caller's bad status is
    # caught on every scan and not only on the ones that happen to be running.
    resettled = scan.completed_at if scan.status == status else None
    fields = terminal_fields(status, message, now=resettled or now)
    if scan.status == ScanStatus.CANCELLED:
        log.info("scan.ending_ignored", scan_id=str(scan.id), ignored=status.value)
        return
    for name, value in fields.items():
        setattr(scan, name, value)
