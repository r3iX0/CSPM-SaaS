"""What a Prowler run is recorded as: its results, and what it could not do.

Prowler's failure mode is silence. A service whose listing is denied logs an
error and leaves its resource list empty; every check over it then iterates
over nothing and emits nothing. A check that raises is caught and logged, and
also emits nothing. Neither is visible in the results -- only in the log.

So the log is captured. :class:`ErrorCapture` sits on the root logger (which is
Prowler's logger) for the length of one run and files every ERROR by where it
came from: a record whose message begins with a requested check id is that
check's, and a record raised inside ``providers/<cloud>/services/<service>/`` --
or by shared code a service called, such as the base class that builds its
clients, found by walking the stack -- is that service's. The API turns both
into UNKNOWN verdicts rather than passes (``apps/api/app/prowler/ingest.py``).

A refusal is captured whatever level Prowler logs it at. Prowler logs an Azure
resource group it could not list, a key vault whose data plane refused it and
most "not supported here" answers as WARNING; the last are noise, the first two
are exactly the silence this module exists to catch, so a WARNING is kept when
its message names a refusal (``_REFUSAL``) and dropped otherwise. An ERROR that
belongs to no service or check still makes the run PARTIAL: it is something
Prowler could not do, even where it cannot be pinned to a question
(DECISIONS.md section 151).

The encoding is the API's (``app/core/payloads.py``): canonical JSON --
sorted keys, compact separators -- through zlib. The two sides do not share
code, so ``tests/test_capture.py`` pins the bytes.
"""

import hashlib
import json
import logging
import re
import sys
import zlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from types import FrameType
from typing import Any

COMPRESSION_LEVEL = 6

# Messages kept per service and per check. The first few name the cause;
# a thousand copies of "AuthorizationFailed" name nothing more.
MESSAGES_PER_SOURCE = 5
MESSAGE_LENGTH = 500
# How much of Prowler's free-text resource description a result keeps.
DETAILS_LENGTH = 2000

_SERVICE_PATH = re.compile(r"[\\/]providers[\\/][a-z0-9_]+[\\/]services[\\/]([a-z0-9_]+)[\\/]")

# How Azure, AWS and Graph say "you may not": the markers that make a WARNING
# worth keeping. Matched case-blind against Prowler's message, which carries
# the SDK's error text.
_REFUSAL = re.compile(
    r"AuthorizationFailed|AuthorizationPermissionMismatch|AccessDenied|Access Denied"
    r"|UnauthorizedOperation|Unauthorized|Forbidden|InsufficientAccountPermissions"
    r"|not authorized|does not have authorization|\b403\b",
    re.IGNORECASE,
)

# The scanner's own loggers, and Celery's. Their records are about this
# process -- a lease renewal that hit a database blip -- not about the cloud.
_OWN_LOGGERS = ("cloudguard_scanner", "celery")

# How far up the stack to look for the service a shared helper was working for.
_STACK_DEPTH = 40


class ErrorCapture(logging.Handler):
    """Files each ERROR Prowler logs under the service or check it concerns."""

    def __init__(self, requested: Iterable[str]) -> None:
        super().__init__(level=logging.WARNING)
        self.requested = frozenset(requested)
        self.services: dict[str, list[str]] = {}
        self.checks: dict[str, str] = {}
        self.other: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        if record.name.startswith(_OWN_LOGGERS):
            return
        try:
            message = record.getMessage()[:MESSAGE_LENGTH]
        except Exception:  # pragma: no cover - a malformed record is still an error
            message = str(record.msg)[:MESSAGE_LENGTH]
        if record.levelno < logging.ERROR and not _REFUSAL.search(message):
            return

        # "<check_id> -- Error[line]: ..." from the check runner, and
        # "<check_id> - Error[line]: ..." from the scan loop.
        first = message.split(" ", 1)[0]
        if first in self.requested:
            self.checks.setdefault(first, message)
            return

        service = _service_of(record.pathname) or _service_on_stack()
        if service:
            messages = self.services.setdefault(service, [])
            if len(messages) < MESSAGES_PER_SOURCE:
                messages.append(message)
            return

        if len(self.other) < MESSAGES_PER_SOURCE:
            self.other.append(message)

    def summary(self, fatal: str | None = None, stopped: str | None = None) -> dict[str, Any]:
        summary: dict[str, Any] = {
            "fatal": fatal,
            "services": self.services,
            "checks": self.checks,
            "other": self.other,
        }
        if stopped:
            summary["stopped"] = stopped
        return summary


def _service_of(path: str | None) -> str | None:
    match = _SERVICE_PATH.search(path or "")
    return match.group(1) if match else None


def _service_on_stack() -> str | None:
    """The Prowler service whose code is on the stack of the record being logged.

    ``emit`` runs synchronously in the thread that logged, so the stack is the
    one that raised: a failure in the shared base class that builds a service's
    clients (``providers/<cloud>/lib/service/service.py``) was called from that
    service's own module, a few frames up. Nearest frame first.
    """
    frame: FrameType | None = sys._getframe(1)
    for _ in range(_STACK_DEPTH):
        if frame is None:
            return None
        service = _service_of(frame.f_code.co_filename)
        if service:
            return service
        frame = frame.f_back
    return None


def serialize(finding: Any) -> dict[str, Any]:
    """One Prowler finding, as the API reads it.

    Deliberately not ``resource_metadata``: that is the whole service object
    Prowler built for the resource -- every property the SDK returned -- and
    storing it would copy configuration the customer never asked Cleave to
    hold into a table it keeps for months. What is kept is what a finding needs
    to say what is wrong and where.
    """
    status = getattr(finding.status, "value", finding.status)
    details = str(getattr(finding, "resource_details", "") or "")
    return {
        "check_id": str(finding.check_id),
        "status": str(status),
        "status_extended": str(finding.status_extended or ""),
        "resource_uid": str(finding.resource_uid or ""),
        "resource_name": str(finding.resource_name or ""),
        "region": str(finding.region or ""),
        "resource_tags": dict(getattr(finding, "resource_tags", None) or {}),
        "resource_details": details[:DETAILS_LENGTH],
    }


def canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class Encoded:
    compressed: bytes
    content_hash: str
    byte_size: int


def encode(payload: dict[str, Any]) -> Encoded:
    raw = canonical(payload)
    return Encoded(
        compressed=zlib.compress(raw, COMPRESSION_LEVEL),
        content_hash=hashlib.sha256(raw).hexdigest(),
        byte_size=len(raw),
    )


@dataclass
class RunOutcome:
    """Everything one step stores about its run."""

    requested: list[str]
    completed: list[str] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)
    errors: dict[str, Any] = field(default_factory=dict)

    @property
    def outcome(self) -> str:
        """COMPLETE, PARTIAL or FAILED, as the capture's ``outcome`` column."""
        if self.errors.get("fatal"):
            return "FAILED"
        if any(self.errors.get(key) for key in ("services", "checks", "other", "stopped")):
            return "PARTIAL"
        if set(self.requested) - set(self.completed):
            return "PARTIAL"
        return "COMPLETE"

    def payload(self) -> dict[str, Any]:
        return {
            "requested": self.requested,
            "completed": sorted(self.completed),
            "results": self.results,
        }
