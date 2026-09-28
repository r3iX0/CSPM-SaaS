"""Keeps a step's lease alive while Prowler runs, and notices when it is gone.

A thread rather than calls between checks, because a single Prowler service can
spend many minutes building its clients -- listing every S3 bucket's policy,
every storage account's properties -- before the first check runs, and a lease
renewed only between checks would expire inside that silence. The reaper would
then hand the step to another worker while this one was still reading.

The thread renews on a third of the lease, the API's own cadence
(``app/services/scan/lease.py``). A renewal refused means the step moved on;
the runner asks :meth:`Heartbeat.alive` between checks and stops. A renewal
that errors is retried on the next beat rather than taken as loss: a database
blip is not the reaper.

The first renewal is made on entry, before Prowler starts. The API claims an
ASSESS step with a lease as long as the queue may make it wait
(``assess_queue_seconds``); renewing at once replaces that with the ordinary
lease, so a scanner that dies mid-run is noticed in minutes rather than hours
-- and a step already taken is refused before a single check runs.
"""

from __future__ import annotations

import logging
import threading
from types import TracebackType
from uuid import UUID

from cloudguard_scanner.store import LEASE_SECONDS, LeaseLost, Store

log = logging.getLogger("cloudguard_scanner")


class Heartbeat:
    def __init__(
        self,
        store: Store,
        organization_id: UUID,
        step_id: UUID,
        attempt: int,
        *,
        interval: float = LEASE_SECONDS / 3,
    ) -> None:
        self.store = store
        self.organization_id = organization_id
        self.step_id = step_id
        self.attempt = attempt
        self.interval = interval
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._thread = threading.Thread(target=self._beat, name="lease-heartbeat", daemon=True)

    def alive(self) -> bool:
        return not self._lost.is_set()

    def _beat(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                if not self.store.renew(self.organization_id, self.step_id, self.attempt):
                    log.warning("scanner.lease_lost step_id=%s", self.step_id)
                    self._lost.set()
                    return
            except Exception:
                log.exception("scanner.lease_renew_failed step_id=%s", self.step_id)

    def __enter__(self) -> Heartbeat:
        if not self.store.renew(self.organization_id, self.step_id, self.attempt):
            raise LeaseLost(f"step {self.step_id} was taken before its run started")
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
