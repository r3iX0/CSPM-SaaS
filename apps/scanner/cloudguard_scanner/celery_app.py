"""The scanner's Celery application: one queue, one task, one step per process.

Shares the broker with the API's worker and nothing else. The API's worker
claims an ASSESS step and publishes it here by task name; this worker runs it,
settles it, and publishes the scan's next advance back by name. Neither side
imports the other.

``worker_max_tasks_per_child=1`` is not tuning. Prowler builds each service
client as a module global from a process-wide provider, so a second step in the
same process would run against the first tenant's clients -- and their data.
One step per child process is what keeps two customers apart; Prowler's own
API service runs its workers the same way for the same reason.
"""

from celery import Celery

from cloudguard_scanner.config import settings

# Must equal ASSESS_QUEUE and ASSESS_TASK in apps/api/app/workers/celery_app.py.
ASSESS_QUEUE = "assess"
ASSESS_TASK = "cloudguard.run_assess_step"
# The API's task that claims whatever a scan may run next, and its queue.
ADVANCE_TASK = "cloudguard.advance_scan"
DEFAULT_QUEUE = "celery"

celery_app = Celery(
    "cloudguard-scanner",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["cloudguard_scanner.tasks"],
)

celery_app.conf.update(
    task_default_queue=ASSESS_QUEUE,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    # One message at a time: a run is long, and a reserved message is one no
    # other scanner can start.
    worker_prefetch_multiplier=1,
    # One step per child process. See the module docstring -- this is the
    # tenant boundary inside the process, not a memory setting.
    worker_max_tasks_per_child=1,
    broker_connection_retry_on_startup=True,
)
