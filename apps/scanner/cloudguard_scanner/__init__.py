"""Cleave's scanner service: runs Prowler for one ASSESS step at a time.

A separate service rather than a module of the API's worker, for two reasons
that are both about Prowler rather than about Cleave (DECISIONS.md section 150):

* **Dependencies.** Prowler pins botocore 1.40 and pydantic 2.12; the API's
  aiobotocore needs botocore 1.43. One process cannot hold both, so this
  package has its own image and never imports ``app``.
* **Global state.** Prowler keeps each service client in a module global built
  from a process-wide "current provider". A second scan in the same process
  would reuse the first tenant's clients and data. So every step runs in a
  fresh child process (``worker_max_tasks_per_child=1``), and
  :func:`cloudguard_scanner.tasks.refuse_reused_process` refuses to start in
  one that has already imported a Prowler service.

What it shares with the API is a database and a broker, and three contracts:
the ``assessment_captures`` columns it writes, the ``scan_steps`` fence it
honours, and the task name it answers to. ``apps/api/tests/unit/
test_prowler_engine.py`` holds both sides to the same values.
"""
