"""The scanner's configuration, read from the environment once per process.

Plain environment reads rather than a settings framework: the scanner has a
handful of values, and every one of them is either a credential or a
connection string that Railway injects.
"""

import os
from dataclasses import dataclass
from pathlib import Path

# Where the image puts the catalogue the API was built with. The Dockerfile
# copies it from apps/api/app/prowler/data/catalog.json, so the two services
# always read the same file.
DEFAULT_CATALOG = Path(__file__).resolve().parent.parent / "catalog.json"


@dataclass(frozen=True)
class Settings:
    # The broker the API's worker publishes ASSESS steps to.
    redis_url: str
    # psycopg URL for the ``cloudguard_scanner`` role (migration 0042). Never
    # the owner, never the API's role: this process runs third-party code with
    # a customer's credentials in memory.
    database_url: str
    # Cleave's multi-tenant Entra application -- the same one the API's
    # collectors authenticate as. The customer's tenant id comes from the
    # connection row, never from here.
    azure_client_id: str
    azure_client_secret: str
    # Cleave's own AWS identity, which does nothing but assume the role each
    # customer created for it, under that customer's external id.
    aws_access_key_id: str
    aws_secret_access_key: str
    catalog_path: Path
    # How long one step may run. Prowler over a large AWS account with every
    # region enabled legitimately takes over an hour; the lease, renewed by
    # the heartbeat, is what catches a run that has actually stopped.
    soft_time_limit: int
    time_limit: int
    # Seconds a run may spend starting checks. Checked between checks, and
    # the only limit that stops a run cleanly: Prowler catches every
    # exception a check raises, Celery's SoftTimeLimitExceeded included, so
    # the soft limit is swallowed and the hard one kills the process with
    # nothing stored. At the budget the run stops, stores what it finished,
    # and the rest reads UNKNOWN (DECISIONS.md section 151). Far enough below
    # the soft limit for one slow check to finish inside it.
    run_budget: int

    @classmethod
    def from_env(cls) -> "Settings":
        soft = int(os.environ.get("SCANNER_SOFT_TIME_LIMIT", "6900"))
        budget = int(os.environ.get("SCANNER_RUN_BUDGET", str(max(soft - 1800, soft // 2))))
        return cls(
            redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
            database_url=os.environ.get("SCANNER_DATABASE_URL", ""),
            azure_client_id=os.environ.get("AZURE_CLIENT_ID", ""),
            azure_client_secret=os.environ.get("AZURE_CLIENT_SECRET", ""),
            aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", ""),
            aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
            catalog_path=Path(os.environ.get("SCANNER_CATALOG_PATH", str(DEFAULT_CATALOG))),
            soft_time_limit=soft,
            time_limit=int(os.environ.get("SCANNER_TIME_LIMIT", str(soft + 300))),
            run_budget=budget,
        )


settings = Settings.from_env()
