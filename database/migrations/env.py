"""Alembic environment.

Migrations run as the table OWNER (DATABASE_OWNER_URL), not as the RLS-bound
application role -- creating policies requires ownership.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, text
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.core.urls import to_sync_dsn

# Importing Base also registers every table on its metadata, which is what
# autogenerate compares against.
from app.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# One migration run at a time, whoever starts it (DECISIONS.md section 161).
#
# Every API instance runs ``alembic upgrade head`` as it boots, so two booting
# together -- a scaled service, or a restart overlapping a deploy -- would both
# read the same version and both apply the next migration: the second fails on
# a table that now exists, and its instance crash-loops. A transaction-scoped
# advisory lock taken before the version is read makes the second wait for the
# first to commit, then find nothing left to do. Transaction-scoped rather than
# session-scoped so it holds through Supabase's transaction pooler too, and is
# released by the commit however the run ends. The number is arbitrary and only
# has to be the same in every process.
MIGRATION_LOCK = 7_261_553_010

# Synchronous driver on purpose -- see app.core.urls.
OWNER_DSN = to_sync_dsn(settings.database_owner_url)
config.set_main_option("sqlalchemy.url", OWNER_DSN)


def run_migrations_offline() -> None:
    context.configure(
        url=OWNER_DSN,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        {"sqlalchemy.url": OWNER_DSN}, prefix="sqlalchemy.", poolclass=NullPool
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK})
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
