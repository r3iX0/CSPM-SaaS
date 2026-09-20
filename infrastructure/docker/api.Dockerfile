FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Without this, `import app` depends on whichever entrypoint happens to add the
# working directory to sys.path: uvicorn does (--app-dir defaults to "."),
# alembic does (prepend_sys_path in alembic.ini), but Celery is not guaranteed
# to -- so the worker would fail to start while the API looked fine.
ENV PYTHONPATH=/srv/apps/api

WORKDIR /srv

# WeasyPrint renders the PDF reports through pango/cairo rather than in pure
# Python, so those libraries have to be in the image. Without them the package
# imports and then fails at `dlopen` -- which looks like a code fault and is a
# missing apt package.
#
# The runtime libraries only. A compiler toolchain is a build-time need and is
# installed, used and removed in the dependency layer below, so it is not part
# of what ships.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libffi8 \
 && rm -rf /var/lib/apt/lists/*

# Dependency layer: copy only the manifest so edits to source don't reinstall.
# Runtime dependencies only -- pytest, mypy and ruff belong in CI, not in a
# deployed image, where they only add build time and attack surface.
#
# `build-essential` is installed and purged inside this one layer. Anything a
# wheel does not cover is compiled here; nothing of the toolchain survives into
# the image, which is the difference between a container escape needing to
# bring its own compiler and finding one.
COPY apps/api/pyproject.toml /srv/apps/api/pyproject.toml
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && pip install --upgrade pip \
 && pip install -e /srv/apps/api \
 && apt-get purge -y --auto-remove build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY apps/api /srv/apps/api
COPY database /srv/database

# Not root. Nothing this process does needs to write outside its own package or
# to bind a privileged port -- $PORT comes from the platform and is high -- so
# running as uid 0 buys nothing and hands anything that gets inside the
# container the whole of it.
#
# The tree is left owned by root and readable rather than handed to the new
# user: the application never writes to its own source, and a process that
# cannot overwrite the code it is running is one fewer way for a foothold to
# become persistence.
RUN useradd --system --create-home --uid 10001 cloudguard
USER cloudguard

WORKDIR /srv/apps/api
EXPOSE 8000

# Railway's start command (railway.json) overrides this to run the migration
# first. This default stands in for any host that runs the image as-is, so it
# honors $PORT rather than assuming 8000.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
