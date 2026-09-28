# The scanner service: runs Prowler for ASSESS scan steps (DECISIONS.md §150).
#
# Its own image, never the API's. Prowler pins botocore and pydantic to versions
# the API's dependencies cannot share, and it runs with a customer's cloud
# credentials in memory -- so it gets a separate process tree, a separate
# database role (cloudguard_scanner, migration 0042) and nothing of the API's
# code.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    # The catalogue the API was built with, copied below. The scanner runs
    # exactly the checks it lists, so the two services cannot disagree about
    # what a result means.
    SCANNER_CATALOG_PATH=/srv/catalog.json

WORKDIR /srv

# Dependency layer. Prowler pins its own direct dependencies exactly; the
# pins here must match apps/scanner/pyproject.toml and the Prowler version
# tools/prowler/curation.json names. A compiler is installed, used for any
# sdist and removed within this one layer, as in the API image.
COPY apps/scanner/pyproject.toml /srv/apps/scanner/pyproject.toml
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && pip install --upgrade pip \
 && pip install \
      "prowler==5.43.0" \
      "celery[redis]==5.4.0" \
      "redis==5.2.1" \
      "psycopg[binary]==3.2.3" \
 && apt-get purge -y --auto-remove build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY apps/scanner /srv/apps/scanner
RUN pip install --no-deps /srv/apps/scanner
COPY apps/api/app/prowler/data/catalog.json /srv/catalog.json

# Not root, and not the owner of its own code, for the reasons api.Dockerfile
# gives -- with more force here, since this is the process that executes
# third-party checks.
RUN useradd --system --create-home --uid 10002 scanner
USER scanner

# One step per child process: Prowler's service clients are module globals, and
# a reused process would scan the next tenant with the previous one's.
CMD ["celery", "-A", "cloudguard_scanner.celery_app.celery_app", "worker", \
     "--queues=assess", "--loglevel=INFO", "--concurrency=2", "--max-tasks-per-child=1"]
