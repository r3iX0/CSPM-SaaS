---
paths:
  - "**/*.py"
  - "**/pyproject.toml"
  - "ruff.toml"
---

# Python

Before writing or reviewing Python in this repository, read `docs/PYTHON_GUIDELINES.md` in
full, once per session, and follow it. It condenses PEP 8, the Google Python Style Guide and the
Hitchhiker's Guide, and records where this codebase departs from them and why.

The ones most often missed:

- Annotate every function, `-> None` included. Write `X | None`, built-in
  generics, and PEP 695 type parameters on 3.12.
- Catch named exceptions. `except Exception` only at an isolation boundary,
  logged once. Chain with `raise ... from exc`. `assert` only in tests.
- No blocking call inside `async def`; offload to a thread. No dropped tasks.
- structlog: `log.info("area.event", key=value)`, a constant event and never an
  f-string. No `print`, no secrets in logs or error messages.
- Timezone-aware UTC datetimes, `pathlib`, `with` for anything that opens.
- Docstrings are prose that says why, often citing `DECISIONS.md §N`; no
  `Args:`/`Returns:` sections.
- Ruff format owns layout. Run `ruff check --fix` and `ruff format` (or let the
  pre-commit hook do it) rather than hand-formatting.
