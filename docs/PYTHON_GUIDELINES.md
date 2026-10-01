# Python guidelines

How Python is written in this repository. It condenses three sources, and where
they disagree with each other or with this codebase, it says which one wins and
why:

- [PEP 8](https://peps.python.org/pep-0008/), the community baseline;
- the [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html),
  which is stricter about language features, exceptions and typing;
- the [Hitchhiker's Guide, Code Style](https://docs.python-guide.org/writing/style/),
  for idioms.

PEP 8's first rule applies throughout: consistency with the code around you
beats any single rule here. The second applies too: a guideline that makes a
piece of code less readable is the wrong guideline for that code. Say so in a
comment and in review.

Each rule is tagged with how it is held:

- **`[ruff XXX]`**: a Ruff rule that fails the commit hook and CI today.
- **`[mypy]`**: the type checker fails on it.
- **`[next: XXX]`**: a Ruff rule that lands in the next ratchet (DECISIONS.md
  §191). Follow it now; the check will hold it later.
- **`[review]`**: no tool can see it, so review does.

Formatting is not in this document. Ruff format owns it (100 columns, double
quotes, trailing commas, blank lines, whitespace, comment spacing), and arguing
with the formatter is not a review comment. See `docs/STANDARDS.md` for the
tools.

---

## 1. Principles

1. **Readable over clever.** Code is read far more than written. Pick the most
   straightforward way to do it. No metaprogramming, import hooks, custom
   metaclasses, `__del__`, bytecode tricks or dynamic inheritance. Standard
   library uses of them (`abc`, `dataclasses`, `enum`, Pydantic) are fine.
   `[review]`
2. **Explicit over implicit.** A function's signature says what it needs. Avoid
   `*args`/`**kwargs` where named parameters would do. `[review]`
3. **One obvious way.** If this codebase already has a pattern for something
   (a `PropertySpec` for a single-setting rule, `ScanWriter.commit` for a scan
   write, `services/audit.record` for an audit row), use it. Do not add a
   second one. `[review]`
4. **Small, focused functions.** Past about 40 lines, look for the seam.
   `[next: PLR0912, PLR0915]`

## 2. Imports

- Imports go at the top, after the module docstring, one module per line.
  Groups are standard library, then third party, then `app`, with a blank line
  between groups. `[ruff I001]`
- Use absolute imports only (`from app.rules.base import SecurityRule`), never
  relative ones. `[next: TID252]`
- No wildcard imports. `[ruff F403]`
- Importing a symbol (`from app.x import Thing`) is the house style. Google
  imports modules only, but this codebase does not. Alias only for a real
  collision or a standard abbreviation.
- Importing a module must not do work: no network, no database, no reading
  files beyond config. Executable scripts guard with `if __name__ ==
  "__main__": main()`. `[review]`
- Neutral code never imports a provider (`app.connectors.azure`/`aws`).
  `tests/unit/test_provider_seam.py` fails the build.

## 3. Naming

| Kind | Style | Example |
|---|---|---|
| Package, module | `lower_with_under` | `cloud_connections.py` |
| Class, type alias, enum | `CapWords` | `SecurityRule`, `EvidenceKey` |
| Exception | `CapWords`, usually without `Error` | `NotFound`, `PermissionDenied` |
| Function, method, variable, parameter | `lower_with_under` | `evaluate_rules()` |
| Constant (module or class level) | `CAPS_WITH_UNDER` | `MAX_PAGE_SIZE` |
| Internal (module, class, attribute) | leading `_` | `_env`, `_parse_scope()` |
| Type parameter | short `CapWords` | `class Envelope[DataT, MetaT]` |

`[ruff N8xx]`

- Names say what a thing is, not its type: `rules_by_id`, not
  `rules_dict`. `[review]`
- Don't abbreviate by dropping letters. Short names are only for loop indices
  (`i`, `j`), a caught exception (`exc`) and a file handle (`f`). Never `l`,
  `O` or `I`. `[ruff E741]`
- For acronyms in CapWords, capitalize every letter: `HTTPClient`, not
  `HttpClient`. `[review]`
- Use one leading underscore for internal names. Don't use `__name` to
  "make private": name mangling hurts testing and debugging. `[review]`
- Name a deliberately unused variable `_`, or start it with `_`. The
  Hitchhiker's `__` is not used: Ruff and this codebase use `_`.
  `[ruff F841, RUF059]`
- Exceptions keep this codebase's domain names (`NotFound`, not
  `NotFoundError`). PEP 8 and Google want the `Error` suffix; the project
  turned that off on purpose (`N818` in `pyproject.toml`).

## 4. Types

The type checker is part of the build. The target is mypy `strict`
(DECISIONS.md §191, ratchet).

- Annotate every function: parameters and return type, `-> None` included.
  Don't annotate `self`/`cls`; use `Self` where a method returns its own
  type. `[mypy disallow_untyped_defs]`
- Write `X | None`, never `Optional[X]`, and never a bare `= None` default
  without `| None` in the annotation. `[ruff UP007, mypy no_implicit_optional]`
- Use built-in generics: `list[str]`, `dict[str, int]`, `tuple[int, ...]`.
  Don't use `typing.List`/`Dict`. `[ruff UP006]`
- On Python 3.12, write generics with type parameters (`class Envelope[DataT,
  MetaT](BaseModel)`, `def first[T](xs: Sequence[T]) -> T`), not `TypeVar` and
  `Generic`. `[ruff UP046, UP047]`
- Parameters take the abstract type (`Sequence`, `Mapping`, `Iterable` from
  `collections.abc`). Return values give the concrete type. `[review]`
- Name complex types with a `type` alias: `type RuleIndex = dict[str,
  list[SecurityRule]]`. `[review]`
- Use `Any` only at a real boundary (raw provider JSON before
  normalization) and say so. Anything else gets a type, a `TypedDict` or a
  Pydantic model. `[review]`
- `# type: ignore` names its code and gives a reason: `# type: ignore[arg-type]
  -- aiobotocore stubs omit this overload`. `[next: PGH003, mypy
  warn_unused_ignores]`
- Don't add `from __future__ import annotations`; 3.12 doesn't need it, and
  Pydantic and FastAPI read annotations at runtime. `[review]`
- Use `if TYPE_CHECKING:` imports only to break a real import cycle, and
  prefer moving code over adding one. `[review]`

## 5. Functions and arguments

- Mandatory inputs are positional, in their natural order. Optional ones are
  keyword arguments with defaults. Make a boolean flag keyword-only (`*,
  dry_run: bool = False`) so a call never reads as `sync(conn, True)`.
  `[review]`
- Never use a mutable default (`[]`, `{}`, `set()`). Default to `None`, or to
  an immutable empty value (`()`, `frozenset()`). `[ruff B006]` (`B008` is
  ignored only for FastAPI's `Depends()`.)
- Return consistently: either every `return` gives a value (`return None`
  spelled out) or none does. `[next: RET501, RET502, RET503]`
- Return early for errors and edge cases, so the main path isn't nested.
  `[ruff SIM, next: RET505]`
- Assign a function with `def`, never a lambda (`f = lambda x: ...`). Use a
  lambda only inline and only for one short expression, and prefer `operator`
  (`operator.attrgetter("id")`) where one fits. `[ruff E731]`
- Nest a function only to close over a local value. To hide a helper, make it
  a module-level `_helper`. `[review]`
- Prefer a module-level function to a `@staticmethod` in new code (Google).
  The existing ones stay. Use `@classmethod` for alternative constructors.
  `[review]`
- Use `@property` only for cheap, side-effect-free computation that reads like
  an attribute. A plain attribute needs no getter/setter pair. `[review]`

## 6. Exceptions

- Raise the most specific built-in exception that fits (`ValueError`,
  `KeyError`, `LookupError`) or a domain exception from `app.core`. Custom
  exceptions derive from `Exception`, never `BaseException`. `[review]`
- Never write a bare `except:`. `[ruff E722]` Catch `Exception` only at an
  isolation boundary (a Celery task, a per-subscription collector, a request
  handler) where the error is logged and turned into a recorded failure.
  Anywhere else, name the exceptions. `[next: BLE001]`
- Keep `try` bodies minimal: wrap only the call that can raise what you catch,
  so a bug in the next line isn't swallowed. `[review]`
- When translating an exception, chain it: `raise NotFound(...) from exc`.
  Use `from None` only when the cause would leak something or mislead.
  `[ruff B904]`
- Never `return`, `break` or `continue` inside `finally`; it silently cancels
  the exception. `[ruff B012]`
- Use `assert` only in tests. It is stripped under `python -O`, so production
  checks raise. `[next: S101 outside tests]`
- Error messages name the condition precisely and quote the value, so the
  message is greppable: `f"Unknown provider: {provider!r}"`. Never put a
  secret, token or connection string in one. `[review]`
- An exception is never silenced to make a scan "succeed". Unknown is not
  PASS (CLAUDE.md, rule engine). `[review]`

## 7. Idioms and expressions

- Compare to `None`, and other singletons, with `is` / `is not`, never `==`.
  `[ruff E711]`
- Write `x is not None`, not `not x is None`. `[ruff E714]`
- Don't compare booleans to `True`/`False`. Use `if flag:` / `if not flag:`.
  `[ruff E712]`
- Use emptiness as falseness for sequences: `if not items:`, never `if
  len(items) == 0:`. But when `0`, `""` or an empty list is a legitimate
  value distinct from "missing", test `is None`. `[review]`
- Check types with `isinstance(x, T)`, never `type(x) == T`. `[ruff E721]`
- Use `startswith()`/`endswith()`, not slicing, for prefixes and suffixes.
  Pass a tuple for several. `[review]`
- Iterate the object itself (`for key in mapping:`, `for line in f:`), not
  `.keys()` or `.readlines()`. Use `enumerate()` for an index and `zip(...,
  strict=True)` for parallel sequences. `[ruff SIM118, B905]`
- Use membership on a set or dict for repeated lookups, not a list.
  `[review]`
- Use unpacking instead of indexing: `first, *rest = items`, `a, b = b, a`.
  `[review]`
- Use a comprehension for one `for` and at most one `if`. Anything more is a
  loop. Never use a comprehension only for its side effects. `[ruff C4,
  review]`
- Never mutate a collection while iterating over it. Build a new one.
  `[review]`
- Use a conditional expression only when each part fits on one line:
  `"public" if exposed else "private"`. `[review]`
- Build strings with f-strings. To join many pieces, collect them in a list and
  use `"".join(...)`, never `+=` in a loop. `[ruff UP031, UP032, review]`
- Keep one statement per line: no `;`, no `if x: y` on one line. `[ruff E701,
  E702, E703]`
- Continue a line with parentheses, never a backslash. Ruff format places line
  breaks before binary operators, as PEP 8 now prefers.

## 8. Resources, time, files

- Anything that opens must close: use `with` for files, locks, HTTP clients and
  sessions (`async with rls_session(...)`). Don't rely on garbage collection
  or `__del__`. `[ruff SIM115]`
- Datetimes are timezone-aware, in UTC: `datetime.now(UTC)`, never `utcnow()`
  or a naive `now()`. `[next: DTZ]`
- In new code, use `pathlib.Path` for paths, not `os.path` string handling.
  `[next: PTH]`
- When reading or writing text, always pass `encoding="utf-8"`. `[review]`

## 9. Async (FastAPI, the worker)

These come from this codebase, not from the three guides. They are where
Python services fail in production.

- Nothing on the event loop blocks: no `time.sleep`, no `requests`, no sync
  file or DB I/O in an `async def`. Run CPU or blocking work in a thread
  (`graph_service.off_loop`, `anyio.to_thread`) (DECISIONS.md §158, §161).
  `[next: ASYNC]`
- Never idle on a pooled connection: close the session before slow work
  (rendering, network calls). `[review]`
- Keep a reference to every task you start and await it, or put it under a
  task group. A dropped task loses its exception. `[ruff RUF006]`
- HTTP calls have a timeout. A URL a customer typed goes only through
  `core/outbound.post_json` (§164). `[review]`

## 10. Logging

The project logs with structlog, which differs from Google's `%`-pattern advice
for the same reason. The event is a fixed string, and the values are fields:

```python
log.warning("rules.sync_failed", rule_id=rule.rule_id, error=str(exc))
```

- The event name is `area.what_happened`, lowercase, and constant. Never an
  f-string: a constant event can be searched and counted. `[next: G004,
  review]`
- Don't log secrets, tokens, raw credentials or customer cloud payloads.
  `[review]`
- Don't `print` in application code. `[next: T201]`
- Log a caught exception at its isolation boundary once, with
  `log.exception`. Don't log it at every layer it passes through. `[review]`

## 11. Comments and docstrings

- A comment says **why**, not what. Assume the reader knows Python. A comment
  that contradicts the code is worse than none, so update it with the code.
  `[review]`
- Write comments as complete sentences, starting with a capital letter.
  `[review]`
- Every public module, class and function has a docstring (PEP 257): `"""`
  quotes, a one-line summary ending in a period, then a blank line and the
  detail. Private helpers get one when their logic isn't obvious.
  `[review; next: D1xx for app/ public API]`
- Docstrings here are prose: what the thing is or does, and why it is shaped
  that way, often citing `DECISIONS.md §N`. Google's `Args:` / `Returns:` /
  `Raises:` sections are not used. Name an exception the caller must handle in
  the prose. `[review]`
- A test's name says what it proves (`test_cannot_update_another_tenants_row`).
  Add a docstring only to say why. `[review]`
- Don't leave commented-out code. Version control remembers it.
  `[next: ERA001]`
- A `TODO` names the issue or condition that ends it: `# TODO(#123): drop once
  every tenant is on role v12`. Never a bare `TODO` or a person's name.
  `[next: TD]`

## 12. Security

- Never use `eval`, `exec`, `pickle` on untrusted data, or `yaml.load` without
  `SafeLoader`. `[next: S307, S102, S301, S506]`
- Call `subprocess` with an argument list, never `shell=True` with
  interpolated input. `[next: S602, S603, S604, S605]`
- Build SQL only through SQLAlchemy expressions or bound parameters, never
  string formatting. RLS stays on: application code uses `cloudguard_app`,
  never the owner connection. `[next: S608, review]`
- Use `secrets` for tokens and anything security-relevant, not `random`.
  `[next: S311]`
- Jinja environments autoescape. `[next: S701]`
- Rules are deterministic: no network, database, clock or LLM call inside
  `evaluate()` (CLAUDE.md, rule engine). `[review]`

## 13. Tests

- Use pytest with plain `assert`, one behaviour per test, and names that state
  the behaviour. `[review]`
- Mark tests that need a live Postgres with `@pytest.mark.integration`.
- Use fixtures from `tests/fixtures/`, never a mock connector in `app/`
  (CLAUDE.md).
- `pytest.raises(..., match=...)` takes a raw string or `re.escape(...)`.
  `[ruff RUF043]`
- Parametrize instead of copying a test. `[next: PT006, PT007]`

---

## Where these depart from the sources

| Topic | PEP 8 | Google | Hitchhiker | Here | Why |
|---|---|---|---|---|---|
| Line length | 79 (99 allowed) | 80 | — | 100 | Matches the formatter and the web code; PEP 8 allows a team to raise it |
| Import style | symbols or modules | modules only | — | symbols | Every existing module does; consistency wins |
| Throwaway name | — | — | `__` | `_` | Ruff's dummy-variable convention and the codebase |
| Exception suffix | `Error` | `Error` | — | domain names | `N818` is ignored deliberately (`pyproject.toml`) |
| Docstring sections | — | `Args/Returns/Raises` | — | prose | The codebase explains _why_, often with a DECISIONS § |
| Logging | — | `%`-patterns | — | structlog event + fields | Constant event names, queryable fields |
| `@staticmethod` | — | never | — | discouraged in new code | Existing uses are not churned |
| `from __future__ import annotations` | — | yes | — | no | 3.12 doesn't need it; runtime annotation readers do |
