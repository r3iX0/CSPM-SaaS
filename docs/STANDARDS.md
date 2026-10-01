# Code standards

Every standard here is a check that fails, not advice
([DECISIONS.md §191](DECISIONS.md)). The config files hold the rules; this page
says where each one lives, how it reaches every change, and how to ask for an
exception.

## Where each standard lives

| Files | Tool | Config | Based on |
|---|---|---|---|
| Python: lint | Ruff | `apps/api/pyproject.toml` `[tool.ruff]` (`ruff.toml` at the root extends it for `tools/`) | PEP 8, PEP 257, flake8-bugbear, pyupgrade |
| Python: format | Ruff format | same | Black's style |
| Python: types | mypy | `apps/api/pyproject.toml` `[tool.mypy]` | typeshed, the pydantic plugin |
| TypeScript: lint | ESLint | `apps/web/eslint.config.js` | typescript-eslint, react-hooks, jsx-a11y strict |
| TypeScript: types | tsc | `apps/web/tsconfig.json` | `strict` |
| TS, JS, CSS, JSON: format | Prettier | `.prettierrc.json`, `.prettierignore` | Prettier defaults, 100 columns |
| Every file | pre-commit-hooks | `.pre-commit-config.yaml` | LF endings, final newline, no merge markers, no private keys, no file over 1 MB |
| Every file | gitleaks | `.pre-commit-config.yaml` | gitleaks' default rules |
| Editors | EditorConfig, VS Code | `.editorconfig`, `.vscode/` | |

What the Python checks cannot see (naming that says what a thing is, why a
comment exists, where an exception may be caught) is in
[`PYTHON_GUIDELINES.md`](PYTHON_GUIDELINES.md), with each rule tagged by the
check that holds it or `[review]`.

Markdown, YAML, Jinja2 and workflow checks come next (§191, "Rules tighten by
ratchet"). Until they land, follow the shape of the files around you.

## How a check reaches every change

1. **In the editor.** `.editorconfig` and `.vscode/settings.json` format on
   save with the same tools, so most issues never reach a commit.
2. **On commit and push.** `tools/dev/setup.sh` installs the hooks once per
   clone. Commit runs the fast checks on the files you changed. Push runs mypy
   and tsc over the whole program.
3. **In CI.** The `repo` job runs every hook on every file, and the `api` and
   `web` jobs run lint, types, tests and build. These are required checks on
   `main`, so a change that skipped the hooks still cannot merge.

Never commit with `--no-verify`. If a hook is wrong, fix the hook.

## Asking for an exception

- **One line:** an inline ignore naming the rule and the reason, such as
  `# noqa: S608 -- table name comes from the model, not the request` or
  `// eslint-disable-next-line react-hooks/exhaustive-deps -- runs once on mount`.
  A bare `# noqa` or `eslint-disable` without a rule is refused in review.
- **One file:** a per-file ignore in the tool's config, with a comment saying
  why. Lists like this only shrink.
- **One rule, everywhere:** turned off in the config with its reason beside it,
  like `B008` and `N818` in `pyproject.toml`.

## Updating the tools

- Ruff: bump `ruff==` in `apps/api/pyproject.toml` and the
  `astral-sh/ruff-pre-commit` hook together. `ruff-pin` refuses one without the
  other.
- Prettier, ESLint, TypeScript: `npm install` in `apps/web`. The hooks use the
  locked version.
- Hook repositories: `pre-commit autoupdate --freeze`, which pins each to a
  commit.
- GitHub Actions: Dependabot opens the bump, with the commit and the tag.

A formatter upgrade that changes output lands as its own commit, and that
commit goes in `.git-blame-ignore-revs`.
