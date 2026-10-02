---
paths:
  - "**/*.md"
---

# Markdown

Before writing or editing any Markdown in this repository, read
`docs/MARKDOWN_GUIDELINES.md` in full, once per session, and follow it. It condenses Google's,
Microsoft's and IBM's Markdown guidance and records where this repository departs from them and
why. `.markdownlint-cli2.jsonc` enforces the mechanical part on commit and in CI.

The ones most often missed:

- One H1 on the first line; headings in sentence case, one level at a time, no deeper than H4.
- Wrap prose at 100 columns. Never split an inline code span or a `$$` formula across lines.
- `-` bullets, nested two spaces under `-`; `_italic_` and `**bold**`.
- Every code fence names its language (`text` for output, trees and ASCII diagrams). A closing
  fence stands alone on its line.
- Link text says where it goes; repository links are relative with `.md`.
- No trailing spaces; a hard break is a trailing `\`, and rarely needed.
- Cite `DECISIONS.md §N` rather than restating a decision. Never put a secret or a customer
  identifier in a document.
- Run `npx markdownlint-cli2 <file>` (or let the hook do it) before finishing. Don't run
  `--fix` unreviewed: it has broken fences nested in lists.
