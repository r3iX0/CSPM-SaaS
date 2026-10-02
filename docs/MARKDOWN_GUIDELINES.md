# Markdown guidelines

How documentation is written in this repository: every `.md` file, from `README.md` to
`DECISIONS.md` and the Claude Code rules under `.claude/rules/`. It condenses three sources, and
where they disagree with each other or with this repository, it says which one wins and why:

- the [Google Markdown style guide](https://google.github.io/styleguide/docguide/style.html), for
  layout and the "minimum viable documentation" stance;
- [Microsoft's Markdown best practices](https://learn.microsoft.com/en-us/powershell/scripting/community/contributing/general-markdown),
  for CommonMark strictness, lists, emphasis and links;
- [IBM's Markdown documentation best practices](https://community.ibm.com/community/user/blogs/hiren-dave/2025/05/27/markdown-documentation-best-practices-for-document),
  for ownership, accessibility and maintenance.

Each rule is tagged with how it is held:

- **`[mdl MDxxx]`**: a markdownlint rule. It fails the commit hook and CI's `repo` job
  (`.markdownlint-cli2.jsonc`, DECISIONS.md §192).
- **`[review]`**: no tool can see it, so review does.

## 1. Principles

1. **Minimum viable documentation.** A short, true document beats a long, stale one. Delete what
   is no longer true, in small changes, rather than letting it rot. `[review]`
2. **Docs change with the code.** A change that alters behaviour updates the document that
   describes it in the same pull request. Generated documents (`docs/RULE_CATALOG.md`,
   `docs/api/`) are regenerated, never hand-edited; CI's drift checks refuse a stale one.
   `[review, CI drift checks]`
3. **Say it once.** A decision is recorded in `DECISIONS.md` and cited by section (`DECISIONS.md
   §168`) everywhere else, not restated. `[review]`
4. **Lead with the point.** The first paragraph says what the document is for and who it is for.
   The detail follows. `[review]`
5. **Better is better than best.** Review a document for being true and clear, not perfect. Fix a
   nit in a follow-up rather than blocking on it. `[review]`

## 2. Document layout

```markdown
# Title of the document

One or two paragraphs: what this is, who it is for, what to read first.

## First topic

...

## See also
```

- Use exactly one H1, on the first line, as the title. `[mdl MD025, MD041]`
- Increase heading levels one at a time, and go no deeper than H4. If you need H5, split the
  document. `[mdl MD001; depth: review]`
- A long document (more than one screen of headings) gets a short contents list after the
  introduction. GitHub also builds one from the headings. `[review]`
- Dated documents (`*_REVIEW_2026-09-20.md`, `SECURITY_AUDIT_2026-09.md`) are snapshots. They
  are kept lint-clean but their content is not updated; a newer review supersedes them in a new
  file. `[review]`

## 3. Headings

- Use ATX headings (`## Heading`), never underlined ones. `[mdl MD003]`
- Put one space after the `#`s and a blank line before and after. `[mdl MD018, MD019, MD022]`
- Write headings in sentence case: capitalize only the first word and proper nouns ("Scan
  execution", not "Scan Execution"). `[review]`
- Make headings unique and descriptive ("Risk scoring inputs", not "Inputs"), so a link to one
  is unambiguous. Repeating a heading under different parents is fine. `[mdl MD024]`
- No trailing punctuation, and no bold or code-only headings. `[mdl MD026; review]`
- Don't use bold text as a heading. `[mdl MD036]`

## 4. Paragraphs and line length

- Wrap prose at 100 columns, the same as the code. Wrapped text keeps diffs and review comments
  on the sentence that changed. Tables, code blocks, headings and an unbreakable URL may run
  over. `[mdl MD013]`
- Leave one blank line between blocks, never two. `[mdl MD012]`
- No trailing whitespace. For a hard line break, end the line with `\` (Google). The two-space
  break is invisible and editors strip it. Prefer a new paragraph or a list to either.
  `[mdl MD009]`
- No hard tabs. `[mdl MD010]`
- Keep paragraphs short: one idea each. Turn a run of parallel items into a list. `[review]`

## 5. Lists

- Bullets use `-`, never `*` or `+`. `*` is easily confused with emphasis. `[mdl MD004]`
- Use a numbered list only for steps that happen in order. Number either `1.` on every item (easy
  to reorder) or `1. 2. 3.`, consistently within a list. `[mdl MD029]`
- Indent nested items and continuation lines to the first character after the marker: two spaces
  under `-`, three under `1.`. `[mdl MD005, MD007]`
- Put a blank line before and after a list. `[mdl MD032]`
- End an item with a period only when it is a full sentence. Keep items in one list
  grammatically parallel. `[review]`
- If an item needs several paragraphs, it should probably be a subsection. `[review]`

## 6. Emphasis

- Use `**bold**` for the few words a skimming reader must not miss, and `_italic_` for a term
  being introduced or for light stress. Different characters make the intent visible when both
  appear. `[mdl MD049, MD050]`
- Use emphasis rarely: if everything is bold, nothing is. `[review]`
- No spaces inside the markers (`** wrong **`). `[mdl MD037]`

## 7. Code

- Put code, file paths, identifiers, commands, environment variables and literal values in
  backticks: `ScanWriter.commit`, `apps/api/pyproject.toml`, `APP_ENV=test`. `[review]`
- Use fenced code blocks, never indented ones, with backticks rather than tildes.
  `[mdl MD046, MD048]`
- Every fence names its language: `python`, `typescript`, `bash`, `sql`, `json`, `yaml`,
  `dotenv` for environment files, `mermaid` for diagrams, and `text` for output, trees and ASCII
  diagrams. `[mdl MD040]`
- Commands are copyable: no `$` prompt in front, unless the block also shows output.
  `[mdl MD014]`
- Put a blank line around a fence, except where it closes straight into the next item of a list.
  `[mdl MD031]`
- Inside a list, indent the fence to the item's text. A closing fence stands alone on its line.
  `[review]`
- Draw new diagrams in a ` ```mermaid ` block, which GitHub renders, rather than ASCII art.
  Existing ASCII diagrams stay as `text`. `[review]`

## 8. Links

- Link text says where the link goes, never "here", "this" or "link", and never a bare URL as
  text: `see [the deployment guide](DEPLOYMENT.md)`. `[mdl MD059]`
- No bare URLs in prose. Make it a link, or put a URL that is itself the subject in backticks.
  `[mdl MD034]`
- Link between repository files with relative paths that include the `.md` extension
  (`[Fix as code](FIX_AS_CODE.md#scope)`). They work on GitHub, in editors and offline. This
  departs from Google's root-absolute paths; see the table below. `[review]`
- Link to a heading with its lowercase, hyphenated anchor (`#risk-scoring-inputs`). An anchor
  must exist in the target. `[mdl MD051 within a file; review across files]`
- External links use `https://` and drop tracking and locale parameters (`?utm_*`, `/en-us/`).
  `[review]`
- Use reference-style links (`[text][id]`, defined after the paragraph) only where a long URL
  would bury the sentence. Every defined reference is used. `[mdl MD052, MD053]`
- No empty links or link text. `[mdl MD042]`

## 9. Images

- Every image has alt text that says what it shows; a decorative image has empty alt text.
  `[mdl MD045]`
- Use an image only when showing is clearer than telling. Never put text in an image, because it
  can't be searched, translated or read by a screen reader. `[review]`
- Store a document's images beside it, in `docs/media/<document-name>/`, with descriptive file
  names. Don't share one image between documents. `[review]`

## 10. Tables

- Use a table only for data that is parallel across rows: the same attributes for each item. For
  anything else, use a list, which is easier to edit, wrap and read with a screen reader.
  `[review]`
- Keep cells short. No paragraphs in a cell; if a cell needs one, the table should be a list.
  `[review]`
- Every row has the same number of cells as the header, with a leading and a trailing pipe.
  `[mdl MD055, MD056]`
- Use `<br>` for a line break inside a cell, the one place HTML is needed for it. `[mdl MD033]`
- Put a blank line before and after a table. `[mdl MD058]`

## 11. HTML

- Prefer Markdown to HTML everywhere. The only HTML allowed is what Markdown has no form for:
  `<details>`/`<summary>` for collapsible sections, `<b>` inside `<summary>`, and `<br>` in table
  cells. `[mdl MD033]`
- An HTML comment is fine for a note to the next editor, or to turn off one rule for one line
  with its reason: `<!-- markdownlint-disable-next-line MD013 -- a formula cannot wrap -->`.
  `[review]`
- To call out a warning or a note, use GitHub's alerts (`> [!NOTE]`, `> [!IMPORTANT]`,
  `> [!WARNING]`) sparingly, not coloured HTML. `[review]`

## 12. Writing

- Write for a reader who is new to this part of the system but knows the field. Define a term or
  acronym the first time it appears: "cloud security posture management (CSPM)". `[review]`
- Use plain, direct sentences in present tense and active voice: "The worker claims the step",
  not "The step will be claimed by the worker". `[review]`
- Name products and tools as their makers do: Azure, PostgreSQL, GitHub, Markdown, TypeScript.
  `[review]`
- Use the domain vocabulary of `app/core/vocabulary.py`: identifiers keep Azure's names, but
  sentences don't (DECISIONS.md §78). `[review]`
- Write absolute dates, like "20 September 2026", or `2026-09-20` in file names. Never write "last
  week". `[review]`
- Don't name a person as an owner or a TODO's assignee. Name the issue, the decision or the
  condition. `[review]`
- Never put a secret, token, real connection string or customer identifier in a document, even as
  an example. Use placeholders like `<project-ref>`. `[gitleaks, review]`

## 13. Exceptions

A rule that is wrong for one line is turned off for that line, with the rule and the reason:

```markdown
<!-- markdownlint-disable-next-line MD013 -- a formula cannot wrap -->
$$\text{Risk Score} = \dots$$
```

A rule that is wrong for the whole repository is changed in `.markdownlint-cli2.jsonc`, with the
reason beside it. Never disable a rule for a whole file to get a change through.

The hook only checks; it does not fix. `markdownlint-cli2 --fix` once inserted blank lines inside
a code fence nested in a list and turned a section into code, so fixes are made in the editor
(the VS Code extension shows each one) and reviewed like any other change.

---

## Where these depart from the sources

| Topic | Google | Microsoft | IBM | Here | Why |
|---|---|---|---|---|---|
| Line length | 80 | 100 | 100 | 100 | Matches the code; long URLs, tables and code exempt |
| Nested list indent | 4 spaces | align to text | — | align to text (2 under `-`) | CommonMark nests by alignment, so it reads the same in every renderer |
| Italic marker | — | `_` | `_` | `_` | Distinct from `**` bold |
| Ordered numbers | lazy `1.` for long lists | always `1.` | always `1.` | `1.` throughout or 1, 2, 3, per list | Short sequential lists read better in source; markdownlint holds consistency |
| Repository links | root-absolute `/docs/x.md` | relative with `.md` | — | relative with `.md` | Works on GitHub, in editors and offline; existing docs already do |
| Hard line break | trailing `\` | — | — | trailing `\`, rarely | The two-space break is invisible |
| Table of contents | `[TOC]` directive | — | — | short list when long | `[TOC]` is Gitiles-only; GitHub renders its own outline |
| Diagrams | images sparingly | — | — | Mermaid for new ones | Renders on GitHub, diffs as text |
