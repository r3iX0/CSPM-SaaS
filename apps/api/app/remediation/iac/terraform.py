"""Write a rule's fix into the customer's own Terraform, or say why not.

``terraform_hints`` names the argument to change. This finds the resource block
in a real file and changes it there, as a byte-range splice over a tree-sitter
parse, so the formatting, the alignment and the comments of everything else in
the file are exactly what the customer wrote (DECISIONS.md §166).

What it will do is narrow on purpose: change the literal value of an argument
in the one block that defines the asset, or add an optional argument that is
missing from a block that exists. What it will not do is everything that needs
a guess -- which resource an interpolated name renders to, what a variable
holds, which copy of a ``count`` is deployed, what else a nested block that is
not there should contain. Each of those is a ``Declined`` with a reason, and a
decline is an answer rather than an error: the customer is told what to change
by hand, which ``terraform_hints`` already says.

The input is untrusted -- an upload now, a repository later. It is parsed and
never evaluated, and it is refused before parsing above a size cap.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

import tree_sitter_hcl
from tree_sitter import Language, Node, Parser

# Larger than any hand-written module file; smaller than generated output
# nobody reviews line by line.
MAX_BYTES = 256 * 1024

# The azurerm releases the hinted attributes were checked against
# (tests/fixtures/terraform): 3.117.1 and 4.81.0. Nothing below 3.117 -- v3
# renamed arguments on its way to v4, and ``https_traffic_only_enabled`` is one
# of the late names -- and nothing from 5, which nobody has checked.
CHECKED_RELEASES = ("3.117.1", "4.81.0")
VERIFIED_FROM = (3, 117, 0)
VERIFIED_BELOW = (5, 0, 0)

_LANGUAGE = Language(tree_sitter_hcl.language())
_AZURERM_LOCK = re.compile(
    r'provider\s+"registry\.terraform\.io/hashicorp/azurerm"\s*\{[^}]*?'
    r'version\s*=\s*"([^"]+)"'
)
_CONSTRAINT_VERSION = re.compile(r'\bversion\s*=\s*"([^"]+)"')
_CONSTRAINT_PART = re.compile(r"\s*(~>|!=|>=|<=|=|>|<)?\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?\s*")

# (start, end, text, attribute, before) -- an insertion has start == end and
# ``before`` of ``None``.
_Splice = tuple[int, int, str, str, str | None]


class Decline(StrEnum):
    """Why no edit was made. The value is what the API returns."""

    TOO_LARGE = "too_large"
    PARSE_ERROR = "parse_error"
    NO_MATCH = "no_match"
    MULTIPLE_MATCHES = "multiple_matches"
    INTERPOLATED_NAME = "interpolated_name"
    COUNT_OR_FOR_EACH = "count_or_for_each"
    VARIABLE_VALUE = "variable_value"
    NESTED_BLOCK_MISSING = "nested_block_missing"
    EMPTY_BLOCK = "empty_block"
    DYNAMIC_BLOCK = "dynamic_block"
    PROVIDER_VERSION_OUT_OF_RANGE = "provider_version_out_of_range"
    ALREADY_SET = "already_set"
    # The engine's own safety net: the edited file did not read back as exactly
    # the change that was meant. Never expected; refused if it happens.
    UNVERIFIED = "unverified"
    # Decided before any file is read: the rule has no Terraform argument to set.
    NOT_EDITABLE = "not_editable"


@dataclass(frozen=True)
class Change:
    """One argument to set: a dotted path below the resource, and the HCL value."""

    attribute: str
    value: str


@dataclass(frozen=True)
class Edit:
    """One change as made. ``before`` is ``None`` where the argument was added."""

    attribute: str
    before: str | None
    after: str
    # 1-based, in the edited file.
    line: int


@dataclass(frozen=True)
class Patched:
    original: str
    source: str
    edits: tuple[Edit, ...]
    # From ``.terraform.lock.hcl`` where one was given. ``None`` is "not known",
    # which the caller says out loud rather than treating as checked.
    provider_version: str | None
    # How the block was found: by its literal ``name``, or as the only block of
    # the rule's types in a file a person chose for this asset. The second is
    # said out loud, so the reviewer checks the block is the one they meant.
    matched_by: Literal["name", "sole_block"] = "name"

    def diff(self, filename: str) -> str:
        return "".join(
            difflib.unified_diff(
                self.original.splitlines(keepends=True),
                self.source.splitlines(keepends=True),
                fromfile=f"a/{filename}",
                tofile=f"b/{filename}",
            )
        )


@dataclass(frozen=True)
class Declined:
    reason: Decline
    detail: str


class _Refused(Exception):
    def __init__(self, reason: Decline, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def edit_terraform(
    source: str,
    *,
    resource_types: Sequence[str],
    name: str,
    changes: Sequence[Change],
    lockfile: str | None = None,
    sole_block: bool = False,
) -> Patched | Declined:
    """Apply ``changes`` to the block of one of ``resource_types`` named ``name``.

    All or nothing: one change that cannot be made safely declines the lot,
    because half a fix leaves the finding open with the customer believing it
    closed.

    ``sole_block`` is for a file a person chose for this asset: there, the only
    block of these types is the one they meant even where its name is an
    expression. Never for a file CloudGuard found on its own (§166).
    """
    try:
        return _edit(source, resource_types, name, changes, lockfile, sole_block)
    except _Refused as refused:
        return Declined(refused.reason, refused.detail)


def _edit(
    source: str,
    resource_types: Sequence[str],
    name: str,
    changes: Sequence[Change],
    lockfile: str | None,
    sole_block: bool,
) -> Patched:
    data = source.encode()
    if len(data) > MAX_BYTES:
        raise _Refused(Decline.TOO_LARGE, f"The file is over {MAX_BYTES // 1024} KiB.")
    root = _parse(data)
    version = _provider_version(root, data, lockfile)
    block, matched_by = _locate(root, data, resource_types, name, sole_block)

    splices = [splice for change in changes if (splice := _plan(block, data, change))]
    if not splices:
        raise _Refused(Decline.ALREADY_SET, "The file already sets every value this fix asks for.")

    edited, edits = _apply(data, splices)
    _verify(edited, resource_types, name, changes, sole_block)
    order = {change.attribute: index for index, change in enumerate(changes)}
    return Patched(
        original=source,
        source=edited.decode(),
        edits=tuple(sorted(edits, key=lambda edit: order[edit.attribute])),
        provider_version=version,
        matched_by=matched_by,
    )


def _apply(data: bytes, splices: list[_Splice]) -> tuple[bytes, list[Edit]]:
    out = bytearray()
    edits: list[Edit] = []
    cursor = 0
    # Stable by offset, so two arguments added at one place land in the order asked.
    for start, end, text, attribute, before in sorted(splices, key=lambda s: s[0]):
        out += data[cursor:start]
        if before is None:
            # An added line: its number is the one it starts on, after any indent.
            after = text.split("=", 1)[1].strip()
            line = out.count(b"\n") + 1 + text[: text.index(attribute.rsplit(".", 1)[-1])].count(
                "\n"
            )
        else:
            after = text
            line = out.count(b"\n") + 1
        out += text.encode()
        cursor = end
        edits.append(Edit(attribute, before, after, line))
    out += data[cursor:]
    return bytes(out), edits


# ------------------------------------------------------------------- the tree
def _parse(data: bytes) -> Node:
    root = Parser(_LANGUAGE).parse(data).root_node
    if root.has_error:
        raise _Refused(Decline.PARSE_ERROR, "The file is not valid HCL.")
    return root


def _text(node: Node, data: bytes) -> str:
    return data[node.start_byte : node.end_byte].decode()


def _child(node: Node, kind: str) -> Node | None:
    return next((child for child in node.children if child.type == kind), None)


def _body(block: Node) -> Node | None:
    return _child(block, "body")


def _blocks(body: Node | None) -> list[Node]:
    return [] if body is None else [c for c in body.children if c.type == "block"]


def _keyword(block: Node, data: bytes) -> str:
    identifier = _child(block, "identifier")
    return "" if identifier is None else _text(identifier, data)


def _labels(block: Node, data: bytes) -> list[str]:
    return [_literal_string(c, data) or "" for c in block.children if c.type == "string_lit"]


def _attributes(body: Node | None, data: bytes) -> dict[str, Node]:
    if body is None:
        return {}
    found: dict[str, Node] = {}
    for child in body.children:
        if child.type == "attribute" and (identifier := _child(child, "identifier")):
            found[_text(identifier, data)] = child
    return found


def _value(attribute: Node) -> Node:
    expression = _child(attribute, "expression")
    assert expression is not None  # the grammar has no attribute without one
    return expression


def _literal(expression: Node) -> Node | None:
    """The ``literal_value`` an expression is, or ``None`` if it is anything else."""
    inner = expression.children[0] if expression.children else None
    return inner if inner is not None and inner.type == "literal_value" else None


def _literal_string(node: Node, data: bytes) -> str | None:
    """The text of a plain quoted string; ``None`` for anything interpolated."""
    if node.type == "expression":
        literal = _literal(node)
        if literal is None or not literal.children:
            return None
        node = literal.children[0]
    if node.type != "string_lit":
        return None
    parts = [
        c for c in node.children if c.type not in ("quoted_template_start", "quoted_template_end")
    ]
    if any(part.type != "template_literal" for part in parts):
        return None
    return "".join(_text(part, data) for part in parts)


# ---------------------------------------------------------------- the block
def _locate(
    root: Node, data: bytes, resource_types: Sequence[str], name: str, sole_block: bool
) -> tuple[Node, Literal["name", "sole_block"]]:
    wanted = name.casefold()
    matches: list[Node] = []
    interpolated: list[Node] = []
    for block in _blocks(_child(root, "body")):
        labels = _labels(block, data)
        if _keyword(block, data) != "resource" or not labels or labels[0] not in resource_types:
            continue
        named = _attributes(_body(block), data).get("name")
        if named is None:
            continue
        literal = _literal_string(_value(named), data)
        if literal is None:
            interpolated.append(block)
        elif literal.casefold() == wanted:
            matches.append(block)

    if len(matches) > 1:
        raise _Refused(
            Decline.MULTIPLE_MATCHES, f"{len(matches)} resources in this file are named {name!r}."
        )
    matched_by: Literal["name", "sole_block"] = "name"
    if sole_block and not matches and len(interpolated) == 1:
        # The only block of these types in a file chosen for this asset. A sole
        # block with a *different* literal name is another resource, and is not
        # taken: it never reaches here, as it is not interpolated.
        matches, interpolated, matched_by = interpolated, [], "sole_block"
    if interpolated:
        raise _Refused(
            Decline.INTERPOLATED_NAME,
            "A resource of this type takes its name from an expression, so which one "
            f"is {name!r} cannot be told from the file.",
        )
    if not matches:
        raise _Refused(Decline.NO_MATCH, f"No resource in this file is named {name!r}.")

    (block,) = matches
    meta = _attributes(_body(block), data).keys() & {"count", "for_each"}
    if meta:
        raise _Refused(
            Decline.COUNT_OR_FOR_EACH,
            f"The resource uses {sorted(meta)[0]}, so one block defines several.",
        )
    return block, matched_by


def _nested_body(block: Node, data: bytes, path: Sequence[str]) -> Node:
    body = _body(block)
    for name in path:
        blocks = _blocks(body)
        if any(_keyword(b, data) == "dynamic" and _labels(b, data)[:1] == [name] for b in blocks):
            raise _Refused(
                Decline.DYNAMIC_BLOCK, f"{name} is a dynamic block, generated rather than written."
            )
        found = [b for b in blocks if _keyword(b, data) == name]
        if not found:
            raise _Refused(
                Decline.NESTED_BLOCK_MISSING,
                f"The resource has no {name} block, and adding one needs settings only "
                "you can choose.",
            )
        if len(found) > 1:
            raise _Refused(
                Decline.MULTIPLE_MATCHES, f"The resource has {len(found)} {name} blocks."
            )
        body = _body(found[0])
        if body is None:
            raise _Refused(Decline.EMPTY_BLOCK, f"The {name} block is empty.")
    assert body is not None  # a located resource has a body: it holds ``name``
    return body


# ----------------------------------------------------------------- the edit
def _plan(block: Node, data: bytes, change: Change) -> _Splice | None:
    *path, leaf = change.attribute.split(".")
    body = _nested_body(block, data, path)
    attribute = _attributes(body, data).get(leaf)

    if attribute is not None:
        expression = _value(attribute)
        literal = _literal(expression)
        is_string = bool(literal and literal.children and literal.children[0].type == "string_lit")
        if literal is None or (is_string and _literal_string(expression, data) is None):
            raise _Refused(
                Decline.VARIABLE_VALUE,
                f"{change.attribute} is set from an expression; change it where its value "
                "comes from.",
            )
        before = _text(expression, data)
        if before.strip() == change.value:
            return None
        return (expression.start_byte, expression.end_byte, change.value, change.attribute, before)

    line = f"{leaf} = {change.value}"
    siblings = [c for c in body.children if c.type == "attribute"]
    if siblings:
        anchor = siblings[-1]
        indent = data[anchor.start_byte - anchor.start_point.column : anchor.start_byte].decode()
        # After the whole line, so a trailing comment stays with its argument.
        newline = data.index(b"\n", anchor.end_byte) + 1
        return (newline, newline, f"{indent}{line}\n", change.attribute, None)
    first = body.children[0]
    indent = data[first.start_byte - first.start_point.column : first.start_byte].decode()
    return (first.start_byte, first.start_byte, f"{line}\n{indent}", change.attribute, None)


def _verify(
    edited: bytes,
    resource_types: Sequence[str],
    name: str,
    changes: Sequence[Change],
    sole_block: bool,
) -> None:
    """Read the edited file back and refuse unless it says what was meant."""
    try:
        block, _ = _locate(_parse(edited), edited, resource_types, name, sole_block)
        for change in changes:
            *path, leaf = change.attribute.split(".")
            attribute = _attributes(_nested_body(block, edited, path), edited).get(leaf)
            if attribute is None or _text(_value(attribute), edited).strip() != change.value:
                raise _Refused(Decline.UNVERIFIED, change.attribute)
    except _Refused as refused:
        raise _Refused(
            Decline.UNVERIFIED, "The edited file did not read back as the intended change."
        ) from refused


# ------------------------------------------------------------ the provider
def _provider_version(root: Node, data: bytes, lockfile: str | None) -> str | None:
    constraint = _required_azurerm(root, data)
    if constraint is not None and not _constraint_in_range(constraint):
        raise _Refused(
            Decline.PROVIDER_VERSION_OUT_OF_RANGE,
            f"The file pins azurerm {constraint}; this fix was checked against 3.117 and 4.x.",
        )
    locked = _AZURERM_LOCK.search(lockfile) if lockfile else None
    if locked is None:
        return None
    version = locked.group(1)
    if not VERIFIED_FROM <= _release(version) < VERIFIED_BELOW:
        raise _Refused(
            Decline.PROVIDER_VERSION_OUT_OF_RANGE,
            f"The lock file holds azurerm {version}; this fix was checked against 3.117 and 4.x.",
        )
    return version


def _required_azurerm(root: Node, data: bytes) -> str | None:
    for terraform in _blocks(_child(root, "body")):
        if _keyword(terraform, data) != "terraform":
            continue
        for required in _blocks(_body(terraform)):
            if _keyword(required, data) != "required_providers":
                continue
            azurerm = _attributes(_body(required), data).get("azurerm")
            if azurerm is not None and (found := _CONSTRAINT_VERSION.search(_text(azurerm, data))):
                return found.group(1)
    return None


def _release(version: str) -> tuple[int, int, int]:
    major, minor, patch = ([int(n) for n in re.findall(r"\d+", version)[:3]] + [0, 0, 0])[:3]
    return major, minor, patch


def _constraint_in_range(constraint: str) -> bool:
    """False only where the constraint rules out every checked release.

    A lower bound alone (``>= 3.0``) can resolve to a checked release, and so
    can ``~> 3.0``; ``~> 2.0`` and ``= 2.99.0`` cannot. Anything this cannot
    read is left to the lock file rather than declined on.
    """
    for part in constraint.split(","):
        match = _CONSTRAINT_PART.fullmatch(part)
        if match is None:
            continue
        operator, major, minor, patch = match.groups()
        release = (int(major), int(minor or 0), int(patch or 0))
        if operator in (None, "="):
            if not VERIFIED_FROM <= release < VERIFIED_BELOW:
                return False
        elif operator == "~>":
            # ~> 3.0 allows any 3.x; ~> 3.100.0 allows 3.100.x only.
            upper = (release[0], release[1] + 1, 0) if patch else (release[0] + 1, 0, 0)
            if upper <= VERIFIED_FROM or release >= VERIFIED_BELOW:
                return False
    return True
