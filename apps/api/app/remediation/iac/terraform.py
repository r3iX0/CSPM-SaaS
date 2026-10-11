"""Write a rule's fix into the customer's own Terraform, or say why not.

``terraform_hints`` names the argument to change. This finds the resource block
in a real file and changes it there, as a byte-range splice over a tree-sitter
parse, so the formatting, the alignment and the comments of everything else in
the file are exactly what the customer wrote (DECISIONS.md §190).

What it will do is narrow on purpose: change the literal value of an argument
in the one block that defines the asset, or add an optional argument that is
missing from a block that exists. What it will not do is everything that needs
a guess -- which resource an interpolated name renders to, what a variable
holds, which copy of a ``count`` is deployed, what else a nested block that is
not there should contain. Each of those is a ``Declined`` with a reason, and a
decline is an answer rather than an error: the customer is told what to change
by hand, which ``terraform_hints`` already says. The one value followed out of
the block is a module's input passed straight through, which is written on the
module call instead (``edit_module_input``, §233).

The input is untrusted -- an upload now, a repository later. It is parsed and
never evaluated, and it is refused before parsing above a size cap.
"""

from __future__ import annotations

import difflib
import posixpath
import re
from collections.abc import Mapping, Sequence
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
    # Adding an argument to ``x { a = 1 }`` means splitting the line, which is
    # reformatting the customer's code rather than editing one value.
    SINGLE_LINE_BLOCK = "single_line_block"
    PROVIDER_VERSION_OUT_OF_RANGE = "provider_version_out_of_range"
    ALREADY_SET = "already_set"
    # The engine's own safety net: the edited file did not read back as exactly
    # the change that was meant. Never expected; refused if it happens.
    UNVERIFIED = "unverified"
    # Decided before any file is read: the rule has no Terraform argument to set.
    NOT_EDITABLE = "not_editable"
    # Decided before any file is read: changing the argument makes Terraform
    # destroy the resource and create another, which no fix may do (§228).
    REPLACES_RESOURCE = "replaces_resource"
    # Following a state address (§229): a module on the way is not in this
    # repository (a registry or git source), or the address no longer names a
    # block in the code, which moved since the index was uploaded.
    MODULE_EXTERNAL = "module_external"
    INDEX_STALE = "index_stale"
    # A block under ``count``, ``for_each`` or several workspaces defines more
    # assets than fail the rule, so editing it would change the rest too (§232).
    PARTIAL_INSTANCES = "partial_instances"
    # Through a module's inputs (§233): the module uses the input variable
    # somewhere else too, or other code calls the module and no uploaded state
    # index says what that code deployed, so an edit would change what nobody
    # asked about.
    VARIABLE_SHARED = "variable_shared"
    UNINDEXED_CALLER = "unindexed_caller"


@dataclass(frozen=True)
class Renamed:
    """The argument's name and value from a major azurerm release on (§230)."""

    since: int
    attribute: str
    value: str


@dataclass(frozen=True)
class Change:
    """One argument to set: a dotted path below the resource, and the HCL value."""

    attribute: str
    value: str
    # Other values that already meet the rule, as HCL. A file holding one of
    # them is left alone: TLS 1.3 rewritten to the 1.2 a rule asks for is a
    # regression dressed as a fix.
    accepts: tuple[str, ...] = ()
    # Later names of the argument. ``attribute`` is the one every checked
    # release accepts, written when nothing says which release the file is for.
    renamed: tuple[Renamed, ...] = ()

    def met_by(self, written: str) -> bool:
        return written.strip() in (self.value, *self.accepts)


@dataclass(frozen=True)
class RuleChanges:
    """What one rule's fix writes, and the resource types it may write it into."""

    resource_types: tuple[str, ...]
    changes: tuple[Change, ...]


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
    # How the block was found: by its literal ``name``, as the only block of
    # the rule's types in a file a person chose for this asset, or by the label
    # the customer's own state gives the asset (``address``, §229). The second is
    # said out loud, so the reviewer checks the block is the one they meant.
    matched_by: Literal["name", "sole_block", "address"] = "name"

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
class Passed:
    """A change whose argument is written ``= var.<variable>``: its value is the caller's (§233).

    ``change`` keeps the name and value the resource block needs, so whichever
    module call sets the variable is given that value.
    """

    variable: str
    change: Change


@dataclass(frozen=True)
class Declined:
    reason: Decline
    detail: str
    # Set where every change left is a module input passed straight through, so
    # the edit belongs one call up (``edit_module_input``); asked for only by a
    # caller that can follow the module call (§233).
    passed: tuple[Passed, ...] = ()


class _Refused(Exception):
    def __init__(self, reason: Decline, detail: str, passed: tuple[Passed, ...] = ()) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
        self.passed = passed


def edit_terraform(
    source: str,
    *,
    resource_types: Sequence[str],
    name: str,
    changes: Sequence[Change],
    lockfile: str | None = None,
    sole_block: bool = False,
    label: str | None = None,
    allow_repeated: bool = False,
    through_inputs: bool = False,
) -> Patched | Declined:
    """Apply ``changes`` to the block of one of ``resource_types`` named ``name``.

    All or nothing: one change that cannot be made safely declines the lot,
    because half a fix leaves the finding open with the customer believing it
    closed.

    ``sole_block`` is for a file a person chose for this asset: there, the only
    block of these types is the one they meant even where its name is an
    expression. Never for a file CloudGuard found on its own (§190).

    ``label`` is the block's own label from the customer's state address
    (``resource "azurerm_storage_account" "<label>"``), which names the block
    exactly whatever its ``name`` renders to (§229). Given, it replaces the name
    search; ``find_resource_block`` says which file to pass.

    ``allow_repeated`` edits a block under ``count`` or ``for_each``, which
    changes every instance it defines. Only for a caller that has checked every
    instance fails the rule, from the customer's state index (§232).

    ``through_inputs`` is for a block inside a module the caller can follow:
    where every change left is written ``= var.<name>``, the decline carries
    them as ``passed``, for ``edit_module_input`` to set on the module call
    (§233). Without it, such a value declines as any other expression does.
    """
    try:
        return _edit(
            source,
            resource_types,
            name,
            changes,
            lockfile,
            sole_block,
            label,
            allow_repeated,
            through_inputs,
        )
    except _Refused as refused:
        return Declined(refused.reason, refused.detail, refused.passed)


@dataclass(frozen=True)
class Removed:
    """A resource block taken out of a file whole (DECISIONS.md section 257)."""

    original: str
    source: str
    #: 1-based line the block started on, in the original file.
    line: int

    def diff(self, filename: str) -> str:
        return "".join(
            difflib.unified_diff(
                self.original.splitlines(keepends=True),
                self.source.splitlines(keepends=True),
                fromfile=f"a/{filename}",
                tofile=f"b/{filename}",
            )
        )


def remove_resource_block(
    source: str, *, resource_type: str, label: str, allow_repeated: bool = False
) -> Removed | Declined:
    """Delete the ``resource "<type>" "<label>"`` block, with the blank line after it.

    A new kind of edit beside ``edit_terraform``, which only changes arguments:
    removing a role assignment, the cut a customer makes most, is deleting its
    block. Found by its label from the customer's state address, exactly as an
    edit is (section 229). ``allow_repeated`` deletes a block under ``count``
    or ``for_each``, which removes every assignment it defines -- only for a
    caller that checked each of them is in the plan.
    """
    try:
        data = source.encode()
        root = _parse(data)
        block = _by_label(root, data, (resource_type,), label, allow_repeated)
    except _Refused as refused:
        return Declined(refused.reason, refused.detail)
    start = data.rfind(b"\n", 0, block.start_byte) + 1
    end = block.end_byte
    # The line break that ends the block, and one blank line after it, go with
    # it, so the file keeps the spacing it had between the blocks either side.
    for _ in range(2):
        if data[end : end + 1] == b"\n":
            end += 1
        else:
            break
    removed = data[:start] + data[end:]
    return Removed(original=source, source=removed.decode(), line=block.start_point[0] + 1)


def _edit(
    source: str,
    resource_types: Sequence[str],
    name: str,
    changes: Sequence[Change],
    lockfile: str | None,
    sole_block: bool,
    label: str | None,
    allow_repeated: bool = False,
    through_inputs: bool = False,
) -> Patched:
    data = source.encode()
    if len(data) > MAX_BYTES:
        raise _Refused(Decline.TOO_LARGE, f"The file is over {MAX_BYTES // 1024} KiB.")
    root = _parse(data)
    version = _provider_version(root, data, lockfile)
    block, matched_by = _find(root, data, resource_types, name, sole_block, label, allow_repeated)
    major = _release(version)[0] if version is not None else None
    changes = [_named(block, data, change, major) for change in changes]

    passed = [
        Passed(variable, change)
        for change in changes
        if through_inputs and (variable := _passed_variable(block, data, change))
    ]
    written = [change for change in changes if all(p.change is not change for p in passed)]
    splices = [splice for change in written if (splice := _plan(block, data, change))]
    if passed:
        _refuse_passed(passed, mixed=bool(splices), where="this block")
    if not splices:
        raise _Refused(Decline.ALREADY_SET, "The file already sets every value this fix asks for.")

    edited, edits = _apply(data, splices)
    _verify(edited, resource_types, name, changes, sole_block, label, allow_repeated)
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
            line = (
                out.count(b"\n") + 1 + text[: text.index(attribute.rsplit(".", 1)[-1])].count("\n")
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
def _find(
    root: Node,
    data: bytes,
    resource_types: Sequence[str],
    name: str,
    sole_block: bool,
    label: str | None,
    allow_repeated: bool = False,
) -> tuple[Node, Literal["name", "sole_block", "address"]]:
    if label is None:
        return _locate(root, data, resource_types, name, sole_block)
    return _by_label(root, data, resource_types, label, allow_repeated), "address"


def _resource_blocks(
    root: Node, data: bytes, resource_types: Sequence[str], label: str
) -> list[Node]:
    return _resource_blocks_in(_blocks(_child(root, "body")), data, resource_types, label)


def _by_label(
    root: Node, data: bytes, resource_types: Sequence[str], label: str, allow_repeated: bool
) -> Node:
    matches = _resource_blocks(root, data, resource_types, label)
    if not matches:
        raise _Refused(Decline.INDEX_STALE, f"No resource in this file is labelled {label!r}.")
    if len(matches) > 1:
        raise _Refused(
            Decline.MULTIPLE_MATCHES,
            f"{len(matches)} resources in this file are labelled {label!r}.",
        )
    (block,) = matches
    if not allow_repeated:
        _refuse_repeated(block, data)
    return block


def _refuse_repeated(block: Node, data: bytes, noun: str = "resource") -> None:
    meta = _attributes(_body(block), data).keys() & {"count", "for_each"}
    if meta:
        raise _Refused(
            Decline.COUNT_OR_FOR_EACH,
            f"The {noun} uses {sorted(meta)[0]}, so one block defines several.",
        )


def _locate(
    root: Node, data: bytes, resource_types: Sequence[str], name: str, sole_block: bool
) -> tuple[Node, Literal["name", "sole_block"]]:
    wanted = name.casefold()
    matches: list[Node] = []
    interpolated: list[Node] = []
    others = 0
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
        else:
            others += 1

    if len(matches) > 1:
        raise _Refused(
            Decline.MULTIPLE_MATCHES, f"{len(matches)} resources in this file are named {name!r}."
        )
    matched_by: Literal["name", "sole_block"] = "name"
    if sole_block and not matches and not others and len(interpolated) == 1:
        # The only block of these types in a file chosen for this asset -- the
        # only one at all, as the reviewer is told. A sole block with a
        # *different* literal name is another resource and is never taken.
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
    _refuse_repeated(block, data)
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
def _named(block: Node, data: bytes, change: Change, major: int | None) -> Change:
    """``change`` under the name this block and this release use (§230).

    The name the block already sets wins: writing the other beside it would set
    one argument twice, which ``terraform plan`` refuses. Otherwise the newest
    name the lock file's release documents, and with no lock file the original
    name, which every checked release still accepts.
    """
    names = [change, *(Change(r.attribute, r.value) for r in change.renamed)]
    for named in names:
        *path, leaf = named.attribute.split(".")
        try:
            if leaf in _attributes(_nested_body(block, data, path), data):
                return named
        except _Refused:
            continue
    later = [r for r in change.renamed if major is not None and r.since <= major]
    if later:
        newest = max(later, key=lambda r: r.since)
        return Change(newest.attribute, newest.value)
    return change


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
        if change.met_by(before):
            return None
        return (expression.start_byte, expression.end_byte, change.value, change.attribute, before)

    line = f"{leaf} = {change.value}"
    # The file's own line ending, so a CRLF file does not come back mixed.
    eol = "\r\n" if b"\r\n" in data else "\n"
    siblings = [c for c in body.children if c.type == "attribute"]
    anchor = siblings[-1] if siblings else body.children[0]
    closing = _child(body.parent, "block_end") if body.parent is not None else None
    if closing is None or anchor.end_point.row >= closing.start_point.row:
        raise _Refused(
            Decline.SINGLE_LINE_BLOCK,
            f"The block that would hold {change.attribute} is written on one line.",
        )
    indent = data[anchor.start_byte - anchor.start_point.column : anchor.start_byte].decode()
    if siblings:
        # After the whole line, so a trailing comment stays with its argument.
        # The block closes on a later line, so that line has an end.
        newline = data.index(b"\n", anchor.end_byte) + 1
        return (newline, newline, f"{indent}{line}{eol}", change.attribute, None)
    return (anchor.start_byte, anchor.start_byte, f"{line}{eol}{indent}", change.attribute, None)


def _verify(
    edited: bytes,
    resource_types: Sequence[str],
    name: str,
    changes: Sequence[Change],
    sole_block: bool,
    label: str | None,
    allow_repeated: bool,
) -> None:
    """Read the edited file back and refuse unless it says what was meant."""
    try:
        block, _ = _find(
            _parse(edited), edited, resource_types, name, sole_block, label, allow_repeated
        )
        for change in changes:
            *path, leaf = change.attribute.split(".")
            attribute = _attributes(_nested_body(block, edited, path), edited).get(leaf)
            if attribute is None or not change.met_by(_text(_value(attribute), edited)):
                raise _Refused(Decline.UNVERIFIED, change.attribute)
    except _Refused as refused:
        raise _Refused(
            Decline.UNVERIFIED, "The edited file did not read back as the intended change."
        ) from refused


# ------------------------------------------------------- through module inputs
def _bare_variable(expression: Node, data: bytes) -> str | None:
    """``x`` where the expression is exactly ``var.x``; ``None`` for anything else.

    ``var.x.y``, ``"${var.x}"``, ``!var.x`` and ``coalesce(var.x, ...)`` all
    transform the value on the way, so the value to pass in is not the one the
    argument needs.
    """
    parts = expression.children
    if (
        len(parts) != 2
        or parts[0].type != "variable_expr"
        or _text(parts[0], data) != "var"
        or parts[1].type != "get_attr"
    ):
        return None
    identifier = _child(parts[1], "identifier")
    return None if identifier is None else _text(identifier, data)


def _passed_variable(block: Node, data: bytes, change: Change) -> str | None:
    *path, leaf = change.attribute.split(".")
    try:
        body = _nested_body(block, data, path)
    except _Refused:
        return None  # ``_plan`` says why, as it would without modules.
    attribute = _attributes(body, data).get(leaf)
    return None if attribute is None else _bare_variable(_value(attribute), data)


def _refuse_passed(passed: Sequence[Passed], *, mixed: bool, where: str) -> None:
    first = passed[0]
    if mixed:
        # Half in the block and half on the call is two edits in two places
        # for one fix; rare enough to leave to a person.
        raise _Refused(
            Decline.VARIABLE_VALUE,
            f"{first.change.attribute} is set from var.{first.variable} but other arguments "
            f"of this fix are written in {where}; change them together by hand.",
        )
    raise _Refused(
        Decline.VARIABLE_VALUE,
        f"{first.change.attribute} is set from var.{first.variable}, an input of this module; "
        "change it where its value comes from.",
        tuple(passed),
    )


def edit_module_input(
    source: str,
    *,
    module: str,
    inputs: Sequence[Passed],
    defaults: Mapping[str, str | None],
    lockfile: str | None = None,
    allow_repeated: bool = False,
) -> Patched | Declined:
    """Set each passed-through input on the ``module "<module>"`` call in ``source`` (§233).

    The call's literal value is changed, or the input is added where the call
    leaves it to the variable's default. ``defaults`` holds each variable's
    default as written, ``None`` for one with none; the caller has checked that
    the module uses each variable for this argument and nothing else
    (``Repository.variable``). Where the call itself passes ``var.<y>`` along,
    the decline carries it as ``passed``, for the call one level further up.
    """
    try:
        return _edit_input(source, module, inputs, defaults, lockfile, allow_repeated)
    except _Refused as refused:
        return Declined(refused.reason, refused.detail, refused.passed)


def _edit_input(
    source: str,
    module: str,
    inputs: Sequence[Passed],
    defaults: Mapping[str, str | None],
    lockfile: str | None,
    allow_repeated: bool,
) -> Patched:
    data = source.encode()
    if len(data) > MAX_BYTES:
        raise _Refused(Decline.TOO_LARGE, f"The file is over {MAX_BYTES // 1024} KiB.")
    root = _parse(data)
    version = _provider_version(root, data, lockfile)
    call = _module_call(root, data, module, allow_repeated)
    arguments = _attributes(_body(call), data)

    passed: list[Passed] = []
    changes: list[Change] = []
    for item in inputs:
        change = Change(item.variable, item.change.value, item.change.accepts)
        attribute = arguments.get(item.variable)
        if attribute is not None and (variable := _bare_variable(_value(attribute), data)):
            passed.append(Passed(variable, item.change))
            continue
        if attribute is None:
            default = defaults.get(item.variable)
            if default is None:
                raise _Refused(
                    Decline.INDEX_STALE,
                    f"Module {module!r} does not set {item.variable}, which has no default.",
                )
            if change.met_by(default):
                continue  # The default already meets the rule; nothing to add.
        changes.append(change)

    splices = [splice for change in changes if (splice := _plan(call, data, change))]
    if passed:
        _refuse_passed(passed, mixed=bool(splices), where=f"module {module!r}")
    if not splices:
        raise _Refused(Decline.ALREADY_SET, "The module call already passes what this fix asks.")
    edited, edits = _apply(data, splices)
    try:
        written = _attributes(_body(_module_call(_parse(edited), edited, module, True)), edited)
        if not all(
            c.attribute in written and c.met_by(_text(_value(written[c.attribute]), edited))
            for c in changes
        ):
            raise _Refused(Decline.UNVERIFIED, module)
    except _Refused as refused:
        raise _Refused(
            Decline.UNVERIFIED, "The edited file did not read back as the intended change."
        ) from refused
    return Patched(
        original=source,
        source=edited.decode(),
        edits=tuple(edits),
        provider_version=version,
        matched_by="address",
    )


def _module_call(root: Node, data: bytes, module: str, allow_repeated: bool) -> Node:
    calls = [
        block
        for block in _blocks(_child(root, "body"))
        if _keyword(block, data) == "module" and _labels(block, data) == [module]
    ]
    if not calls:
        raise _Refused(Decline.INDEX_STALE, f"No module {module!r} is called in this file.")
    if len(calls) > 1:
        raise _Refused(Decline.MULTIPLE_MATCHES, f"{len(calls)} module calls are named {module!r}.")
    (call,) = calls
    if not allow_repeated:
        _refuse_repeated(call, data, "module call")
    return call


def _references(node: Node, data: bytes, variable: str) -> int:
    """How many times ``var.<variable>`` appears under ``node``, templates included."""
    count = 0
    stack = [node]
    while stack:
        current = stack.pop()
        siblings = current.children
        for index, child in enumerate(siblings[:-1]):
            if child.type == "variable_expr" and _text(child, data) == "var":
                following = siblings[index + 1]
                identifier = _child(following, "identifier")
                if following.type == "get_attr" and identifier is not None:
                    count += _text(identifier, data) == variable
        stack.extend(siblings)
    return count


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
        elif operator in (">=", ">"):
            # Everything allowed is at or above this; from 5 on, none was checked.
            if release >= VERIFIED_BELOW:
                return False
        elif operator in ("<", "<="):
            below = release < VERIFIED_FROM if operator == "<=" else release <= VERIFIED_FROM
            if below:
                return False
        elif operator == "~>":
            # ~> 3.0 allows any 3.x; ~> 3.100.0 allows 3.100.x only.
            upper = (release[0], release[1] + 1, 0) if patch else (release[0] + 1, 0, 0)
            if upper <= VERIFIED_FROM or release >= VERIFIED_BELOW:
                return False
    return True


# ---------------------------------------------------------- by state address
@dataclass(frozen=True)
class ModuleCall:
    """A ``module "<label>"`` block with a local source: the file holding it, and its directory."""

    path: str
    label: str
    directory: str


@dataclass(frozen=True)
class FoundBlock:
    """Where a state address's resource is written: a file of the repository, and its label."""

    path: str
    label: str
    #: The module calls the address passes through, outermost first.
    calls: tuple[ModuleCall, ...] = ()


@dataclass(frozen=True)
class Variable:
    """A module's input variable that one argument uses and nothing else does (§233)."""

    #: As written, or ``None`` where the variable has no default.
    default: str | None


def find_resource_block(
    files: Mapping[str, str],
    working_directory: str,
    modules: Sequence[str],
    resource_type: str,
    label: str,
) -> FoundBlock | Declined:
    """Follow a state address from the directory Terraform ran in to its resource block.

    ``modules`` are the address's module calls in order, without their
    instance keys: ``module.storage["eu"].azurerm_storage_account.main`` is
    ``("storage",)``, ``azurerm_storage_account`` and ``main``. Each call's
    ``source`` must be a local path inside the repository; a registry or git
    module is declined, because the block is not here to edit (§229).

    ``files`` maps repository-relative paths to their text. Only ``.tf`` files
    in the directory a step reaches are read, and each is parsed, never evaluated.
    """
    return Repository(files).find_resource_block(working_directory, modules, resource_type, label)


class Repository:
    """A repository's Terraform, each file parsed once, read for what an edit depends on.

    A pull request's plan asks the same files many questions -- where every
    indexed address is written, which code calls a module, what uses a
    variable -- so the parse of each file is kept.
    """

    def __init__(self, files: Mapping[str, str]) -> None:
        self._files = files
        self._parsed: dict[str, tuple[Node, bytes]] = {}
        self._calls: dict[str, list[ModuleCall]] | None = None

    def _parse(self, path: str) -> tuple[Node, bytes]:
        if path not in self._parsed:
            data = self._files[path].encode()
            if len(data) > MAX_BYTES:
                raise _Refused(Decline.TOO_LARGE, f"{path} is over {MAX_BYTES // 1024} KiB.")
            try:
                self._parsed[path] = (_parse(data), data)
            except _Refused as refused:
                raise _Refused(refused.reason, f"{path} is not valid HCL.") from refused
        return self._parsed[path]

    def _in(self, directory: str) -> list[str]:
        return [
            path
            for path in sorted(self._files)
            if path.endswith(".tf") and posixpath.dirname(path) == directory
        ]

    def _blocks_in(self, directory: str) -> list[tuple[str, Node, bytes]]:
        found = []
        for path in self._in(directory):
            root, data = self._parse(path)
            found += [(path, block, data) for block in _blocks(_child(root, "body"))]
        return found

    def find_resource_block(
        self, working_directory: str, modules: Sequence[str], resource_type: str, label: str
    ) -> FoundBlock | Declined:
        """``find_resource_block``, over this repository's parsed files."""
        try:
            calls = self._follow(working_directory, modules)
            directory = calls[-1].directory if calls else _inside(working_directory, "")
            found = sorted(
                {
                    path
                    for path, block, data in self._blocks_in(directory)
                    if _resource_blocks_in([block], data, (resource_type,), label)
                }
            )
        except _Refused as refused:
            return Declined(refused.reason, refused.detail)
        if not found:
            return Declined(
                Decline.INDEX_STALE,
                f"No {resource_type} labelled {label!r} is in {directory or 'the root'} any more.",
            )
        if len(found) > 1:
            return Declined(
                Decline.MULTIPLE_MATCHES, f"{len(found)} files define {resource_type}.{label}."
            )
        return FoundBlock(path=found[0], label=label, calls=calls)

    def module_calls(
        self, working_directory: str, modules: Sequence[str]
    ) -> tuple[ModuleCall, ...] | Declined:
        """The local module calls an address passes through, or why they cannot be followed."""
        try:
            return self._follow(working_directory, modules)
        except _Refused as refused:
            return Declined(refused.reason, refused.detail)

    def _follow(self, working_directory: str, modules: Sequence[str]) -> tuple[ModuleCall, ...]:
        directory = _inside(working_directory, "")
        calls: list[ModuleCall] = []
        for module in modules:
            call = self._call(directory, module)
            calls.append(call)
            directory = call.directory
        return tuple(calls)

    def _call(self, directory: str, module: str) -> ModuleCall:
        for path, block, data in self._blocks_in(directory):
            if _keyword(block, data) != "module" or _labels(block, data) != [module]:
                continue
            source = _attributes(_body(block), data).get("source")
            literal = None if source is None else _literal_string(_value(source), data)
            if literal is None or not literal.startswith(("./", "../")):
                raise _Refused(
                    Decline.MODULE_EXTERNAL,
                    f"Module {module!r} comes from {literal or 'an expression'}, "
                    "which is not in this repository.",
                )
            return ModuleCall(path, module, _inside(literal, directory))
        raise _Refused(
            Decline.INDEX_STALE, f"No module {module!r} is called in {directory or 'the root'}."
        )

    def callers(self, directory: str) -> list[ModuleCall] | Declined:
        """Every module call in the repository whose local source is ``directory``.

        Every file is read, since a call can be anywhere; one that does not
        parse is a decline, because what it calls cannot be told.
        """
        if self._calls is None:
            calls: dict[str, list[ModuleCall]] = {}
            try:
                for path in sorted(self._files):
                    if not path.endswith(".tf"):
                        continue
                    root, data = self._parse(path)
                    for block in _blocks(_child(root, "body")):
                        call = _local_call(path, block, data)
                        if call is not None:
                            calls.setdefault(call.directory, []).append(call)
            except _Refused as refused:
                return Declined(refused.reason, refused.detail)
            self._calls = calls
        return self._calls.get(directory, [])

    def variable(self, directory: str, name: str) -> Variable | Declined:
        """The module's ``variable "<name>"``, if one argument is all that uses it (§233).

        Used anywhere else, setting it would change that too, so it declines
        ``variable_shared``. A ``validation`` block declines as well: it may
        refuse the value the fix needs, and only ``terraform plan`` can say.
        """
        where = directory or "the root"
        try:
            blocks = self._blocks_in(directory)
        except _Refused as refused:
            return Declined(refused.reason, refused.detail)
        declared = [
            (block, data)
            for _path, block, data in blocks
            if _keyword(block, data) == "variable" and _labels(block, data) == [name]
        ]
        if len(declared) != 1:
            return Declined(Decline.INDEX_STALE, f"var.{name} is not declared once in {where}.")
        ((block, data),) = declared
        if any(_keyword(nested, data) == "validation" for nested in _blocks(_body(block))):
            return Declined(
                Decline.VARIABLE_VALUE,
                f"var.{name} has a validation rule, which may refuse the value this fix needs.",
            )
        uses = sum(_references(top, data, name) for _path, top, data in blocks)
        if uses != 1:
            return Declined(
                Decline.VARIABLE_SHARED,
                f"var.{name} is used {uses} times in {where}, so setting it changes more "
                "than this argument.",
            )
        default = _attributes(_body(block), data).get("default")
        return Variable(None if default is None else _text(_value(default), data))


def _resource_blocks_in(
    blocks: Sequence[Node], data: bytes, resource_types: Sequence[str], label: str
) -> list[Node]:
    found = []
    for block in blocks:
        labels = _labels(block, data)
        if (
            _keyword(block, data) == "resource"
            and len(labels) == 2
            and labels[0] in resource_types
            and labels[1] == label
        ):
            found.append(block)
    return found


def _local_call(path: str, block: Node, data: bytes) -> ModuleCall | None:
    labels = _labels(block, data)
    if _keyword(block, data) != "module" or len(labels) != 1:
        return None
    source = _attributes(_body(block), data).get("source")
    literal = None if source is None else _literal_string(_value(source), data)
    if literal is None or not literal.startswith(("./", "../")):
        return None
    try:
        return ModuleCall(path, labels[0], _inside(literal, posixpath.dirname(path)))
    except _Refused:
        return None  # Outside the repository: not code this repository holds.


def _inside(path: str, base: str) -> str:
    """``path`` under ``base``, normalised; refused if it leaves the repository."""
    joined = posixpath.normpath(posixpath.join(base, path.strip("/")))
    if joined == ".." or joined.startswith("../"):
        raise _Refused(Decline.MODULE_EXTERNAL, f"{path!r} is outside this repository.")
    return "" if joined == "." else joined
