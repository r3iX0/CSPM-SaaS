"""A finding's fix as a diff of the customer's own Terraform (DECISIONS.md §166).

The seam between the rules and the edit engine: which arguments a rule asks
for, on which resource types, and the answer the API gives. Nothing here is
stored and nothing is sent anywhere -- the file comes in with the request and
the diff goes back in the response.

Synchronous and CPU-bound: the route runs it in a worker thread, never on the
loop (§158).
"""

from app.core.enums import Provider
from app.remediation import terraform_hints
from app.remediation.iac import Change, Decline, Declined, edit_terraform
from app.remediation.iac.terraform import CHECKED_RELEASES, MAX_BYTES
from app.rules.base import SecurityRule
from app.schemas.finding import IacDiffOut, IacEditOut


def upload_filename(given: str | None) -> str:
    """The name an upload is shown under in the diff header: a plain file name.

    A browser may send a path, and a crafted request anything at all; the diff
    names only the last component, without control characters.
    """
    last = (given or "").replace("\\", "/").rsplit("/", 1)[-1]
    kept = "".join(ch for ch in last if ch.isprintable())[:255]
    return kept if kept.strip(". ") else "main.tf"


def propose_terraform_fix(
    rule: SecurityRule | None,
    resource_name: str | None,
    *,
    filename: str,
    source: str | bytes,
    lockfile: str | bytes | None = None,
    sole_block: bool = False,
) -> IacDiffOut:
    """Edit ``source`` so the asset named ``resource_name`` meets ``rule``.

    Bytes are an upload and must be UTF-8, which is what Terraform reads. A
    file in another encoding is declined rather than decoded with replacements:
    the diff would carry the replacements back into the customer's file.

    ``sole_block`` only where a person chose the file for this finding: an
    upload, never a repository CloudGuard searched (DECISIONS.md §166).
    """
    if any(isinstance(part, bytes) and len(part) > MAX_BYTES for part in (source, lockfile)):
        return _declined(filename, Decline.TOO_LARGE, f"The file is over {MAX_BYTES // 1024} KiB.")
    try:
        text = source.decode() if isinstance(source, bytes) else source
        lock = lockfile.decode() if isinstance(lockfile, bytes) else lockfile
    except UnicodeDecodeError:
        return _declined(filename, Decline.PARSE_ERROR, "The file is not UTF-8 text.")

    spec = rule.remediation_spec if rule is not None else None
    hints = terraform_hints(spec) if spec is not None else []
    if (
        # AWS attributes are unverified until AWS is (docs/AWS_INTEGRATION.md).
        rule is None
        or rule.provider != Provider.AZURE
        or spec is None
        or not spec.terraform_resource_types
        or not hints
    ):
        return _declined(
            filename, Decline.NOT_EDITABLE, "This rule has no Terraform argument to set."
        )
    if resource_name is None:
        return _declined(
            filename, Decline.NOT_EDITABLE, "This finding is not about one resource in code."
        )

    result = edit_terraform(
        text,
        resource_types=spec.terraform_resource_types,
        name=resource_name,
        changes=[Change(hint["attribute"], hint["value"]) for hint in hints],
        lockfile=lock,
        sole_block=sole_block,
    )
    if isinstance(result, Declined):
        return _declined(filename, result.reason, result.detail)
    return IacDiffOut(
        filename=filename,
        outcome="patched",
        diff=result.diff(filename),
        edits=[
            IacEditOut(attribute=e.attribute, before=e.before, after=e.after, line=e.line)
            for e in result.edits
        ],
        decline_reason=None,
        detail=None,
        provider_version=result.provider_version,
        checked_against=list(CHECKED_RELEASES),
        matched_by=result.matched_by,
    )


def _declined(filename: str, reason: Decline, detail: str) -> IacDiffOut:
    return IacDiffOut(
        filename=filename,
        outcome="declined",
        diff=None,
        edits=[],
        decline_reason=reason.value,
        detail=detail,
        provider_version=None,
        checked_against=list(CHECKED_RELEASES),
    )
