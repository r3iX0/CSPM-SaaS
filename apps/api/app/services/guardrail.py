"""The pull-request guardrail: a plan judged by the rules' hints, reported on GitHub (§234).

A pull request job runs ``tools/iac/github/cleave-guardrail.sh`` after
``terraform plan``. The script asks for the allowlist, keeps only those
arguments of each azurerm resource the plan creates or updates, and posts them
with the job's own GitHub Actions token. The token's ref names the pull request
(``refs/pull/<n>/merge``); the repository must be covered by an installation an
organization linked, as for the state index (§231).

The plan is judged in memory (``remediation.iac.guardrail``) and the answer goes
back two ways: in the response, so the job can fail, and as a check run on the
pull request's head commit, through the App. Nothing is stored: the check run
is the record, on the pull request it judged.
"""

import re
from collections.abc import Sequence
from functools import lru_cache

from app.core.config import settings
from app.core.errors import CodeHostError, PermissionDenied, ValidationFailed
from app.core.logging import get_logger
from app.integrations import github
from app.integrations.github_oidc import ActionsIdentity
from app.remediation.iac.guardrail import (
    GuardedRule,
    InvalidPlan,
    Judged,
    Verdict,
    allowlist,
    conclusion,
    judge,
    resources_from_upload,
)
from app.remediation.iac.terraform import Declined
from app.rules.registry import enabled_rules
from app.schemas.code_integration import (
    GuardrailAllowlistOut,
    GuardrailOut,
    GuardrailPlanIn,
    GuardrailVerdictOut,
)
from app.services.code_integrations import linked_repository, require_offered, working_directory_in
from app.services.iac import rule_checks

log = get_logger(__name__)

_PULL_REQUEST_REF = re.compile(r"^refs/pull/(\d+)/merge$")
#: Rows per section of a check run's summary; the rest are counted.
MAX_ROWS = 50


@lru_cache
def guarded_rules() -> tuple[GuardedRule, ...]:
    """Every enabled rule with a Terraform argument to judge, in rule order.

    A hint that would replace the resource is judged too: new code should set
    it, even though Cleave never edits existing code to (§228).
    """
    guarded = []
    for rule in enabled_rules():
        checks = rule_checks(rule)
        if not isinstance(checks, Declined):
            guarded.append(GuardedRule(rule.rule_id, rule.name, str(rule.severity), checks))
    return tuple(guarded)


def attributes() -> GuardrailAllowlistOut:
    """What the Action may send: the same list for everyone, and no secret."""
    require_offered()
    return GuardrailAllowlistOut(attributes=allowlist(guarded_rules()))


async def take_plan(identity: ActionsIdentity, payload: GuardrailPlanIn) -> GuardrailOut:
    """Judge a pull request's plan and report it on the pull request."""
    require_offered()
    ref = _PULL_REQUEST_REF.match(identity.ref)
    if ref is None:
        raise PermissionDenied(f"Only a pull request's plan is judged, not {identity.ref}")
    number = int(ref.group(1))
    rules = guarded_rules()
    try:
        resources = resources_from_upload(
            [resource.model_dump() for resource in payload.resources], allowlist(rules)
        )
    except InvalidPlan as exc:
        raise ValidationFailed(str(exc)) from exc
    working_directory = working_directory_in(payload.working_directory)

    linked = await linked_repository(identity)
    full_name = linked.repository.full_name
    token = await github.installation_token(linked.installation_id)
    head_sha = await github.pull_request_head(full_name, number, token)
    if head_sha is None:
        raise ValidationFailed(f"Pull request #{number} is not open")

    judged = judge(resources, rules)
    concluded = conclusion(judged)
    name = f"Cleave guardrail: {working_directory or 'root'} ({payload.workspace})"
    check_run_url: str | None = None
    check_run_detail: str | None = None
    try:
        check_run_url = await github.create_check_run(
            full_name,
            token=token,
            head_sha=head_sha,
            name=name,
            conclusion=concluded,
            title=_title(judged),
            summary=check_summary(judged, rules),
            details_url=settings.app_url or None,
        )
    except CodeHostError as exc:
        # Usually an installation that has not accepted ``checks: write``. The
        # job still gets the verdicts, and fails on them.
        check_run_detail = str(exc)
    log.info(
        "guardrail.judged",
        organization_id=str(linked.organization_id),
        repository=full_name,
        pull_request=number,
        resources=len(resources),
        introduced=sum(item.introduced for item in judged),
        unknown=sum(item.verdict is Verdict.UNKNOWN for item in judged),
        conclusion=concluded,
        check_run=check_run_url is not None,
    )
    return GuardrailOut(
        repository=full_name,
        pull_request=number,
        head_sha=head_sha,
        conclusion=concluded,
        check_run_url=check_run_url,
        check_run_detail=check_run_detail,
        verdicts=[
            GuardrailVerdictOut(
                rule_id=item.rule_id,
                address=item.address,
                verdict=item.verdict.value,
                introduced=item.introduced,
                attribute=item.attribute,
                planned=item.planned,
                expected=item.expected,
            )
            for item in judged
        ],
    )


def _title(judged: Sequence[Judged]) -> str:
    introduced = sum(item.introduced for item in judged)
    if introduced:
        return f"{introduced} misconfiguration{'s' if introduced != 1 else ''} this change brings"
    return "No misconfiguration this change brings"


def check_summary(judged: Sequence[Judged], rules: Sequence[GuardedRule]) -> str:
    """The check run's report: what this change brings, what it leaves failing, what is unknown."""
    by_id = {rule.rule_id: rule for rule in rules}
    introduced = [item for item in judged if item.introduced]
    still = [item for item in judged if item.verdict is Verdict.FAIL and not item.introduced]
    unknown = [item for item in judged if item.verdict is Verdict.UNKNOWN]
    passed = sum(item.verdict is Verdict.PASS for item in judged)
    lines = [
        f"Cleave judged {len(judged)} rule checks over the resources this plan creates or "
        f"changes: {len(introduced)} brought by this change, {len(still)} already failing, "
        f"{len(unknown)} unknown until apply, {passed} passing.",
        "",
    ]
    for heading, items in (
        ("Brought by this change", introduced),
        ("Already failing, and not fixed by this change", still),
    ):
        if not items:
            continue
        lines += [f"### {heading}", "", "| Rule | Severity | Resource | Planned | Expected |"]
        lines += ["|---|---|---|---|---|"]
        for item in items[:MAX_ROWS]:
            rule = by_id.get(item.rule_id)
            lines.append(
                f"| {item.rule_id} {_cell(rule.name if rule else '')} "
                f"| {rule.severity if rule else ''} | `{item.address}` "
                f"| `{item.attribute} = {_cell(item.planned or 'null')}` "
                f"| `{_cell(item.expected)}` |"
            )
        if len(items) > MAX_ROWS:
            lines.append(f"\nAnd {len(items) - MAX_ROWS} more.")
        lines.append("")
    if unknown:
        lines += [
            "### Unknown until apply",
            "",
            "The plan does not say these values, so they are neither passed nor failed. "
            "The next scan judges what is deployed.",
            "",
        ]
        lines += [f"- {item.rule_id} on `{item.address}`" for item in unknown[:MAX_ROWS]]
        if len(unknown) > MAX_ROWS:
            lines.append(f"- And {len(unknown) - MAX_ROWS} more.")
        lines.append("")
    lines.append(
        "Only rules with a Terraform argument are judged here, against planned values. "
        "Cleave's scans still judge every rule against what is deployed."
    )
    return "\n".join(lines)


def _cell(text: str) -> str:
    """A value safe inside a Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ")
