from fastapi import APIRouter

from app.core.deps import DbSession, Tenant
from app.models.rule import Rule
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta
from app.schemas.rule import RuleOut
from app.services import findings as findings_service
from app.services import rules as service

router = APIRouter(prefix="/rules", tags=["rules"], responses=ERROR_RESPONSES)


def _serialize(rule: Rule) -> RuleOut:
    return RuleOut(
        rule_id=rule.rule_id,
        name=rule.name,
        description=rule.description,
        category=rule.category,
        provider=rule.provider,
        severity=rule.severity,
        version=rule.version,
        exploitability=rule.exploitability,
        scope=rule.scope,
        applies_to=rule.applies_to,
        enabled=rule.enabled,
        remediation=rule.remediation,
        rationale=rule.rationale,
        estimated_effort_minutes=rule.estimated_effort_minutes,
        # Data-driven framework tagging, straight out of JSONB. No business
        # logic anywhere branches on these values.
        compliance_mappings=rule.compliance_mappings,
        # What "fixed" means for this rule, and the artifacts generated from
        # that one statement: the commands, the Terraform arguments, and -- only
        # where one can genuinely enforce it -- an Azure Policy definition.
        # Read from the registry rather than the mirror because it is code, not
        # a row: a policy stored in the database could outlive the rule that
        # generated it.
        remediation_spec=findings_service.remediation_detail(rule.rule_id),
    )


@router.get("")
async def list_rules(session: DbSession, tenant: Tenant) -> Envelope[list[RuleOut], NoMeta]:
    """Every rule that runs, with what it checks and how to fix a failure."""
    rows = await service.list_rules(session)
    return Envelope(data=[_serialize(r) for r in rows], meta=NoMeta())


@router.get("/{rule_id}")
async def get_rule(rule_id: str, session: DbSession, tenant: Tenant) -> Envelope[RuleOut, NoMeta]:
    """One rule by its id, such as ``AZ-STO-001``."""
    rule = await service.get_rule(session, rule_id)
    return Envelope(data=_serialize(rule), meta=NoMeta())
