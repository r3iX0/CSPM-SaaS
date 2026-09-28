"""Sync the Python rule registry into the ``rules`` read-mirror.

The registry is the source of truth. The table exists so the API and UI can join
rule metadata onto findings without importing rule code, and so a finding can
name a rule that has since changed. Runs at startup with the owner connection —
``authenticated`` deliberately has no write access to this table.
"""

from sqlalchemy import select

from app.core.config import settings
from app.core.db import service_session
from app.core.enums import RuleEngineKind
from app.models.rule import Rule
from app.prowler.rules import compliance_mappings_for
from app.rules.registry import catalogue_rules


async def sync_rules_to_database() -> int:
    async with service_session() as session:
        existing = {
            row.rule_id: row for row in (await session.execute(select(Rule))).scalars().all()
        }

        rules = catalogue_rules()
        for rule in rules:
            values = {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "description": rule.description,
                "category": rule.category,
                "provider": rule.provider.value,
                "severity": rule.severity.value,
                "version": rule.version,
                "exploitability": rule.exploitability,
                "scope": rule.scope.value,
                "applies_to": [t.value for t in rule.applies_to],
                # A Prowler check is live only where the scanner service runs.
                # Mirroring it enabled without one would list controls as
                # "not yet assessed" for ever, waiting on an engine that was
                # never deployed.
                "enabled": (
                    rule.engine is RuleEngineKind.NATIVE or settings.assess_enabled
                ),
                "remediation": rule.remediation,
                "estimated_effort_minutes": rule.estimated_effort_minutes,
                "rationale": rule.rationale,
                # Including, for a native rule, the controls it answers because
                # the Prowler checks it covers do (DECISIONS.md section 150).
                "compliance_mappings": compliance_mappings_for(rule),
                # Mirrored so the compliance view can follow a control back to
                # the readings behind it without importing rule code.
                "requires_evidence": [key.value for key in rule.requires_evidence],
                # Which engine answers it. The Prowler checks are mirrored beside
                # the native rules so a finding, a control and the rules page
                # can name either without importing code (DECISIONS.md
                # section 150).
                "engine": rule.engine.value,
                "engine_version": (
                    rule.version if rule.engine is RuleEngineKind.PROWLER else None
                ),
            }

            row = existing.get(rule.rule_id)
            if row is None:
                session.add(Rule(**values))
            else:
                for key, value in values.items():
                    setattr(row, key, value)

        # A rule deleted from the registry is disabled rather than removed:
        # findings it raised in the past still reference it.
        registry_ids = {r.rule_id for r in rules}
        for rule_id, row in existing.items():
            if rule_id not in registry_ids:
                row.enabled = False

        await session.commit()
        return len(rules)
