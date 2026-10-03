"""Aggregate API router. One place to see the whole surface (API.md section 1)."""

from fastapi import APIRouter

from app.api.routes import (
    assets,
    attack_paths,
    audit_grants,
    audit_log,
    audit_packages,
    auditor,
    changes,
    cloud_accounts,
    cloud_connections,
    compliance,
    context_declarations,
    dashboard,
    events,
    findings,
    notifications,
    organizations,
    remediation,
    reports,
    risks,
    rules,
    scans,
    team,
    webhooks,
)

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(organizations.router)
api_router.include_router(team.router)
api_router.include_router(audit_log.router)
api_router.include_router(audit_packages.router)
api_router.include_router(audit_grants.router)
# An auditor has no organization, so these take no tenant (DECISIONS.md section 211).
api_router.include_router(auditor.router)
api_router.include_router(webhooks.router)
api_router.include_router(cloud_accounts.router)
api_router.include_router(context_declarations.router)
api_router.include_router(cloud_connections.router)
api_router.include_router(scans.router)
api_router.include_router(assets.router)
api_router.include_router(changes.router)
api_router.include_router(notifications.router)
api_router.include_router(attack_paths.router)
api_router.include_router(findings.router)
api_router.include_router(risks.router)
api_router.include_router(remediation.router)
api_router.include_router(rules.router)
api_router.include_router(compliance.router)
api_router.include_router(dashboard.router)
api_router.include_router(reports.router)
# Called by Azure rather than by the app, and guarded by a signed token.
api_router.include_router(events.router)
