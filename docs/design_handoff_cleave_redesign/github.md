repo: r3iX0/CSPM-SaaS
branch: main
path: apps/web/src

## Last sync

date: 2026-09-26T11:49:38Z

### Updated in this project

- Attack paths rebuilt as one frame: the drawing plus a side panel with Routes and Simulate tabs, the repeated-route group, a route navigator walked hop by hop, and a multi-change plan checked as a whole.
- Choke-point card removed from Attack paths; its suggestions now start the Simulate tab. The cut still collapses routes in sequence once the plan's answer lands.
- Overview: Priority risks rows gained a graph link (trace the route or open the asset); the link-to-cut panel now opens the simulation with that cut already in the plan.
- Remediation rows say when the asset sits on an attack path.

## Screen map

| Screen (in Cleave.dc.html) | Built from |
| --- | --- |
| Shell, sidebar, header | components/Shell.tsx, components/layout/Sidebar.tsx, components/layout/nav.ts, components/Brand.tsx, index.css |
| Overview | pages/Dashboard.tsx, dashboard/PostureHeader.tsx, dashboard/ScorePanel.tsx, dashboard/SeverityStrip.tsx, dashboard/PriorityRisks.tsx, dashboard/AttackPathPanel.tsx, dashboard/CoveragePanel.tsx, graph/GraphLink.tsx |
| Findings | pages/Findings.tsx, security/SeverityBadge.tsx, security/StatusPill.tsx, common/states.tsx |
| Finding detail + verified close | pages/FindingDetail.tsx, security/FixVerification.tsx, graph/AttackPathRoute.tsx |
| Risks | pages/Risks.tsx, security/ScoreTile.tsx |
| Risk detail | pages/RiskDetail.tsx |
| Attack paths (the cut) | pages/AttackPaths.tsx, graph/RouteMapCanvas.tsx, graph/RouteRows.tsx, graph/RouteNavigator.tsx, graph/SimulationPanel.tsx, graph/GraphLegend.tsx, graph/routeOrder.ts, i18n/en.ts |
| Assets | pages/Assets.tsx |
| Compliance | pages/Compliance.tsx, pages/ComplianceFramework.tsx |
| Remediation | pages/Remediation.tsx, common/StatStrip.tsx |
| Scans | pages/Scans.tsx |
| Rules | pages/Rules.tsx |
| Cloud connections | pages/Connect.tsx, README.md |
| Connection setup wizard | pages/ConnectionSetup.tsx |
| Settings | pages/Settings.tsx |
| Reports | pages/Reports.tsx |
| Changes | pages/Changes.tsx |
| Sign in | pages/SignIn.tsx |
| First run | pages/Onboarding.tsx |
| Tokens (light + dark, severity scale) | apps/web/src/index.css, lib/format.ts |

## Sync history

### 2026-09-21T16:45:00Z

- Rebuilt the whole product UI as one Design Component, `Cleave.dc.html`.
- Renamed CloudGuard to Cleave and set a deep-teal brand accent on `--primary`, severity scale untouched.
- Added the two signature moments: the cut (routes collapse in sequence) and the verified close (a finding resolving itself with an evidence hash).
- Swept the copy against the brand voice rules — no "secure" as a state, no verdict dressed as a pass.
