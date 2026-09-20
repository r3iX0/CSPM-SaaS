# CloudGuard — Architecture

See `PRODUCT_SPEC.md` for vision/scope. This doc covers the technical shape: stack, repo layout, request flow, multi-tenancy, and roles.

---

## 1. Tech Stack

| Layer | Choice |
| --- | --- |
| Frontend | React, TypeScript, Vite, Tailwind CSS, shadcn/ui, React Router, TanStack Query, Recharts, Motion |
| Backend | Python, FastAPI, Pydantic, SQLAlchemy 2, Alembic, Pytest, Ruff, MyPy |
| Database / Auth | Supabase PostgreSQL + Supabase Auth + PostgreSQL Row-Level Security (a real security boundary, not a frontend convenience) |
| Background jobs | Celery + Redis |
| Cloud | Azure Resource Manager REST, Microsoft Graph REST, Microsoft Entra ID, MSAL for tokens — **not** the `azure-mgmt-*` SDKs, so the raw JSON can be stored verbatim and re-evaluated (`DECISIONS.md` §3) |
| Infra | Docker image built by Railway, GitHub Actions (CI). No local runtime. |
| Testing | Pytest (unit + an `integration` marker needing live PostgreSQL), Vitest. No E2E runner — see `TESTING.md` §5 |
| Monitoring | Sentry now; OpenTelemetry later |
| Reports | Jinja2 + WeasyPrint |
| Architecture style | **Modular monolith + worker.** Explicitly NOT microservices. |

Do not change this stack unless development proves it necessary.

---

## 2. Request / Data Flow

```mermaid
graph TB
    subgraph Client ["Client Tier (Vercel)"]
        UI["React SPA (Vite + TS)"]
    end

    subgraph API_Tier ["API Tier (Railway)"]
        FastAPI["FastAPI Modular Monolith"]
        AuthMid["Auth & RLS Context Middleware"]
        Router["API v1 Routers (/api/v1/*)"]
    end

    subgraph Data_Tier ["Data & Auth Tier (Supabase)"]
        SupaAuth["Supabase Auth (Entra / OAuth)"]
        PG[("PostgreSQL 16")]
        RLS["Row-Level Security (cloudguard_app)"]
    end

    subgraph Worker_Tier ["Async Worker Tier (Railway)"]
        Redis[("Redis 7 (Broker & Leases)")]
        CeleryWorker["Celery Worker Cluster"]
        ScanPlan["Step: PLAN"]
        ScanCollect["Queue: collect (Parallel)"]
        ScanAnalyze["Queue: analyze (Single / Fenced)"]
    end

    subgraph Cloud_Providers ["Cloud Targets (Read-Only)"]
        Azure["Azure ARM & Microsoft Graph REST"]
        AWS["AWS APIs (aiobotocore / SigV4)"]
    end

    UI -->|JWT Auth| SupaAuth
    UI -->|HTTPS REST| FastAPI
    FastAPI --> AuthMid --> Router
    Router -->|RLS-Scoped Query| RLS --> PG
    Router -->|Enqueue Step| Redis
    Redis --> CeleryWorker
    CeleryWorker --> ScanPlan
    ScanPlan -->|Dispatch| ScanCollect
    ScanCollect -->|REST JSON| Azure
    ScanCollect -->|SigV4 JSON| AWS
    ScanCollect -->|Verbatim RawSnapshot| PG
    ScanCollect -->|Advance to| ScanAnalyze
    ScanAnalyze -->|Normalize & Rules| PG
```

### Scan Step Orchestration Sequence

A scan is not one queued task. It is a set of durable steps — `PLAN`, one `COLLECT` per subscription plus one for the tenant directory, then `ANALYZE` — recorded in `scan_steps` and claimed under a lease by whichever worker is free.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant API as FastAPI Router
    participant DB as PostgreSQL (RLS)
    participant Redis as Redis Queue
    participant W_Coll as Celery (Collect Queue)
    participant W_Ana as Celery (Analyze Queue)
    participant Cloud as Cloud Provider (Azure / AWS)

    User->>API: POST /api/v1/scans {connection_id}
    API->>DB: Insert scan (PENDING) & PLAN step
    API->>Redis: Enqueue PLAN task
    Redis->>W_Coll: Claim PLAN step
    W_Coll->>DB: Discover subscriptions beneath connection
    W_Coll->>DB: Create COLLECT steps (per sub + tenant) & ANALYZE step
    W_Coll->>Redis: Dispatch COLLECT tasks

    par Parallel Collection Steps
        Redis->>W_Coll: Claim COLLECT (Subscription A) [Lease + Attempt N]
        W_Coll->>Cloud: Read resources via REST / SigV4
        W_Coll->>DB: Save verbatim RawSnapshot (fenced on attempt N)
    and
        Redis->>W_Coll: Claim COLLECT (Tenant Directory) [Lease + Attempt M]
        W_Coll->>Cloud: Read users, roles, Conditional Access
        W_Coll->>DB: Save verbatim RawSnapshot (fenced on attempt M)
    end

    W_Coll->>Redis: Trigger ANALYZE step once all collections complete
    Redis->>W_Ana: Claim ANALYZE step [Lease + Attempt K]
    W_Ana->>DB: Load RawSnapshots for scan
    W_Ana->>W_Ana: 1. Normalize to CloudResource domain model
    W_Ana->>W_Ana: 2. Evaluate SecurityRule registry (deterministic)
    W_Ana->>W_Ana: 3. Calculate Risk scores (Severity x Criticality x Exposure)
    W_Ana->>W_Ana: 4. Build Attack Path Graph & severance choke points
    W_Ana->>DB: ScanWriter.commit (fenced on lease claim - atomic commit)
    W_Ana->>DB: Transition scan to COMPLETED
    User->>API: GET /api/v1/scans/{id}/detail
    API-->>User: Scan findings, risks, and verified resolutions
```

Collection and analysis go to different queues because they cost opposite
things: collection waits on Azure and wants many in flight, analysis holds a
tenant in memory and wants few. What makes it survivable is that the state lives
in the database rather than in a Python frame: a redeploy costs the step in
flight rather than the scan, one unreadable subscription does not take the other
forty-nine with it, and every write a running step makes is fenced on the claim
it was made under, so a worker that was merely slow cannot settle a step another
worker is running (`services/orchestrator.py`, `DECISIONS.md` §65).

---

## 3. Repository Structure

Monorepo.

```
cloudguard/
|-- apps/
|   |-- web/                      # React + Vite
|   |   `-- src/, package.json, vite.config.ts
|   `-- api/
|       |-- app/
|       |   |-- main.py
|       |   |-- core/            # config, enums, security, logging, dependencies
|       |   |-- api/routes/      # organizations, cloud_accounts, cloud_connections,
|       |   |                     # scans, assets, findings, risks, attack_paths,
|       |   |                     # remediation, compliance, reports, rules,
|       |   |                     # dashboard, changes, events
|       |   |-- models/, schemas/, repositories/, services/
|       |   |-- domain/          # CloudResource -- the evaluation-time view, no DB, no SDK
|       |   |-- connectors/     # base.py, collection.py, planning.py, evidence.py,
|       |   |                     # onboarding.py, registry.py -- all provider-neutral
|       |   |-- connectors/azure/, connectors/aws/
|       |   |-- context/         # asset context: inferred, then overruled by declaration
|       |   |-- graph/           # AssetGraph: attack paths, escalation chains, severance, patterns
|       |   |-- rules/azure/{identity,rbac,network,storage,compute,database,logging,secrets,posture}/
|       |   |-- rules/{base.py, controls.py, registry.py}
|       |   |-- risk/{config.py, scorer.py, grouping.py}
|       |   |-- remediation/     # RemediationSpec: the machine-readable half of a fix
|       |   |-- compliance/, reports/
|       |   `-- workers/{celery_app.py, scan_tasks.py}
|       `-- tests/{unit/, integration/, fixtures/}
|-- database/{migrations/, seed/}
|-- infrastructure/{docker/, supabase/, railway/, azure/, ci/}
|-- docs/
`-- .github/workflows/
```

Three directories are worth naming because they are not obvious from the flow
diagram above. `domain/` holds the cloud-neutral resource a rule actually sees,
which is what lets rules be tested against fixture JSON with no database and no
network. `context/` is where criticality and sensitivity are inferred from tags
and names and then overruled by what a customer declared — the multiplier the
risk engine applies, kept apart from both the connector that read the tags and
the scorer that uses the result. `graph/` is the second question asked of one
scan's normalized state: not "what is wrong" but "what is wrong *together*".

---

## 4. Multi-Tenancy

Every customer is an Organization. Every tenant-owned record carries `organization_id`. The backend derives organization from the authenticated user's membership — **a client-supplied `organization_id` is never trusted.** PostgreSQL RLS independently enforces isolation as a second, database-level boundary, not just an application-layer check. Full schema and RLS policy pattern: `DATABASE.md`.

```mermaid
graph LR
    subgraph Inbound ["1. Inbound Request"]
        JWT["Supabase JWT (Bearer Token)"]
    end

    subgraph App_Tier ["2. Application Boundary (FastAPI)"]
        Verify["Verify JWT Signature (ES256/RS256)"]
        Lookup["Lookup Verified Org Membership"]
        Context["Bind organization_id to rls_session"]
    end

    subgraph DB_Tier ["3. Database Boundary (PostgreSQL)"]
        Role["Connect as cloudguard_app (Non-Owner Role)"]
        SetVar["SET LOCAL app.current_organization_id = ..."]
        Policy["RLS Policy: organization_id = current_setting(...)"]
        Data[("Tenant Tables: assets, findings, risks, scans")]
    end

    JWT --> Verify --> Lookup --> Context
    Context --> SetVar --> Role --> Policy --> Data
```

---

## 5. Roles

MVP permissions kept simple:

| Role | MVP permissions |
| --- | --- |
| OWNER | Everything |
| ADMIN | Everything except deleting the organization |
| SECURITY_ANALYST | Security data: read/write remediation |
| IT_ADMIN | Assets, findings, remediation |
| VIEWER | Read-only |
| ADVISOR | Read + assessment/report capabilities (schema-ready, no dedicated UI in MVP) |

MSP-specific roles are future functionality, not added now.

---

## 6. Cloud Connector Abstraction

Generic interface so AWS/GCP can be added later without reshaping the core. Azure-specific implementation detail (auth, collection pipeline) lives in `AZURE_INTEGRATION.md`.

```python
class CloudConnector(ABC):
    async def validate_connection(self) -> ConnectionCheck: ...
    async def collect(...) -> RawSnapshot: ...          # subscription-scoped
    async def collect_directory(...) -> RawSnapshot: ...  # tenant-scoped

CloudConnector
  `-- AzureConnector          # MVP
      (future: AWSConnector, GCPConnector)
```

Two collection methods rather than one per service. An earlier draft of this
doc listed eight `discover_*` calls — one for identity, one for storage, and so
on — and the shape did not survive contact with evidence tracking: a
subscription whose PostgreSQL listing timed out has read its SQL servers
perfectly well, so what a scan needs to record is which *evidence key* failed,
not which method was called. `collect` returns a `RawSnapshot` carrying the
verbatim JSON plus per-key outcomes, and the rule engine degrades only the rules
whose own evidence is missing (`RULE_ENGINE.md`).

The split between the two is directory versus subscription, because they are
different grants with different consent: tenant-level reads (Entra users, role
assignments, Conditional Access) come from one, resource reads from the other.

The core data model (`CloudResource`, `RawSnapshot`, `NormalizedState`,
`SecurityRule`, `Finding`, `Risk`) stays cloud-neutral; cloud-specific logic
lives under `connectors/`.

---

## 7. Attack Path Graph & Severance Model

The graph engine (`app/graph/`) models asset relationships, exposure reachability, and identity escalation chains to identify the shortest routes from internet entry points to critical assets.

```mermaid
graph TD
    subgraph Entry ["1. Exposure Surface"]
        Internet(("Public Internet"))
        NSG["NSG Rule: 0.0.0.0/0:22 (Public SSH)"]
        VM["Jumpbox VM (Public IP)"]
    end

    subgraph Escalation ["2. Lateral Movement & Escalation"]
        MSI["Managed Service Identity"]
        RoleAssign["Subscription Contributor Assignment"]
    end

    subgraph CrownJewels ["3. Target Assets (Critical Impact)"]
        Vault["Key Vault (Production Secrets)"]
        DB[("Production Customer Database")]
    end

    Internet -->|Reaches| NSG -->|Guards| VM
    VM -->|Uses Identity| MSI -->|Grants Role| RoleAssign
    RoleAssign -->|Controls| Vault
    RoleAssign -->|Controls| DB

    classDef choke fill:#b91c1c,stroke:#f87171,stroke-width:2px,color:#fff;
    class NSG,MSI choke;
```

- **Severance Analysis (`severance.py`)**: Computes which single relationship cuts (choke points, shown in red above) sever the greatest number of viable attack routes. Remediating a single choke point eliminates entire attack trees.
- **Evidence-backed hops (`facts.py`)**: A hop's evidence (the role, network rule, or identity type) is read dynamically from the assets rather than stamped statically on edges.
