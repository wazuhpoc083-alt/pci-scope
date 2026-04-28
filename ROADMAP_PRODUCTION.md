# PCI DSS Scoping Tool — Production Readiness Roadmap

> Version: 0.1.0 → 1.0.0  
> Last updated: 2026-04-28  
> Standard: OpenSpec / Markdown

This document describes every engineering workstream required to take the PCI DSS Scoping Tool from its current MVP state to a production-grade, secure, observable, and maintainable system. Items are grouped into phases. Each phase can be executed in parallel across tracks within the phase but must be completed before the next phase begins.

---

## Table of Contents

1. [Current State Assessment](#1-current-state-assessment)
2. [Phase 1 — Security Hardening (Weeks 1–3)](#2-phase-1--security-hardening-weeks-13)
3. [Phase 2 — Reliability & Observability (Weeks 4–6)](#3-phase-2--reliability--observability-weeks-46)
4. [Phase 3 — Testing & CI/CD (Weeks 6–9)](#4-phase-3--testing--cicd-weeks-69)
5. [Phase 4 — Performance & Scalability (Weeks 9–12)](#5-phase-4--performance--scalability-weeks-912)
6. [Phase 5 — Operational Readiness (Weeks 12–14)](#6-phase-5--operational-readiness-weeks-1214)
7. [Phase 6 — Compliance & Audit (Weeks 14–16)](#7-phase-6--compliance--audit-weeks-1416)
8. [Non-Functional Requirements Summary](#8-non-functional-requirements-summary)
9. [Dependency Map](#9-dependency-map)
10. [Definition of Done](#10-definition-of-done)

---

## 1. Current State Assessment

### What exists

| Capability | Status |
|------------|--------|
| FastAPI REST backend | Functional MVP |
| PostgreSQL schema + Alembic migrations | Done |
| Multi-tenant auth (static admin token + tenant JWT) | Functional, needs hardening |
| Asset CRUD + CSV import | Done |
| Firewall config parsing (4 vendors) | Done |
| BFS scope engine | Done |
| PCI DSS v4.0 gap analysis (10 checks) | Done |
| PDF + CSV report export | Done |
| React SPA frontend | Done |
| Render (backend) + Vercel (frontend) deployment | Done |
| Unit tests (gap engine) | Partial |

### Critical gaps before production

| Gap | Risk | Phase |
|-----|------|-------|
| Admin token is a static string with no rotation mechanism | Critical | 1 |
| No rate limiting on any endpoint | Critical | 1 |
| No audit log of who accessed/modified what | Critical | 6 |
| No integration tests or E2E tests | High | 3 |
| No CI/CD pipeline | High | 3 |
| No structured logging or tracing | High | 2 |
| No health checks beyond `/health` (no DB check) | High | 2 |
| File uploads stored only as raw text in DB — no size/type enforcement beyond 10 MB | High | 1 |
| Token stored only in React memory — lost on refresh | Medium | 1 |
| No password/credential management for admin | Medium | 1 |
| No database connection pool configuration | Medium | 4 |
| No request ID propagation | Medium | 2 |
| CORS origins hard-coded in source | Medium | 2 |
| No secrets rotation workflow | Medium | 6 |

---

## 2. Phase 1 — Security Hardening (Weeks 1–3)

> **Goal:** Eliminate every critical and high security risk before any production traffic.

### 2.1 Authentication overhaul

**Problem:** The admin token is a static string stored in an env var with no expiry, no rotation mechanism, and no MFA.

**Solution:**

1. **Introduce admin JWT issuance.** Add a `POST /api/auth/admin/login` endpoint (not the current static bypass). The endpoint accepts `{ "password": string }`, validates it against a bcrypt hash stored in env/secrets, and returns a short-lived admin JWT (e.g. 4h) signed with `SECRET_KEY`.

2. **Deprecate static `ADMIN_TOKEN`.** Support it for a transition period behind a feature flag (`ALLOW_STATIC_ADMIN_TOKEN=false` in production). Remove entirely in v1.1.

3. **Refresh tokens.** Issue opaque refresh tokens (stored hashed in DB) alongside access JWTs. Add `POST /api/auth/refresh` endpoint. Access token TTL: 15 minutes. Refresh token TTL: 7 days.

4. **Frontend token persistence.** Store refresh token in an `httpOnly; Secure; SameSite=Strict` cookie. Store access token in memory only (not localStorage). Implement silent refresh before expiry.

**Implementation files:**
- `backend/app/auth.py` — add admin login logic
- `backend/app/routers/auth.py` — new `/admin/login` and `/refresh` routes
- `backend/app/models.py` — add `RefreshToken` table
- `frontend/src/AuthContext.tsx` — silent refresh logic
- `frontend/src/api.ts` — 401 interceptor triggers refresh

**Acceptance criteria:**
- [ ] Admin can authenticate via password, receives JWT with 4h TTL
- [ ] Tenant JWTs expire at 15 min; silent refresh succeeds transparently
- [ ] `ADMIN_TOKEN` env var rejected in production mode (`ALLOW_STATIC_ADMIN_TOKEN=false`)
- [ ] Refresh tokens are single-use (rotated on every refresh)

---

### 2.2 Rate limiting

**Problem:** All endpoints are unprotected against brute force and DoS.

**Solution:** Add `slowapi` middleware (backed by Redis in production, in-memory for dev).

**Rate limit tiers:**

| Endpoint group | Limit | Window |
|----------------|-------|--------|
| `POST /api/auth/admin/login` | 5 req | 1 min per IP |
| `POST /api/auth/tokens` | 20 req | 1 min per admin |
| `POST /api/auth/refresh` | 10 req | 1 min per IP |
| `POST /api/assessments/*/firewall/upload` | 10 req | 1 min per tenant |
| `POST /api/assessments/*/firewall/analyze` | 20 req | 1 min per tenant |
| All other endpoints | 300 req | 1 min per tenant |

**Implementation:**
```
pip install slowapi redis
```

Add `RateLimiter` to `app/main.py`. Use Redis as backing store via `REDIS_URL` env var. Fall back to in-memory if `REDIS_URL` is not set (dev only).

**Acceptance criteria:**
- [ ] Login endpoint returns `429` after 5 failed attempts in 1 min from same IP
- [ ] Rate limit headers (`X-RateLimit-*`) present on all responses
- [ ] Redis-backed limiter configured on Render

---

### 2.3 Input validation & file upload hardening

**Problem:** File uploads validate only size (10 MB) and text decodability. No MIME-type check, no content scanning.

**Solution:**

1. **MIME validation.** Use `python-magic` to verify uploaded files are plain text before any parser runs. Reject binary, PDF, ZIP etc.

2. **Filename sanitisation.** Strip path separators and null bytes from uploaded filenames before storing.

3. **Upload size limit in NGINX/Render.** Configure `client_max_body_size 10m` at the proxy layer — do not rely solely on application-level checks.

4. **CSV import hardening.** Add row-count limit (max 5,000 rows per import). Sanitise all string fields to strip control characters.

5. **Request body size limit.** Add `ContentSizeLimitMiddleware` to FastAPI app for JSON endpoints (max 1 MB).

**Implementation files:**
- `backend/app/routers/firewall.py` — MIME check before parse
- `backend/app/routers/assets.py` — row count + sanitisation
- `backend/app/main.py` — body size middleware

**Acceptance criteria:**
- [ ] Uploading a PDF returns `415 Unsupported Media Type`
- [ ] CSV import of 5,001 rows returns `422` with clear message
- [ ] Path traversal in filename (`../../etc/passwd`) is neutralised

---

### 2.4 Secret management

**Problem:** Secrets (`SECRET_KEY`, `ADMIN_TOKEN`, `DATABASE_URL`) live in environment variables with no rotation workflow.

**Solution:**

1. **Render secret groups.** Move all secrets to a Render Secret Group (not env vars in `render.yaml`). `render.yaml` references secret group by name only.

2. **Secret rotation runbook.** Document the procedure:
   - Generate new `SECRET_KEY`
   - Update Render secret group
   - Trigger deploy (all existing JWTs are invalidated — users re-login)
   - Invalidate all refresh tokens in DB (`DELETE FROM refresh_tokens`)

3. **Never commit secrets.** Add pre-commit hook that scans for common secret patterns (use `detect-secrets`).

**Acceptance criteria:**
- [ ] `render.yaml` contains no secret values
- [ ] `detect-secrets` pre-commit hook installed
- [ ] Rotation runbook documented in `docs/secret-rotation.md`

---

### 2.5 HTTPS & security headers

**Problem:** No security headers configured beyond CORS.

**Solution:** Add `secure-headers` middleware to FastAPI:

```python
from secure import Secure
secure_headers = Secure()

@app.middleware("http")
async def set_secure_headers(request, call_next):
    response = await call_next(request)
    secure_headers.framework.fastapi(response)
    return response
```

Headers to enforce:

| Header | Value |
|--------|-------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'` |
| `Referrer-Policy` | `no-referrer` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |

**Frontend (Vercel):** Add security headers in `vercel.json` under `"headers"`.

**Acceptance criteria:**
- [ ] `securityheaders.com` scan returns grade A or above
- [ ] No `X-Powered-By` header leaks framework version

---

## 3. Phase 2 — Reliability & Observability (Weeks 4–6)

> **Goal:** Know what the system is doing, catch problems before users do, and recover gracefully.

### 3.1 Structured logging

**Problem:** No structured logging. Uvicorn access logs only.

**Solution:** Replace `print` statements with `structlog` for JSON-structured logs.

```python
import structlog

log = structlog.get_logger()

log.info("firewall.upload", assessment_id=assessment_id, vendor=vendor, rule_count=rule_count)
log.warning("gap_engine.no_cde_seeds", assessment_id=assessment_id)
log.error("db.query_failed", error=str(exc), tenant_id=claims.tenant_id)
```

**Log fields (standard on every log line):**

| Field | Source |
|-------|--------|
| `timestamp` | UTC ISO 8601 |
| `level` | info/warning/error |
| `request_id` | UUID injected by middleware |
| `tenant_id` | from `TokenClaims` |
| `path` | request URL |
| `method` | HTTP verb |
| `status_code` | response status |
| `duration_ms` | request duration |

**Implementation:**
- `backend/app/middleware/logging.py` — request ID injection + timing
- `backend/app/main.py` — mount middleware
- Replace all `print()` calls in routers and engines

**Acceptance criteria:**
- [ ] Every request produces a structured JSON log line with `request_id`
- [ ] Errors include stack trace in `error.stack` field (never in HTTP response body)
- [ ] Logs ship to Render log drain (Datadog / Papertrail / etc.)

---

### 3.2 Deep health check

**Problem:** `GET /health` returns `{"status": "ok"}` with no DB or dependency check.

**Solution:**

```
GET /health
{
  "status": "ok" | "degraded" | "down",
  "checks": {
    "database": {"status": "ok", "latency_ms": 3},
    "migrations": {"status": "ok", "head": "004_add_tenants"}
  },
  "version": "0.1.0"
}
```

- `database`: run `SELECT 1` and measure latency; fail if > 2s
- `migrations`: compare Alembic current revision against `head`; `degraded` if behind
- Returns `200` for `ok`/`degraded`, `503` for `down`

Add a `/readiness` endpoint (same checks, used by Render) and `/liveness` (process-level only, returns `200` immediately).

**Acceptance criteria:**
- [ ] Render health check path set to `/readiness`
- [ ] Prometheus scrape at `/metrics` (via `prometheus-fastapi-instrumentator`)
- [ ] DB failure returns `503` within 3 seconds

---

### 3.3 Error tracking

**Problem:** Unhandled exceptions produce a generic 500 with no alerting.

**Solution:** Integrate **Sentry** SDK.

```python
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration

sentry_sdk.init(
    dsn=settings.sentry_dsn,
    integrations=[FastApiIntegration(), SqlalchemyIntegration()],
    traces_sample_rate=0.1,
    environment=settings.environment,  # "production" | "staging"
)
```

- Add `SENTRY_DSN` and `ENVIRONMENT` env vars.
- Strip PII (tenant names, IP addresses) from Sentry payloads using `before_send` hook.
- Configure alerts: any `error` or `fatal` event → PagerDuty/Slack.

**Acceptance criteria:**
- [ ] Unhandled 500s appear in Sentry within 30 seconds
- [ ] No PII fields in Sentry payloads
- [ ] Sentry performance traces capture DB query durations

---

### 3.4 Database resilience

**Problem:** SQLAlchemy uses default connection pool settings; no retry logic; migrations run synchronously on every startup.

**Solution:**

1. **Connection pool tuning:**
```python
engine = create_engine(
    settings.database_url,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,          # validates connections before use
    pool_recycle=1800,           # recycle connections older than 30 min
    connect_args={"connect_timeout": 10},
)
```

2. **Migration guard.** Run Alembic migrations as a separate pre-deploy step (not on every startup). Keep the startup lifespan guard as a safety net only. Add a startup check that aborts with a clear error if migrations are behind `head` in production mode.

3. **Retry on transient errors.** Wrap DB session calls in `tenacity` retry decorator for `OperationalError` (connection reset, timeout):
```python
@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=0.1, max=2))
def _execute_with_retry(session, stmt): ...
```

**Acceptance criteria:**
- [ ] App recovers transparently when Postgres restarts (within pool_pre_ping cycle)
- [ ] Connection pool metrics exported to Prometheus
- [ ] Migration drift detected at startup → service refuses to start in production

---

### 3.5 Graceful shutdown

**Problem:** Uvicorn receives `SIGTERM` and kills in-flight requests immediately.

**Solution:**

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    _check_migrations()          # assert DB is at head
    yield
    # graceful drain: wait for in-flight requests (Uvicorn handles via --timeout-graceful-shutdown)
```

Add `--timeout-graceful-shutdown 30` to the `startCommand` in `render.yaml`.

**Acceptance criteria:**
- [ ] Zero-downgrade deployments: in-flight requests complete before old process exits
- [ ] Health check returns `503` during shutdown so Render stops routing traffic immediately

---

## 4. Phase 3 — Testing & CI/CD (Weeks 6–9)

> **Goal:** Every commit is verified automatically; regressions are caught before merge.

### 4.1 Integration test suite

**Problem:** Only unit tests exist for the gap engine. No API-level or DB-level tests.

**Solution:** Build an integration test suite using `pytest` + `httpx.AsyncClient` + a real PostgreSQL instance (Docker Compose in CI).

**Test coverage targets:**

| Area | Coverage target |
|------|----------------|
| Auth endpoints | 100% |
| Assessment CRUD | 100% |
| Asset CRUD + bulk + CSV | 90% |
| Report generation | 80% |
| Firewall upload + parse (all 4 vendors) | 90% |
| Scope engine (happy path + edge cases) | 95% |
| Gap engine (all 10 checks) | 100% |
| Multi-tenancy isolation (cross-tenant access denied) | 100% |

**Test fixtures:**
```python
@pytest.fixture
async def client(db_session):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

@pytest.fixture
def admin_headers():
    return {"Authorization": f"Bearer {settings.admin_token}"}

@pytest.fixture
async def tenant_headers(client, admin_headers):
    tenant = await client.post("/api/auth/tenants", ...)
    token = await client.post("/api/auth/tokens", ...)
    return {"Authorization": f"Bearer {token.json()['token']}"}
```

**Multi-tenancy isolation tests (required):**
- Tenant A cannot `GET` assessments belonging to Tenant B
- Tenant A cannot `DELETE` assets from Tenant B's assessment
- Admin can access all tenants' data

**Parser regression tests:**
- Store sample config files for each vendor under `backend/tests/fixtures/`
- Assert exact rule count, specific rule fields, interface mappings

**Acceptance criteria:**
- [ ] `pytest --cov=app --cov-report=term-missing` reports ≥ 85% line coverage
- [ ] All 10 gap checks have at least one positive (finding triggered) and one negative (no finding) test
- [ ] Cross-tenant isolation tests all pass

---

### 4.2 Frontend component tests

**Problem:** No frontend tests.

**Solution:** Vitest + React Testing Library for component-level tests; Playwright for E2E.

**Component tests (Vitest):**
- `LoginPage` — renders, token submission, error display
- `AssessmentsPage` — list renders, create modal, delete confirmation
- `FirewallAnalysis` — step transitions, API mock responses
- `GapFindings` — severity badge rendering, affected rules list

**E2E tests (Playwright):**
```
tests/e2e/
├── auth.spec.ts          ← login, logout, expired token redirect
├── assessments.spec.ts   ← create, view, delete assessment
├── assets.spec.ts        ← add asset, CSV import
├── firewall.spec.ts      ← upload → analyze → answer questions → view findings
└── admin.spec.ts         ← tenant creation, token issuance
```

**Acceptance criteria:**
- [ ] Vitest coverage ≥ 70% on component files
- [ ] Playwright E2E tests pass against staging environment on every PR

---

### 4.3 CI/CD pipeline

**Problem:** No automated build, test, or deployment pipeline.

**Solution:** GitHub Actions.

**`backend.yml` (runs on every PR + push to `main`):**
```yaml
jobs:
  lint:
    - ruff check backend/
    - mypy backend/app --strict

  test:
    services:
      postgres: { image: postgres:15 }
    steps:
      - pytest backend/tests/ --cov=app --cov-fail-under=85

  security-scan:
    - bandit -r backend/app
    - pip-audit --requirement backend/requirements.txt

  build:
    - docker build -t pci-scope-api ./backend
```

**`frontend.yml`:**
```yaml
jobs:
  lint:
    - npm run lint
    - tsc --noEmit

  test:
    - npm run test -- --coverage

  build:
    - npm run build
```

**`deploy.yml` (on push to `main` only):**
```yaml
jobs:
  deploy-backend:
    - render deploy --service pci-scope-api

  deploy-frontend:
    - vercel deploy --prod
```

**`e2e.yml` (after deploy, on staging only):**
```yaml
jobs:
  e2e:
    - playwright test --project=chromium
```

**Branch protection rules:**
- Require all status checks to pass before merge
- Require at least 1 approval
- Require linear history (no merge commits)

**Acceptance criteria:**
- [ ] Every PR triggers lint + test + security scan automatically
- [ ] `main` branch deploys to staging automatically after tests pass
- [ ] Production deploy requires manual approval in GitHub Actions
- [ ] Failed deploy triggers rollback via Render API

---

### 4.4 Static analysis & dependency scanning

| Tool | Purpose | Run frequency |
|------|---------|---------------|
| `ruff` | Python linting + formatting | Every commit (pre-commit + CI) |
| `mypy --strict` | Python type checking | Every PR |
| `bandit` | Python SAST (security antipatterns) | Every PR |
| `pip-audit` | Python CVE scanning | Daily scheduled job |
| `eslint` | TypeScript linting | Every commit |
| `tsc --noEmit` | TypeScript type checking | Every PR |
| `npm audit` | Node CVE scanning | Daily scheduled job |
| `trivy` | Docker image scanning | On every image build |
| `detect-secrets` | Secret scanning in diffs | Pre-commit hook |

**Acceptance criteria:**
- [ ] Zero `bandit` high/critical findings in `app/`
- [ ] Zero known critical CVEs in `pip-audit` / `npm audit`
- [ ] `mypy --strict` passes with zero errors

---

## 5. Phase 4 — Performance & Scalability (Weeks 9–12)

> **Goal:** System handles 100 concurrent tenants with sub-200ms P95 response times on all read endpoints.

### 5.1 Database indexing

**Problem:** No explicit indexes beyond primary keys. Full table scans on tenant-filtered queries at scale.

**Migration to add (Alembic `005_add_indexes.py`):**

```python
op.create_index("ix_assessments_tenant_id", "assessments", ["tenant_id"])
op.create_index("ix_assessments_tenant_created", "assessments", ["tenant_id", "created_at"])
op.create_index("ix_assets_assessment_id", "assets", ["assessment_id"])
op.create_index("ix_scope_reports_assessment_id", "scope_reports", ["assessment_id", "generated_at"])
op.create_index("ix_firewall_uploads_assessment_id", "firewall_uploads", ["assessment_id"])
op.create_index("ix_firewall_rules_upload_id", "firewall_rules", ["upload_id"])
op.create_index("ix_firewall_analyses_assessment_id", "firewall_scope_analyses", ["assessment_id"])
op.create_index("ix_tenants_slug", "tenants", ["slug"], unique=True)
```

**Acceptance criteria:**
- [ ] `EXPLAIN ANALYZE` on common queries shows index scan, not sequential scan
- [ ] P95 latency for `GET /api/assessments/` with 10,000 assessments < 50ms

---

### 5.2 Async SQLAlchemy

**Problem:** Current SQLAlchemy sessions are synchronous (blocking the event loop).

**Solution:** Migrate to async SQLAlchemy engine + `asyncpg` driver.

```python
# database.py
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession

engine = create_async_engine(
    settings.database_url.replace("postgresql://", "postgresql+asyncpg://"),
    pool_size=20,
    max_overflow=30,
)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)
```

Update all router handlers to `async def` and use `async with AsyncSessionLocal() as session`.

**Note:** Alembic migrations must remain synchronous (use a separate sync engine for `env.py`).

**Acceptance criteria:**
- [ ] Uvicorn can handle 200 concurrent requests without thread exhaustion
- [ ] No blocking DB calls in the event loop (verified via `asyncio-debug` mode)

---

### 5.3 Background task processing

**Problem:** Firewall analysis (scope engine + gap engine + BFS over large rule sets) runs synchronously in the request handler. A config with 10,000 rules will time out.

**Solution:** Offload `POST /firewall/analyze` to a background worker via **Celery + Redis**.

**Architecture:**
```
POST /firewall/analyze
  → enqueue task to Redis queue
  → return 202 Accepted { "task_id": "...", "status": "queued" }

GET /firewall/analysis/status/{task_id}
  → return { "status": "queued" | "running" | "done" | "failed" }

GET /firewall/analysis
  → return completed analysis (unchanged)
```

**Celery tasks:**
```python
@celery_app.task(bind=True, max_retries=2, time_limit=120)
def run_firewall_analysis(self, analysis_id: str, upload_id: str, cde_seeds: list, ...):
    ...
```

**Render infrastructure:**
- Add a `worker` service in `render.yaml`:
  ```yaml
  - type: worker
    name: pci-scope-worker
    runtime: python
    rootDir: backend
    startCommand: celery -A app.worker worker --concurrency 4
  ```
- Add Redis service (Render managed or upstash.io).

**Acceptance criteria:**
- [ ] `/analyze` returns `202` within 200ms regardless of config size
- [ ] Worker processes tasks within 5 seconds for configs up to 5,000 rules
- [ ] Failed tasks set analysis to `status: failed` with error message in DB
- [ ] Frontend polls `/status/{task_id}` and transitions to results view on completion

---

### 5.4 Caching

**Problem:** `GET /api/assessments/*/reports/` and `GET /api/assessments/*/firewall/analysis` re-query large JSON columns on every request.

**Solution:** Cache with Redis. Use `fastapi-cache2` with Redis backend.

| Endpoint | Cache TTL | Invalidation |
|----------|-----------|-------------|
| `GET /firewall/analysis` | 5 min | On `POST /analyze` or `PATCH /answers` |
| `GET /reports/` | 10 min | On `POST /reports/` |
| `GET /assets/` | 1 min | On any asset write |
| `GET /assessments/` | 30 sec | On assessment create/delete |

Cache keys are namespaced by `tenant_id` to prevent cross-tenant cache leaks.

**Acceptance criteria:**
- [ ] Cache HIT ratio > 70% for read endpoints under load test
- [ ] Cache invalidation verified: stale data never returned after write
- [ ] Redis eviction policy: `allkeys-lru` to prevent OOM

---

### 5.5 Load testing

Run `locust` load tests against staging before every production release.

**Scenarios:**

| Scenario | Users | Duration | Pass criteria |
|----------|-------|----------|--------------|
| List assessments | 100 concurrent | 5 min | P95 < 100ms, 0% error |
| Full firewall workflow | 20 concurrent | 10 min | P95 < 30s end-to-end, 0% error |
| CSV import (500 rows) | 10 concurrent | 5 min | P95 < 2s, 0% error |
| PDF download | 50 concurrent | 5 min | P95 < 3s, 0% error |

**Acceptance criteria:**
- [ ] All load test scenarios meet pass criteria on staging
- [ ] No memory leaks over 30-min soak test (`memory_profiler`)

---

## 6. Phase 5 — Operational Readiness (Weeks 12–14)

> **Goal:** The team can operate, debug, and recover the system without tribal knowledge.

### 6.1 Staging environment

**Problem:** There is no environment between local dev and production.

**Solution:**

- **Staging:** identical Render service (`pci-scope-api-staging`) with its own PostgreSQL and Redis.
- Staging deploys automatically on every push to `main`.
- Production deploys require manual approval in GitHub Actions.
- Staging uses a dedicated `SENTRY_ENVIRONMENT=staging` so errors are separate.

**Acceptance criteria:**
- [ ] Staging environment deployed and accessible
- [ ] Staging DB is isolated from production
- [ ] E2E tests run against staging after every deploy

---

### 6.2 Database backup & restore

**Solution:**

- Enable **Render managed backups** (daily automatic snapshots, 7-day retention).
- Document manual restore procedure in `docs/db-restore.md`.
- Test restore quarterly (automated via a GitHub Actions scheduled workflow that restores to a temp DB and validates row counts).

**Acceptance criteria:**
- [ ] Daily backups confirmed enabled on Render PostgreSQL
- [ ] Restore test passes in < 30 minutes for the expected DB size
- [ ] RTO (Recovery Time Objective): < 1 hour
- [ ] RPO (Recovery Point Objective): < 24 hours

---

### 6.3 Alerting & on-call

**Alerts to configure (Render + Datadog/Grafana):**

| Alert | Threshold | Severity | Channel |
|-------|-----------|----------|---------|
| Error rate | > 1% over 5 min | P2 | Slack `#pci-alerts` |
| P95 latency | > 500ms over 5 min | P2 | Slack |
| CPU utilisation | > 80% over 10 min | P3 | Slack |
| Memory utilisation | > 85% | P2 | Slack + PagerDuty |
| DB connections | > 80% of pool | P2 | Slack |
| Health check down | `/readiness` returns non-200 | P1 | PagerDuty |
| Celery queue depth | > 50 pending tasks | P3 | Slack |
| Certificate expiry | < 30 days | P2 | Email |
| Failed login spike | > 20/min | P1 | PagerDuty (possible brute force) |

**On-call runbook index** (`docs/runbooks/`):

| Runbook | Trigger |
|---------|---------|
| `db-connection-exhaustion.md` | DB pool saturation alert |
| `celery-queue-backup.md` | Queue depth alert |
| `memory-leak.md` | Memory utilisation alert |
| `auth-brute-force.md` | Failed login spike |
| `rollback-procedure.md` | Failed production deploy |

**Acceptance criteria:**
- [ ] All P1 alerts route to PagerDuty with < 5-min MTTA
- [ ] All runbooks reviewed and tested by on-call team

---

### 6.4 Feature flags

**Problem:** No way to disable a feature in production without a deploy.

**Solution:** Add `FEATURE_FLAGS` env var (comma-separated) or integrate LaunchDarkly for more granular control.

Flags for Phase 1 launch:

| Flag | Default | Purpose |
|------|---------|---------|
| `firewall_analysis_async` | `true` | Use Celery background worker for analysis |
| `pdf_export` | `true` | Enable PDF download endpoint |
| `csv_bulk_import` | `true` | Enable CSV import endpoint |
| `allow_static_admin_token` | `false` | Backwards-compat for static token (disable in production) |

**Acceptance criteria:**
- [ ] Feature flags evaluated at request time (not startup)
- [ ] Flag state changes take effect within 30 seconds

---

## 7. Phase 6 — Compliance & Audit (Weeks 14–16)

> **Goal:** The system that classifies PCI scope must itself be auditable and compliant.

### 7.1 Audit log

**Problem:** No record of who accessed or modified what data. Required for any PCI-adjacent system.

**Solution:** Add an `audit_log` table and middleware.

```sql
audit_log
├── id             UUID PK
├── tenant_id      UUID NULL (NULL for admin actions)
├── actor_type     ENUM(admin, tenant_user)
├── event_type     VARCHAR(64)  -- "assessment.created", "asset.deleted", etc.
├── resource_type  VARCHAR(64)  -- "assessment", "asset", "firewall_upload"
├── resource_id    UUID NULL
├── request_id     UUID
├── ip_address     INET
├── user_agent     TEXT
├── request_body   JSONB NULL   -- scrubbed (no PAN, no credentials)
├── response_code  SMALLINT
└── created_at     TIMESTAMPTZ
```

**Events to log:**

| Event | Sensitivity |
|-------|-------------|
| `auth.admin_login` | High |
| `auth.tenant_token_issued` | High |
| `auth.refresh` | Medium |
| `assessment.created/deleted` | Medium |
| `asset.created/updated/deleted` | Medium |
| `asset.csv_imported` | Medium |
| `report.generated/downloaded` | Medium |
| `firewall.config_uploaded` | High |
| `firewall.analysis_run` | High |
| `auth.failed` | High |

**Retention:** Audit logs retained for 12 months (PCI DSS Req 10.7). Archive to S3-compatible cold storage after 90 days.

**Acceptance criteria:**
- [ ] Every state-modifying request produces an audit log entry
- [ ] Audit log is append-only (no UPDATE/DELETE permissions for app user)
- [ ] PAN and credentials are never present in `request_body`
- [ ] Audit log queryable by tenant, event type, date range via internal admin API

---

### 7.2 Data minimisation & PAN safety

**Problem:** The tool handles systems that may store/process/transmit PAN. The tool itself must never touch PAN.

**Solution:**

1. **PAN detector.** Add a server-side check that scans uploaded firewall configs and CSV imports for Luhn-valid 13–19 digit sequences (likely PAN). Reject the upload with a clear error if found.

2. **Scrubbing in audit log.** Implement a `scrub_body()` function that removes any field matching PAN patterns before storing in `audit_log.request_body`.

3. **Data classification headers.** All API responses include `X-Data-Classification: internal` header to signal downstream proxies/SIEMs.

**Acceptance criteria:**
- [ ] Uploading a file containing a test PAN returns `422` with message "PAN detected in upload — remove cardholder data before uploading"
- [ ] Audit log scrubber unit-tested against 20 PAN patterns

---

### 7.3 GDPR / privacy considerations

Although this tool handles network topology (not personal data), tenants are legal entities that may be subject to data residency requirements.

**Actions:**
1. **Data residency.** Document that data is stored in Render's US-East region. Provide a migration path to EU region on request.
2. **Tenant data deletion.** `DELETE /api/auth/tenants/{id}` (admin only) must cascade-delete all tenant data including audit logs (right-to-erasure). Implement a 30-day soft-delete before hard-delete.
3. **Data processing agreement.** Prepare a DPA template for enterprise customers.

**Acceptance criteria:**
- [ ] Complete tenant deletion (hard + soft) implemented and tested
- [ ] Data residency documented in `docs/data-residency.md`

---

### 7.4 Penetration testing

Before production launch, commission a third-party penetration test covering:

| Scope | Test type |
|-------|-----------|
| REST API | OWASP API Security Top 10 |
| Authentication | Brute force, token theft, JWT algorithm confusion |
| Multi-tenancy | IDOR, cross-tenant data access |
| File upload | Path traversal, content injection, DoS via large files |
| Frontend | XSS, CSRF, clickjacking |
| Infrastructure | Exposed ports, default credentials, misconfigurations |

**Acceptance criteria:**
- [ ] Pentest completed with findings documented
- [ ] All Critical and High findings remediated before production launch
- [ ] Medium findings have an accepted risk or remediation timeline

---

## 8. Non-Functional Requirements Summary

| NFR | Target |
|-----|--------|
| Availability | 99.5% uptime (≤ 4.4 hours downtime/month) |
| P50 API latency | < 50ms (read endpoints) |
| P95 API latency | < 200ms (read endpoints), < 30s (analysis) |
| P99 API latency | < 500ms (read endpoints) |
| Max concurrent tenants | 100 active sessions |
| Max firewall config size | 10 MB (parser) / 5,000 rules |
| Max CSV import size | 5,000 rows |
| Data retention | 12 months audit logs, 7 days DB backups |
| RTO | < 1 hour |
| RPO | < 24 hours |
| Test coverage | ≥ 85% backend, ≥ 70% frontend |

---

## 9. Dependency Map

```
Phase 1 (Security) ──────┐
                          ▼
Phase 2 (Observability) ──┤
                          ▼
Phase 3 (Testing/CI) ────┤
                          ▼
Phase 4 (Performance) ───┤
                          ▼
Phase 5 (Operations) ────┤
                          ▼
Phase 6 (Compliance) ────▶ Production Launch
```

Within Phase 1, tracks 2.1 (auth), 2.2 (rate limiting), 2.3 (upload hardening), and 2.5 (security headers) can be developed in parallel. Track 2.4 (secret management) must complete before 2.1.

Within Phase 3, backend tests (4.1) must pass before CI/CD (4.3) can enforce the coverage gate.

Phase 4 async migration (5.2) must complete before background task processing (5.3).

---

## 10. Definition of Done

A feature or workstream is considered **done for production** when all of the following are true:

- [ ] Code reviewed and approved by at least 1 engineer
- [ ] Unit + integration tests written and passing in CI
- [ ] No new `bandit` high/critical findings introduced
- [ ] `mypy --strict` passes
- [ ] Audit log entries emitted for any new state-mutating operation
- [ ] Feature flag added if the feature carries deployment risk
- [ ] Runbook written if the feature can fail in a way that requires manual intervention
- [ ] Deployed to staging and manually verified
- [ ] E2E tests pass on staging
- [ ] Load test pass criteria met (for performance-sensitive endpoints)
- [ ] Security headers scan still passes grade A
- [ ] Sentry receives no new error classes from staging smoke test

---

*This document was authored on 2026-04-28 and targets v1.0.0 production launch. It should be reviewed and updated at the start of each phase.*
