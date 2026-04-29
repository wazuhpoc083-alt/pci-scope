# PCI DSS Scoping Tool — Technical Specification

> Version: 0.1.0  
> Last updated: 2026-04-28  
> Standard: OpenSpec / Markdown

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Technology Stack](#3-technology-stack)
4. [Data Model](#4-data-model)
5. [Authentication & Authorization](#5-authentication--authorization)
6. [Backend API](#6-backend-api)
7. [Core Algorithms](#7-core-algorithms)
8. [Frontend Application](#8-frontend-application)
9. [Firewall Parsers](#9-firewall-parsers)
10. [Deployment](#10-deployment)
11. [Environment Variables](#11-environment-variables)
12. [Development Setup](#12-development-setup)
13. [Testing](#13-testing)
14. [Security Considerations](#14-security-considerations)

---

## 1. Overview

The **PCI DSS Scoping Tool** is a web application that helps Financial Service Institutions (FSIs) determine which systems fall within PCI DSS scope per **v4.0 Requirement 12.3**. It provides:

- Multi-tenant assessment management
- Asset inventory with PCI scope classification
- Firewall configuration upload, parsing, and automated analysis
- Scope propagation via graph-based BFS engine
- Gap analysis against 10 PCI DSS v4.0 Requirement 1.x controls
- PDF and CSV report generation

The product is structured as a **Python/FastAPI REST backend** backed by **PostgreSQL** and a **React/TypeScript SPA frontend**.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Browser (SPA)                        │
│    React 18 + TypeScript + Vite + Tailwind + Radix UI        │
│    Deployed on: Vercel                                        │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTPS / REST (JSON)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                  FastAPI Application                          │
│    Python 3.12 · Uvicorn ASGI · Alembic migrations          │
│    Deployed on: Render (web service)                          │
│                                                               │
│  Routers                                                      │
│  ├── /api/auth/*          ← Auth, tenants, token issuance    │
│  ├── /api/assessments/*   ← Assessment CRUD                  │
│  ├── /api/assessments/{id}/assets/*   ← Asset CRUD + CSV     │
│  ├── /api/assessments/{id}/reports/*  ← Report gen + PDF     │
│  └── /api/assessments/{id}/firewall/* ← Upload + analyze     │
│                                                               │
│  Engines                                                      │
│  ├── scope_engine.py      ← BFS scope propagation            │
│  ├── gap_engine.py        ← PCI DSS v4.0 gap analysis        │
│  └── report_builder.py    ← Structured report + PDF          │
│                                                               │
│  Parsers                                                      │
│  ├── fortinet.py                                             │
│  ├── cisco_asa.py                                            │
│  ├── palo_alto.py                                            │
│  └── iptables.py                                             │
└────────────────────────┬────────────────────────────────────┘
                         │ SQLAlchemy ORM
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              PostgreSQL Database                              │
│    Tables: tenants, assessments, assets,                      │
│            scope_reports, firewall_uploads,                   │
│            firewall_rules, firewall_scope_analyses            │
└─────────────────────────────────────────────────────────────┘
```

### Request lifecycle

1. Browser sends `Authorization: Bearer <token>` with every request.
2. FastAPI `HTTPBearer` extracts the token.
3. `auth.py:verify_token()` checks for admin static token first, then validates JWT.
4. Route handler receives `TokenClaims(tenant_id, role, is_admin)`.
5. All DB queries are automatically scoped to `tenant_id` (admin sees all).
6. Response serialised via Pydantic v2 schemas.

---

## 3. Technology Stack

### Backend

| Component | Library / Version |
|-----------|-------------------|
| Language | Python 3.12 |
| Web framework | FastAPI 0.111.0 |
| ASGI server | Uvicorn 0.29.0 (with standard extras) |
| ORM | SQLAlchemy 2.0.30 |
| Migrations | Alembic 1.13.1 |
| Database driver | psycopg2-binary 2.9.9 |
| Validation | Pydantic 2.7.1 / pydantic-settings 2.2.1 |
| JWT | python-jose[cryptography] 3.3.0 |
| Password hashing | passlib[bcrypt] 1.7.4 |
| File upload | python-multipart 0.0.9 |
| HTTP client (tests) | httpx 0.27.0 |
| PDF generation | reportlab 4.2.0 |

### Frontend

| Component | Library / Version |
|-----------|-------------------|
| Language | TypeScript 5.9.3 |
| UI framework | React 18.3.1 |
| Bundler | Vite 5.2.11 |
| Routing | react-router-dom 6.23.1 |
| HTTP client | axios 1.7.2 |
| Styling | Tailwind CSS 3.4.3 |
| UI primitives | Radix UI (dialog, select, tabs, toast) |
| Icons | lucide-react 0.378.0 |
| Diagram rendering | mermaid 11.14.0 |
| Utility | clsx, tailwind-merge |

### Infrastructure

| Service | Platform |
|---------|----------|
| Backend hosting | Render (Python web service) |
| Frontend hosting | Vercel |
| Database | PostgreSQL (Render managed or external) |

---

## 4. Data Model

All IDs are UUID v4 strings (36-char). Timestamps are timezone-aware UTC.

### 4.1 Tenants

```
tenants
├── id           STRING(36) PK
├── name         STRING(255) NOT NULL
├── slug         STRING(100) UNIQUE NOT NULL   ← URL-safe identifier
└── created_at   DATETIME(tz) DEFAULT now()
```

**Relationships:** one tenant → many assessments.

### 4.2 Assessments

```
assessments
├── id               STRING(36) PK
├── tenant_id        STRING(36) FK→tenants.id NOT NULL
├── name             STRING(255) NOT NULL
├── organization     STRING(255) NOT NULL
├── pci_dss_version  STRING(10) DEFAULT "4.0"
├── description      TEXT NULL
├── is_finalized     BOOLEAN DEFAULT false
├── created_at       DATETIME(tz)
└── updated_at       DATETIME(tz) onupdate
```

**Cascade:** delete cascades to assets, scope_reports, firewall_uploads, firewall_scope_analyses.

### 4.3 Assets

```
assets
├── id                 STRING(36) PK
├── assessment_id      STRING(36) FK→assessments.id NOT NULL
├── name               STRING(255) NOT NULL
├── ip_address         STRING(45) NULL     ← supports IPv4 and IPv6
├── hostname           STRING(255) NULL
├── asset_type         ENUM(server|database|network_device|workstation|cloud_service|other)
├── scope_status       ENUM(in_scope|connected|out_of_scope|pending)
├── is_cde             BOOLEAN DEFAULT false
├── stores_pan         BOOLEAN DEFAULT false
├── processes_pan      BOOLEAN DEFAULT false
├── transmits_pan      BOOLEAN DEFAULT false
├── segmentation_notes TEXT NULL
├── justification      TEXT NULL
├── tags               JSON DEFAULT []
├── created_at         DATETIME(tz)
└── updated_at         DATETIME(tz) onupdate
```

### 4.4 Scope Reports

```
scope_reports
├── id             STRING(36) PK
├── assessment_id  STRING(36) FK→assessments.id NOT NULL
├── generated_at   DATETIME(tz)
├── summary        JSON NULL   ← {in_scope, connected, out_of_scope, pending, total}
└── report_json    JSON NULL   ← full structured report payload
```

### 4.5 Firewall Uploads

```
firewall_uploads
├── id             STRING(36) PK
├── assessment_id  STRING(36) FK→assessments.id CASCADE
├── filename       STRING(255) NOT NULL
├── vendor         ENUM(fortinet|iptables|cisco_asa|palo_alto|unknown)
├── raw_text       TEXT NULL
├── parse_errors   JSON DEFAULT []
├── rule_count     INTEGER DEFAULT 0
├── interfaces     JSON DEFAULT {}    ← {intf_name: cidr} mappings
└── created_at     DATETIME(tz)
```

### 4.6 Firewall Rules

```
firewall_rules
├── id          STRING(36) PK
├── upload_id   STRING(36) FK→firewall_uploads.id CASCADE
├── policy_id   STRING(64) NULL
├── name        STRING(255) NULL
├── src_intf    STRING(255) NULL
├── dst_intf    STRING(255) NULL
├── src_addrs   JSON DEFAULT []    ← list of IP/CIDR/name strings
├── dst_addrs   JSON DEFAULT []
├── services    JSON DEFAULT []    ← list of "proto/port" or service name strings
├── action      STRING(16) DEFAULT "permit"   ← permit|deny|drop
├── nat         BOOLEAN DEFAULT false
├── log_traffic BOOLEAN DEFAULT true
├── comment     TEXT NULL
└── raw         JSON NULL    ← original parsed object (vendor-specific)
```

### 4.7 Firewall Scope Analyses

```
firewall_scope_analyses
├── id             STRING(36) PK
├── upload_id      STRING(36) FK→firewall_uploads.id CASCADE
├── assessment_id  STRING(36) FK→assessments.id CASCADE
├── cde_seeds      JSON DEFAULT []   ← list of CIDR strings user identified as CDE
├── scope_nodes    JSON DEFAULT []   ← list of ScopeNode objects
├── questions      JSON DEFAULT []   ← clarifying questions from gap engine
├── answers        JSON DEFAULT {}   ← map of question_id → answer string
├── gap_findings   JSON DEFAULT []   ← list of GapFinding objects
├── created_at     DATETIME(tz)
└── updated_at     DATETIME(tz) onupdate
```

### 4.8 Enumerations

| Enum | Values |
|------|--------|
| `AssetType` | `server`, `database`, `network_device`, `workstation`, `cloud_service`, `other` |
| `ScopeStatus` | `in_scope`, `connected`, `out_of_scope`, `pending` |
| `FirewallVendor` | `fortinet`, `iptables`, `cisco_asa`, `palo_alto`, `unknown` |
| `GapSeverity` | `critical`, `high`, `medium`, `low`, `info` |
| `NodeScopeStatus` | `cde`, `connected`, `security_providing`, `out_of_scope`, `unknown` |

---

## 5. Authentication & Authorization

### 5.1 Token Types

**Admin token (static)**
- Set via `ADMIN_TOKEN` environment variable.
- Passed as `Authorization: Bearer <ADMIN_TOKEN>`.
- Grants unrestricted access including tenant management and cross-tenant data.
- Checked first before JWT parsing — no expiry, purely string equality.

**Tenant JWT (short-lived)**
- HS256 JWT signed with `SECRET_KEY`.
- Issued by `POST /api/auth/tokens` (admin only).
- Claims: `sub` (tenant_id), `tenant_id`, `tenant_name`, `role` ("viewer"), `iat`, `exp`.
- Default TTL: 24 hours (configurable via `expires_hours`).
- Scopes all subsequent API calls to the specified tenant.

### 5.2 FastAPI Dependencies

```python
get_current_claims()  # validates token, returns TokenClaims
require_admin()       # wraps get_current_claims, raises 403 if not admin
```

`TokenClaims` dataclass:
```python
@dataclass
class TokenClaims:
    tenant_id: Optional[str]
    tenant_name: Optional[str]
    role: str          # "admin" | "viewer"
    is_admin: bool
```

### 5.3 Access Control Matrix

| Endpoint group | Admin | Tenant JWT |
|----------------|-------|------------|
| `GET /health` | ✓ | ✓ (no auth required) |
| `GET /api/auth/me` | ✓ | ✓ |
| `GET/POST /api/auth/tenants` | ✓ | ✗ |
| `POST /api/auth/tokens` | ✓ | ✗ |
| `GET /api/assessments/` | ✓ (all tenants) | ✓ (own tenant) |
| `POST /api/assessments/` | ✓ (must supply tenant_id) | ✓ (auto-scoped) |
| Assessment detail / assets / reports / firewall | ✓ | ✓ (own tenant only) |

---

## 6. Backend API

Base URL: `https://api.example.com` (production) / `http://localhost:8000` (local)

All endpoints except `GET /health` require `Authorization: Bearer <token>`.  
Error responses follow `{"detail": string | object | array}`.

### 6.1 Health

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Liveness probe. Returns `{"status": "ok"}` |

### 6.2 Auth

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/auth/me` | Any token | Returns caller's role and tenant context |
| GET | `/api/auth/tenants` | Admin | List all tenants |
| POST | `/api/auth/tenants` | Admin | Create a tenant (`name`, `slug` required) |
| POST | `/api/auth/tokens` | Admin | Issue a tenant JWT (`tenant_id` required, optional `expires_hours`) |

**Create tenant request:**
```json
{ "name": "Acme Bank", "slug": "acme-bank" }
```

**Issue token request:**
```json
{ "tenant_id": "<uuid>", "expires_hours": 24 }
```

### 6.3 Assessments

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/assessments/` | Any | List assessments (tenant-scoped) |
| POST | `/api/assessments/` | Any | Create assessment |
| GET | `/api/assessments/{id}` | Any | Get assessment |
| DELETE | `/api/assessments/{id}` | Any | Delete assessment (cascades everything) |

**Create assessment request:**
```json
{
  "name": "Q1 2026 Scope Review",
  "organization": "Acme Bank",
  "pci_dss_version": "4.0",
  "description": "Annual scope confirmation",
  "tenant_id": "<uuid>"   // admin only — omit for tenant JWT callers
}
```

### 6.4 Assets

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/assessments/{id}/assets/` | Any | List all assets |
| POST | `/api/assessments/{id}/assets/` | Any | Create single asset |
| GET | `/api/assessments/{id}/assets/{asset_id}` | Any | Get asset |
| PATCH | `/api/assessments/{id}/assets/{asset_id}` | Any | Partial update |
| DELETE | `/api/assessments/{id}/assets/{asset_id}` | Any | Delete asset |
| POST | `/api/assessments/{id}/assets/bulk` | Any | Create multiple assets (single transaction) |
| GET | `/api/assessments/{id}/assets/csv-template` | Any | Download CSV import template |
| POST | `/api/assessments/{id}/assets/csv-import` | Any | Import assets from CSV (`multipart/form-data`) |

**CSV import rules:**
- Required columns: `name`, `ip_address`, `hostname`, `asset_type`, `scope_status`, `is_cde`, `stores_pan`, `processes_pan`, `transmits_pan`, `segmentation_notes`, `justification`, `tags` (semicolon-separated)
- Lines starting with `#` are ignored
- Atomic: all rows must pass validation or none are created
- Returns `422` with row-level error list on failure

### 6.5 Reports

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/assessments/{id}/reports/` | Any | Generate scope report |
| GET | `/api/assessments/{id}/reports/` | Any | List reports (newest first) |
| GET | `/api/assessments/{id}/reports/{report_id}/pdf` | Any | Download PDF |

Report generation runs `report_builder.py` over all current assets, persists `summary` (counts per scope status) and `report_json` (full structured payload), then returns the report object.

### 6.6 Firewall

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/assessments/{id}/firewall/upload` | Any | Upload & parse firewall config (multipart, max 10 MB) |
| GET | `/api/assessments/{id}/firewall/uploads` | Any | List uploads (newest first) |
| GET | `/api/assessments/{id}/firewall/uploads/{upload_id}/rules` | Any | List normalised rules |
| POST | `/api/assessments/{id}/firewall/analyze` | Any | Run scope + gap analysis |
| GET | `/api/assessments/{id}/firewall/analysis` | Any | Get latest analysis |
| PATCH | `/api/assessments/{id}/firewall/analysis/answers` | Any | Submit question answers & re-run |
| GET | `/api/assessments/{id}/firewall/export/csv` | Any | Export analysis as CSV |

**Analyze request:**
```json
{
  "upload_id": "<uuid>",
  "cde_seeds": ["10.0.1.0/24"],
  "subnet_classifications": {
    "192.168.10.0/24": "connected"
  }
}
```

**Answers request:**
```json
{
  "answers": {
    "question-id-1": "yes",
    "question-id-2": "no, this is a monitoring VLAN"
  }
}
```

---

## 7. Core Algorithms

### 7.1 Scope Engine (`app/scope_engine.py`)

**Purpose:** Classify every IP/subnet observed in firewall rules relative to user-declared CDE seeds.

**Node scope statuses:**

| Status | Definition |
|--------|-----------|
| `cde` | Explicitly declared by user as Cardholder Data Environment |
| `connected` | Bidirectional permitted path to/from at least one CDE seed |
| `security_providing` | Provides auth/DNS/NTP/logging services to CDE on security ports |
| `out_of_scope` | No permitted path to/from CDE |
| `unknown` | Discovered in rules but not yet classified |

**Algorithm (BFS-based):**

1. Extract all unique CIDR strings from rule `src_addrs` + `dst_addrs` + user seeds.
2. Parse each CIDR into `ipaddress.IPv4Network`.
3. Build directed adjacency graph from `permit` rules only: `src → dst`.
4. Build reverse graph: `dst → src`.
5. Run BFS forward from CDE seeds → finds everything reachable FROM CDE.
6. Run BFS backward from CDE seeds → finds everything that can REACH CDE.
7. Union of forward + backward = `connected` zone.
8. Scan `permit` rules for services on known security ports (LDAP 389/636, Kerberos 88, Syslog 514, DNS 53, NTP 123, SNMP 161/162, HTTPS 443/8443, SIEM 5601/9200) — sources become `security_providing`.
9. Assign final status per node: CDE seeds → `cde`; security_providing and not CDE → `security_providing`; in connected zone → `connected`; else → `out_of_scope`.
10. Skip pure internet nodes (non-RFC1918, non-loopback) unless they appear in seed or connected sets.

**Output:** list of `ScopeNode` dicts `{ip, scope_status, rule_ids, label}`.

### 7.2 Gap Engine (`app/gap_engine.py`)

**Purpose:** Run 10 static PCI DSS v4.0 Requirement 1.x gap checks against normalised firewall rules.

**Gap checks implemented:**

| Check ID | Requirement | Severity | Description |
|----------|-------------|----------|-------------|
| `GAP-DENY-ALL` | Req 1.3.2 | High | No explicit deny-all catch-all rule at end of policy |
| `GAP-INET-TO-CDE` | Req 1.3.3 | Critical | Direct permit from internet source to CDE destination |
| `GAP-BROAD-INBOUND` | Req 1.3.5 | High | Any-source / any-service permit rules |
| `GAP-CDE-OUTBOUND` | Req 1.4.2 | High | CDE systems have unrestricted any-service outbound internet |
| `GAP-RULE-COMMENTS` | Req 1.2.5 | Low | >30% of permit rules have no justification comment |
| `GAP-INSECURE-PROTO` | Req 1.2.6 | High | Telnet (23), FTP (20/21), TFTP (69), rsh (514) permitted |
| `GAP-BROAD-INTERNAL-CDE` | Req 1.3.1 | Medium | All-service inbound to CDE from internal/any source |
| `GAP-SPOOF` | Req 1.4.3 | High | Private RFC1918 source IPs permitted from external interface |
| `GAP-CDE-NO-NAT` | Req 1.4.5 | Medium | Internet-to-CDE rules with `nat: false` (real IPs exposed) |
| `GAP-WIRELESS-CDE` | Req 1.3.3 | Critical | Wireless interface has direct permit path to CDE |

**Gap finding object:**
```json
{
  "id": "GAP-INET-TO-CDE",
  "severity": "critical",
  "requirement": "PCI DSS v4.0 Req 1.3.3",
  "title": "Direct internet access to CDE systems detected",
  "description": "...",
  "affected_rules": ["policy-1", "policy-7"],
  "remediation": "Introduce a DMZ tier..."
}
```

**Question generation:**

The engine generates clarifying questions when patterns are ambiguous:
- Any-to-any rules: asks for business justification
- External access to internal subnets on card-processing ports (443, 8080, etc.): asks if subnet is CDE
- Broad ANY-source to private subnet not already in CDE seeds: asks for classification
- Access to known payment processor IP ranges: asks if source is in cardholder data flow
- Connected nodes (up to 5): confirms security controls limiting CDE access
- Wireless interfaces detected: asks about segmentation from CDE
- Zero deny rules: asks if deny-all is enforced at another layer

**Answer processing:**

When `PATCH /api/.../firewall/analysis/answers` is called:
1. `extract_answer_driven_cde_seeds()` scans `cde_id` questions — affirmative answers promote the destination subnet to a CDE seed.
2. The scope engine and gap engine are re-run with the expanded seed set.
3. `refine_findings_with_answers()` post-processes findings:
   - Suppresses `GAP-DENY-ALL` if user confirmed an upstream deny-all at another layer.
   - Annotates findings with user-provided context for affected rules.

### 7.3 Report Builder (`app/report_builder.py`)

Aggregates all assets for an assessment into:
- **Summary:** counts per `ScopeStatus` value plus total
- **report_json:** full structured payload for UI rendering and PDF export

PDF generation uses **ReportLab** to produce a formatted scope report document.

---

## 8. Frontend Application

### 8.1 Application Structure

```
frontend/src/
├── main.tsx              ← React entry point, mounts <App />
├── App.tsx               ← Router setup, Layout, AuthProvider wrapper
├── AuthContext.tsx        ← React context for token + claims state
├── api.ts                ← Axios instance, all typed API call functions
├── components/
│   ├── Navbar.tsx
│   ├── PrivateRoute.tsx
│   ├── AddAssetForm.tsx
│   ├── AssetRow.tsx
│   └── firewall/
│       ├── FirewallAnalysis.tsx   ← orchestrator component
│       ├── UploadStep.tsx
│       ├── SeedIPEntry.tsx
│       ├── MarkSubnetsStep.tsx
│       ├── ParsedRulesTable.tsx
│       ├── QuestionFlow.tsx
│       ├── GapFindings.tsx
│       ├── ScopeSummary.tsx
│       └── NetworkDiagram.tsx     ← Mermaid-rendered topology
└── pages/
    ├── LoginPage.tsx
    ├── AssessmentsPage.tsx
    ├── AssessmentDetailPage.tsx   ← tabs: Assets | Reports | Firewall
    └── AdminPage.tsx              ← tenant management + token issuance
```

### 8.2 Routing

| Path | Component | Auth required |
|------|-----------|---------------|
| `/login` | `LoginPage` | No |
| `/` | Redirect → `/assessments` | Yes |
| `/assessments` | `AssessmentsPage` | Yes |
| `/assessments/:id` | `AssessmentDetailPage` | Yes |
| `/admin` | `AdminPage` | Yes (admin token only enforced server-side) |

### 8.3 Authentication Flow

1. User enters bearer token on `LoginPage`.
2. `api.ts` calls `GET /api/auth/me` to validate token and retrieve claims.
3. `AuthContext` stores `{ token, claims }` in React state (not persisted to localStorage — session lasts while tab is open).
4. `PrivateRoute` redirects to `/login` if no token present.
5. All `axios` requests include `Authorization: Bearer <token>` via request interceptor.

### 8.4 Firewall Analysis Wizard

The firewall workflow is a multi-step wizard inside `AssessmentDetailPage`:

1. **Upload** — drag/drop or file picker → `POST /firewall/upload`
2. **Seed IPs** — user enters known CDE subnets (CIDR) → stored locally
3. **Mark subnets** — manual override of subnet classifications (optional)
4. **Analyze** → `POST /firewall/analyze` with seeds + overrides
5. **Questions** — interactive Q&A flow → `PATCH /firewall/analysis/answers`
6. **Gap findings** — severity-sorted list with affected rules and remediation
7. **Scope summary** — visual summary of node classifications
8. **Network diagram** — Mermaid.js-rendered topology graph

---

## 9. Firewall Parsers

All parsers live in `backend/app/parsers/` and share a common output contract.

### Normalised rule object

```python
{
  "policy_id": str | None,
  "name": str | None,
  "src_intf": str | None,
  "dst_intf": str | None,
  "src_addrs": list[str],     # IP/CIDR strings or named objects
  "dst_addrs": list[str],
  "services": list[str],       # "proto/port" or service names
  "action": "permit" | "deny" | "drop",
  "nat": bool,
  "log_traffic": bool,
  "comment": str | None,
  "raw": dict | None,          # vendor-specific original object
}
```

### 9.1 Fortinet (`parsers/fortinet.py`)

- Parses FortiGate `config firewall policy` blocks.
- Extracts `edit <id>`, `set srcintf`, `set dstintf`, `set srcaddr`, `set dstaddr`, `set service`, `set action`, `set nat`, `set logtraffic`, `set comments`.
- Interface-to-CIDR mappings extracted from `config system interface` → `set ip`.
- Named address objects resolved from `config firewall address`.
- FQDN addresses serialised as `fqdn:<name>|<ip>` when IP is available, else `fqdn:<name>`.

### 9.2 Cisco ASA (`parsers/cisco_asa.py`)

- Parses `access-list <name> extended {permit|deny}` statements.
- Resolves named object groups from `object-group network` blocks.
- Extracts NAT from `nat` statements.
- Interface names parsed from `interface` + `nameif` stanzas.

### 9.3 Palo Alto (`parsers/palo_alto.py`)

- Parses Panorama/PAN-OS XML `<security><rules>` blocks.
- Resolves address objects and address groups from `<address>` and `<address-group>`.
- Service objects resolved from `<service>` + `<service-group>`.
- `<log-end>` → `log_traffic`.

### 9.4 iptables (`parsers/iptables.py`)

- Parses `iptables-save` / `ip6tables-save` text output.
- Supports `-A`, `-s`, `-d`, `-p`, `--dport`, `-j` flags.
- Maps `ACCEPT` → `permit`, `DROP`/`REJECT` → `deny`.
- Chain names used as pseudo-interface names.

### 9.5 Vendor auto-detection

Detection order (in `firewall.py` router):
1. Filename contains `fortigate` / `fortinet` → Fortinet
2. Filename contains `cisco` / `asa` → Cisco ASA
3. Filename contains `palo` / `panorama` → Palo Alto
4. Content contains `config firewall policy` → Fortinet
5. Content contains `access-list` + `extended` → Cisco ASA
6. Content contains `<security><rules>` → Palo Alto
7. Content contains `iptables` / `ip6tables` → iptables
8. Default → `unknown` (stored but returns parse errors)

---

## 10. Deployment

### 10.1 Backend (Render)

Defined in `render.yaml`:

```yaml
services:
  - type: web
    name: pci-scope-api
    runtime: python
    rootDir: backend
    buildCommand: pip install -r requirements.txt
    startCommand: alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port $PORT
    healthCheckPath: /health
    autoDeploy: true
```

On startup, the app also runs `_run_migrations()` via the FastAPI lifespan handler as a safety net (in case the `startCommand` migration step is skipped in custom deployments).

### 10.2 Frontend (Vercel)

- `vite build` produces `dist/` (SPA with client-side routing).
- `vercel.json` rewrites all routes to `index.html` for SPA routing.
- `VITE_API_URL` environment variable configures the backend base URL.

### 10.3 Database

- Alembic manages schema via 4 migration files:
  - `001_initial_schema.py` — assessments, assets, scope_reports
  - `002_firewall_analysis.py` — firewall_uploads, firewall_rules, firewall_scope_analyses
  - `003_add_interfaces.py` — adds `interfaces` JSON column to firewall_uploads
  - `004_add_tenants.py` — adds tenants table, adds tenant_id FK to assessments

---

## 11. Environment Variables

### Backend

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | — | PostgreSQL connection string (e.g. `postgresql://user:pass@host/db?sslmode=require`) |
| `SECRET_KEY` | Yes | `change-me-in-production` | HMAC key for JWT signing. Must be strong random value in production. |
| `ALGORITHM` | No | `HS256` | JWT signing algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | No | `60` | Not directly used (JWT TTL set per-request via `expires_hours`) |
| `CORS_ORIGINS` | No | `http://localhost:5173,https://pci-scope.vercel.app` | Comma-separated allowed CORS origins |
| `ADMIN_TOKEN` | Yes (for admin) | `""` | Static bearer token granting admin access. Empty = admin access disabled. |

### Frontend

| Variable | Required | Description |
|----------|----------|-------------|
| `VITE_API_URL` | Yes | Backend base URL (e.g. `https://pci-scope-api.onrender.com`) |

---

## 12. Development Setup

### Prerequisites

- Python 3.12+
- Node.js 20+ / npm 10+
- PostgreSQL 15+ (local or Docker)

### Backend

```bash
cd backend
cp .env.example .env
# Edit .env with your DATABASE_URL, SECRET_KEY, ADMIN_TOKEN

python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

alembic upgrade head

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API docs available at `http://localhost:8000/docs` (Swagger UI) and `/redoc`.

### Frontend

```bash
cd frontend
npm install

# Create .env.local
echo "VITE_API_URL=http://localhost:8000" > .env.local

npm run dev
```

App runs at `http://localhost:5173`.

### Docker Compose (optional, community)

```yaml
# docker-compose.yml (not committed — create locally)
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: pci_scope
      POSTGRES_USER: dev
      POSTGRES_PASSWORD: dev
    ports: ["5432:5432"]

  api:
    build: ./backend
    environment:
      DATABASE_URL: postgresql://dev:dev@db/pci_scope
      SECRET_KEY: dev-secret
      ADMIN_TOKEN: dev-admin
    ports: ["8000:8000"]
    depends_on: [db]
```

---

## 13. Testing

### Backend tests

Located in `backend/tests/`:

| File | Coverage area |
|------|--------------|
| `test_gap_engine_answers.py` | Answer processing, CDE seed extraction, finding refinement |
| `test_gap_engine_new_checks.py` | All 10 static gap check functions |

Run:
```bash
cd backend
pytest tests/ -v
```

### No integration tests yet

The test suite covers unit tests for the gap and scope engines. Integration tests against a real database (httpx TestClient + SQLite or Postgres) are a known gap.

---

## 14. Security Considerations

| Area | Current approach | Recommended hardening |
|------|-----------------|----------------------|
| Admin token | Static string env var | Rotate regularly; consider short-lived admin JWTs |
| JWT secret | Render-generated random | Store in secrets manager (e.g. AWS Secrets Manager) |
| CORS | Allowlist via `CORS_ORIGINS` | Keep allowlist tight; no wildcard |
| SQL injection | SQLAlchemy ORM parameterised queries | N/A — ORM handles it |
| File upload | 10 MB limit; text decoding only | Add MIME-type validation; scan uploaded content |
| Tenant isolation | All queries filtered by `tenant_id` | Audit new endpoints for missing tenant filter |
| Error responses | Generic 500 message (no stack traces) | Structured error logging with request IDs |
| HTTPS | Enforced by Render / Vercel | Ensure `sslmode=require` on DATABASE_URL |
| Rate limiting | None currently | Add rate limiting middleware for auth endpoints |
| PAN data | Tool classifies PAN presence but does not store PAN | Ensure no PAN ever enters the system |

---

*This document was generated from the live codebase on 2026-04-28 and covers the state of the application at commit `d1ff028`.*
