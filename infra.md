# Heroes Security Platform

AI-powered security scanning platform that orchestrates pentesting tools via intelligent agents. Built on top of the Heroes AI agent framework.

## What is Heroes Security?

Heroes Security transforms the Heroes AI agent platform into a security-focused product. AI agents (called **Heroes**) orchestrate open-source security scanning tools to perform web application testing, network security audits, mobile app analysis, and continuous vulnerability monitoring.

Each Hero specializes in a security domain and can run scans, correlate findings, track vulnerability lifecycle, and integrate with your dev workflow (Slack, GitHub, Jira, Linear).

## Architecture

```
User (Browser)
    |
    v
Frontend (React + Vite + MUI)         <- Security Dashboard, Targets, Findings views
    |
    v
API (NestJS)                           <- Targets CRUD, Findings workflow, Scan orchestration
    |
    v
Mission Executor                       <- AI agent loop (LLM + tools)
    |
    v
Security Service                       <- Tool dispatcher
    |
    +-- ProcessExecutor (Cloud Run)    <- nuclei, httpx, katana, subfinder, dalfox
    +-- DockerExecutor (local/VM)      <- nmap, sqlmap, hydra, nikto
    +-- MobSF REST API                 <- Mobile app analysis
```

### Two execution layers

**Camada 1 -- ProcessExecutor (production-ready):**
Static Go binaries installed directly in the Docker image. Runs via `execFile()` -- no Docker-in-Docker needed. Works on Cloud Run, any container platform, or bare metal.

Tools: nuclei (6500+ vuln templates), httpx (tech fingerprinting), katana (web crawler), subfinder (subdomain discovery), dalfox (XSS scanner)

**Camada 2 -- DockerExecutor (local dev / future worker VM):**
Ephemeral Docker containers for tools that need more isolation. Requires Docker socket.

Tools: nmap (port scanner), sqlmap (SQL injection), hydra (credential audit), nikto (web server misconfig)

## Security Heroes

Four pre-configured AI agents, each specialized in a security domain:

| Hero | Role | Capabilities |
|------|------|-------------|
| **Guardian** | Web Application Security Analyst | Web recon, SQLi detection, XSS scanning, OWASP Top 10 |
| **Sentinel** | Network Security Analyst | Port scanning, subdomain enumeration, credential auditing |
| **Shield** | Mobile Security Analyst | APK analysis, secrets extraction, OWASP Mobile Top 10 |
| **Watcher** | Continuous Security Monitor | Scheduled scans, diff comparison, alerts on new findings |

Each Hero has a tailored system prompt that guides its scanning methodology, output format, and safety rules (never scan without authorization).

## Security Tools (9 tools)

| Tool | What it does | Runner |
|------|-------------|--------|
| `security_web_recon` | HTTP fingerprint + crawl + vulnerability scan pipeline | ProcessExecutor |
| `security_sqli_scan` | SQL injection detection with PoC payloads | ProcessExecutor + Docker |
| `security_xss_scan` | Cross-site scripting scanner | ProcessExecutor |
| `security_network_scan` | Port scan + service detection + CVE matching | DockerExecutor |
| `security_subdomain_scan` | Subdomain discovery + alive probe + scan | ProcessExecutor |
| `security_mobile_scan` | APK static analysis + secrets extraction | MobSF + Docker |
| `security_credential_audit` | Default/weak credential testing | DockerExecutor |
| `security_nuclei_scan` | Direct Nuclei scan with custom templates/tags | ProcessExecutor |
| `security_nikto_scan` | Web server misconfiguration scanner | DockerExecutor |

### Scan Pipelines

Tools are composed into multi-step pipelines:

- **Web Recon**: httpx (fingerprint) -> katana (crawl) -> nuclei (scan). Depth: quick/standard/deep
- **SQLi**: katana (find params) -> sqlmap (test injection)
- **XSS**: katana (find forms) -> dalfox (test XSS)
- **Network**: nmap (ports + services) -> nuclei (network CVEs)
- **Subdomain**: subfinder (enumerate) -> httpx (probe alive) -> nuclei (scan alive)
- **Mobile**: MobSF (full analysis) -> APKLeaks (secrets)

## Data Model

### Target
Groups scans by domain, IP, or application. Tracks scan history and aggregated finding counts.

### Finding (with workflow)
Persisted vulnerability findings with lifecycle status management:
- **Status**: open -> in_progress -> fixed / accepted_risk / false_positive
- **Deduplication**: by `externalId + targetId` (primary) or `type + title + targetId` (fallback)
- **Temporal tracking**: `firstSeenAt` and `lastSeenAt` -- detects when findings appear or disappear between scans
- **Assignment**: assign findings to team members with notes

### SecurityScan
Raw scan execution record linked to a Target and Mission. Stores raw tool output and metadata.

## Frontend

### Navigation
```
Dashboard    -> Security metrics (severity cards, trends, recent scans, top targets)
Targets      -> CRUD targets, scan history, "Scan Now" button
Heroes       -> Security heroes with presets (Guardian, Sentinel, Shield, Watcher)
Missions     -> Chat with Heroes, view scan conversations
Findings     -> Filterable table, status workflow, bulk actions, CSV/JSON export
Integrations -> Connect Slack, GitHub, Jira, Linear for alerts and ticket automation
Settings     -> API keys, credentials, general configuration
```

### Key Views

**Security Dashboard**: Severity cards (critical/high/medium/low), recent scans list, vulnerability trend chart, top vulnerable targets.

**Targets**: List with type badges, status chips, finding summaries. Click into detail view with scan timeline and embedded findings.

**Findings**: The core view. Filter by severity, type, target, OWASP category, status. Expand rows to see evidence, remediation, and change status. Bulk actions for triaging. Export to CSV/JSON.

## Continuous Security

### Scheduled Scans
Use the existing Schedule system with presets:
- Daily quick scan (web recon, top CVEs only)
- Weekly full scan (all severities, deep crawl)
- Monthly network audit (full port scan)

### Scan on Push (Webhooks)
GitHub/GitLab webhooks trigger scans automatically with built-in throttling:
- `cooldownMinutes`: minimum time between scans (default 60)
- `maxScansPerDay`: daily cap per hook (default 5)

Prevents runaway costs on active repositories.

### Integration Alerts
When Watcher finds new critical/high findings, it can automatically:
- Send Slack messages to your security channel
- Create Jira/Linear issues with severity, description, and remediation
- Open GitHub issues on the affected repository

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 18, Vite, MUI v5, Recharts, @assistant-ui/react |
| **API** | NestJS 10, TypeScript, Prisma ORM |
| **Database** | PostgreSQL 16 |
| **Cache/Sessions** | Redis 7 |
| **LLM** | Anthropic Claude (primary), OpenAI, Google Gemini, Ollama (local) |
| **Security Tools** | Nuclei, httpx, katana, subfinder, dalfox, nmap, sqlmap, hydra, nikto, MobSF, APKLeaks |
| **Infrastructure** | GCP Cloud Run, Cloud SQL, Terraform |

## Getting Started

### Prerequisites
- Node.js >= 18.15.0 (< 19 or >= 20)
- pnpm >= 9
- Docker Desktop (for PostgreSQL, Redis, and Camada 2 tools)

### 1. Start services

```bash
docker compose up -d postgres redis
```

### 2. Install dependencies

```bash
pnpm install
```

### 3. Configure environment

```bash
# API
cp apps/api/.env.example apps/api/.env
# Edit apps/api/.env -- set DATABASE_URL, REDIS_HOST, and LLM API keys

# Frontend
cp apps/web-heroes/.env.example apps/web-heroes/.env
```

### 4. Setup database

```bash
pnpm db:generate
DATABASE_URL="postgresql://postgres:password@localhost:5432/heroes" npx prisma migrate deploy
DATABASE_URL="postgresql://postgres:password@localhost:5432/heroes" npx prisma db seed
```

This seeds:
- Admin user (admin@kairos.com / admin)
- 27 built-in powers (14 active, 13 deactivated non-security)
- 4 security heroes (Guardian, Sentinel, Shield, Watcher)

### 5. Run the platform

```bash
pnpm dev
```

- **Frontend**: http://localhost:8080
- **API**: http://localhost:3003
- **API Docs**: http://localhost:3003/api/docs

### Dev bypass (skip login)

For local testing without authentication:

```bash
# In apps/api/.env
BYPASS_AUTH=true

# In apps/web-heroes/.env
VITE_BYPASS_AUTH=true
```

Start the API with the env var:
```bash
cd apps/api && BYPASS_AUTH=true npx nest start --watch
```

## API Endpoints

### Security
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/security/tools` | List available security scanning tools |
| GET | `/api/security/health` | Check Docker/binary availability |
| GET | `/api/security/dashboard` | Dashboard stats (severity counts, recent scans, top targets) |

### Targets
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/security/targets` | List targets (filter by type, status) |
| GET | `/api/security/targets/:id` | Get target detail |
| POST | `/api/security/targets` | Create target |
| PUT | `/api/security/targets/:id` | Update target |
| DELETE | `/api/security/targets/:id` | Delete target |

### Findings
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/security/findings` | List findings (filter by severity, type, target, OWASP, status) |
| GET | `/api/security/findings/stats` | Aggregate stats by severity and status |
| GET | `/api/security/findings/:id` | Get finding detail |
| PATCH | `/api/security/findings/:id` | Update finding status/assignee/notes |
| PATCH | `/api/security/findings/bulk` | Bulk update finding status |
| GET | `/api/security/findings/export` | Export findings as CSV/JSON |

## Project Structure

```
apps/
  api/                              # NestJS backend
    src/
      security/                     # Security scanning module
        types/                      # Finding, ScanResult, ToolRunner interfaces
        runners/                    # 11 tool runners (nuclei, httpx, nmap, etc.)
        pipelines/                  # 7 multi-step scan pipelines
        targets/                    # Targets CRUD service + controller
        findings/                   # Findings workflow service + controller
        process-executor.ts         # execFile wrapper (Cloud Run)
        docker-executor.ts          # Docker container wrapper (local)
        security.service.ts         # Main orchestrator
        security.controller.ts      # REST endpoints + dashboard
        finding-normalizer.ts       # Normalize output for AI agents
      missions/mission-executor/    # AI agent execution engine
        tool-resolver.ts            # Resolves powers to tools (MCP + security)
        mission-executor.service.ts # LLM loop with tool calls
  web-heroes/                       # React frontend
    src/
      views/
        dashboard/                  # Security dashboard
        targets/                    # Targets list + detail
        findings/                   # Findings table with workflow
        heroes-new/                 # Hero management (security presets)
packages/
  db/prisma/                        # Schema (Target, Finding, SecurityScan models)
docker/security/                    # MobSF docker-compose
Dockerfile                          # Includes security binaries for Cloud Run
docs/superpowers/
  specs/2026-04-06-security-pivot-design.md
  plans/2026-04-06-security-pivot.md
```

## Future Roadmap

- **Phase 2: Assessment Platform** -- Project/Client model, PDF/HTML report engine, remediation SLA
- **Phase 2: Camada 2 Worker** -- GCE instance with Docker for nmap/sqlmap/hydra via Redis queue
- **Phase 2: MobSF Deployment** -- Dedicated Cloud Run service for mobile analysis
- **Phase 3: Enterprise** -- Role-based access per project, CI/CD integration (GitHub Actions), compliance mapping (PCI-DSS, SOC2)
