# Heroes Security -- Open-Source Platform Integrations

**Date:** 2026-04-06
**Status:** Draft
**Author:** Security Architecture Team

---

## 1. Introduction

Heroes Security orchestrates 11 pentesting tools (nuclei, httpx, katana, subfinder, dalfox, nmap, sqlmap, hydra, nikto, MobSF, APKLeaks) via AI agents. It handles scan execution, finding normalization, and basic vulnerability lifecycle (open/in_progress/fixed/accepted_risk/false_positive).

However, the platform has clear gaps that established open-source projects have solved over years of development:

- **Finding management at scale** -- Heroes deduplicates by `externalId + targetId` or `type + title + targetId`, but lacks advanced correlation, grouping by vulnerability class, or cross-scan trending beyond `firstSeenAt`/`lastSeenAt`. No SLA tracking, no risk scoring models, no compliance mapping.
- **Reporting** -- Export is limited to CSV/JSON. No PDF/HTML pentest reports, no executive summaries, no compliance report templates (PCI-DSS, SOC2, HIPAA).
- **Scanning depth** -- All current tools are network/template-based (nuclei templates, nmap signatures). There is no DAST with browser context, no SAST (source code analysis), no container/IaC scanning, no secret detection in git history.
- **Threat intelligence** -- Findings include CVE references when tools provide them, but there is no enrichment pipeline (EPSS scores, exploit availability, threat actor context, IOC correlation).
- **Collaboration** -- Single-tenant with basic `assignedTo` field. No real-time collaboration, no project/engagement model for consulting teams, no client-facing portals.

Integrating with mature open-source platforms fills these gaps without rebuilding years of specialized work. This document analyzes the most impactful integrations, how they connect technically, and a prioritized roadmap.

---

## 2. Finding and Vulnerability Management

### 2.1 DefectDojo

**Repository:** https://github.com/DefectDojo/django-DefectDojo
**License:** BSD-3-Clause
**Stars:** 3,800+ | **Contributors:** 400+

#### What it is

DefectDojo is the leading open-source vulnerability management platform. It provides a complete vulnerability lifecycle: import findings from 150+ scanners, deduplicate across tools, track remediation SLAs, generate compliance reports, and integrate natively with Jira, Slack, GitHub, and more.

#### What it adds that Heroes does not have today

| Capability | Heroes Today | With DefectDojo |
|-----------|-------------|-----------------|
| Deduplication | `externalId + targetId` or `type + title + targetId` | Hash-based dedup across 150+ scanner formats, configurable dedup algorithms |
| Scanner support | 11 internal tools | Import from any of 150+ scanners (Burp, Qualys, Snyk, etc.) |
| Engagement model | None -- scans are flat | Product > Engagement > Test > Finding hierarchy for consulting |
| SLA tracking | None | Configurable SLA per severity, overdue alerts, SLA breach reports |
| Compliance | None | ASVS, NIST, PCI-DSS mapping built-in |
| JIRA sync | One-way (Heroes creates issues) | Bidirectional -- status syncs back when Jira ticket is closed |
| Risk scoring | CVSS from scanner output only | Risk acceptance workflow, custom risk ratings, business criticality |
| Reporting | CSV/JSON export | PDF/HTML reports, executive summaries, compliance dashboards |
| Multi-tenancy | Organization model (basic) | Full multi-tenant with product types, RBAC per product |

#### Integration approaches

**Option A: One-way export (Heroes scans, DefectDojo stores)**

Heroes pushes scan results to DefectDojo after each scan completes. DefectDojo becomes the vulnerability management backend. Heroes remains the scanning UI.

```
Heroes SecurityService.executeTool()
  -> scan completes
  -> FindingsService.persistFromScan() [local DB, as today]
  -> DefectDojoExporter.pushScanResults() [new]
       POST /api/v2/import-scan/
       {
         product_name: target.name,
         engagement_name: `heroes-${scanId}`,
         scan_type: "Generic Findings Import",
         file: findings-in-defectdojo-format.json
       }
```

Key API endpoints:
- `POST /api/v2/import-scan/` -- import scan results (supports generic JSON, nuclei native format, and many others)
- `POST /api/v2/reimport-scan/` -- re-import to existing test (triggers dedup)
- `GET /api/v2/findings/?product_name=X` -- query findings
- `GET /api/v2/products/` -- list products (maps to Heroes Targets)
- `GET /api/v2/engagements/` -- list engagements (maps to scan sessions)

Implementation: Create a `DefectDojoClient` service (HTTP API client pattern, similar to MobsfRunner). Add a config flag `DEFECTDOJO_ENABLED=true`, `DEFECTDOJO_URL`, `DEFECTDOJO_API_KEY`.

**Effort:** 3-5 days. DefectDojo natively accepts nuclei JSON output, so the format conversion is minimal.

**Option B: DefectDojo as primary backend (replace Heroes Finding model)**

Heroes stops storing findings in its own DB. All finding queries go through DefectDojo API. The Heroes Finding table becomes a cache/mirror.

**Effort:** 2-3 weeks. Requires rewriting FindingsService, findings controller, dashboard stats queries. Not recommended for MVP -- too much coupling.

**Option C: Bidirectional sync**

Heroes pushes scans to DefectDojo. A background job polls DefectDojo for status changes (analyst marks finding as false_positive in DefectDojo, Heroes mirrors it). DefectDojo is the source of truth for finding status; Heroes is the source of truth for scan execution.

```
Heroes -> DefectDojo: POST /api/v2/import-scan/ (after scan)
DefectDojo -> Heroes: Webhook or poll GET /api/v2/findings/?has_been_updated_since=X
```

**Effort:** 1-2 weeks. Recommended as Phase 2 evolution of Option A.

#### Recommendation

Start with **Option A** (one-way export). It gives immediate access to DefectDojo's reporting, dedup, and Jira sync without changing Heroes' core data flow. Evolve to Option C when teams need to triage in DefectDojo and see results in Heroes.

---

### 2.2 Faraday

**Repository:** https://github.com/infobyte/faraday
**License:** GPL-3.0
**Stars:** 5,000+

#### What it is

Faraday is a collaborative penetration testing and vulnerability management platform. It focuses on real-time multi-user collaboration during engagements, with a workspace concept that groups targets, hosts, services, and vulnerabilities.

#### What it adds

- **Real-time collaboration** -- Multiple pentesters see each other's findings live. Heroes has no real-time collaboration concept.
- **Workspace model** -- Maps naturally to pentest engagements/projects. Heroes has no project/engagement grouping.
- **Plugin ecosystem** -- 80+ tool plugins that normalize output. Many overlap with Heroes' tools but add tools Heroes does not have (Burp, Metasploit, OpenVAS).
- **Host/service/vulnerability hierarchy** -- Richer data model than Heroes' flat `Target > Finding` relationship.

#### Integration approach

Faraday exposes a REST API (`/v3/ws/{workspace}/vulns/`, `/v3/ws/{workspace}/hosts/`). Heroes could push findings to a Faraday workspace after scans, similar to the DefectDojo approach.

However, Faraday's primary value is real-time collaboration during manual pentests. Since Heroes is AI-driven (not manual), the collaboration features are less relevant.

**Effort:** 3-5 days for one-way export.

#### Recommendation

Lower priority than DefectDojo. Consider only if the team does manual pentesting alongside AI-driven scans and needs a shared workspace. DefectDojo covers vulnerability management better for an automated platform.

---

## 3. Extended Scanning

### 3.1 OWASP ZAP

**Repository:** https://github.com/zaproxy/zaproxy
**License:** Apache-2.0
**Stars:** 13,000+

#### What it is

ZAP (Zed Attack Proxy) is the world's most widely used DAST (Dynamic Application Security Testing) tool. It acts as an intercepting proxy that crawls web applications with a real browser engine, then actively tests for vulnerabilities by injecting payloads in the context of authenticated sessions.

#### What it adds that Heroes does not have

| Capability | Heroes Today | With ZAP |
|-----------|-------------|----------|
| Crawling | katana (HTTP-based, no JS rendering) | Spider + Ajax Spider (full browser rendering, SPA support) |
| Authenticated scanning | None -- all scans are unauthenticated | Session management, form-based auth, OAuth, header-based auth |
| Active injection | sqlmap (SQLi only), dalfox (XSS only) | 50+ active scan rules covering SQLi, XSS, SSRF, path traversal, LDAP injection, OS command injection, etc. |
| Session handling | None | Cookie/token management, CSRF token handling, session detection |
| API scanning | nuclei templates (pattern matching) | OpenAPI/Swagger import, GraphQL scanning, SOAP testing |
| Passive analysis | httpx headers only | 40+ passive rules (CSP issues, cookie flags, information disclosure, etc.) |

ZAP fills the biggest gap in Heroes: **authenticated DAST with browser context**. Nuclei is template-based (it matches known patterns), while ZAP actively probes for unknown vulnerabilities by fuzzing with context awareness.

#### Integration approach

ZAP runs as a daemon with a REST API (default port 8080). It can run headless in Docker -- perfect for the DockerExecutor pattern or as a persistent service.

**Pattern: API Client (like MobSF)**

```typescript
// New: ZapRunner (similar to MobsfRunner)
class ZapRunner {
    constructor(private config: { host: string; apiKey: string }) {}

    async spiderScan(target: string, opts?: { contextName?: string; maxChildren?: number }): Promise<ScanResult> {
        // POST /JSON/spider/action/scan/
        // Poll GET /JSON/spider/view/status/ until complete
        // GET /JSON/spider/view/results/ for discovered URLs
    }

    async activeScan(target: string, opts?: { policy?: string; contextId?: number }): Promise<ScanResult> {
        // POST /JSON/ascan/action/scan/
        // Poll GET /JSON/ascan/view/status/ until complete
        // GET /JSON/core/view/alerts/ for findings
    }

    async importContext(contextFile: string): Promise<void> {
        // Import authentication config, session management, excluded URLs
    }
}
```

Key ZAP API endpoints:
- `POST /JSON/spider/action/scan/` -- start spider crawl
- `POST /JSON/ascan/action/scan/` -- start active scan
- `GET /JSON/core/view/alerts/` -- get findings (maps to Heroes Finding)
- `POST /JSON/context/action/importContext/` -- import scan context with auth
- `GET /JSON/core/view/urls/` -- list discovered URLs

**New tool definition:**
```typescript
{
    name: 'security_dast_scan',
    description: 'Dynamic Application Security Testing with browser-based crawling, authenticated scanning, and active vulnerability injection testing.',
    inputSchema: {
        type: 'object',
        properties: {
            target_url: { type: 'string' },
            auth_config: { type: 'object', description: 'Optional: { type: "form"|"header"|"oauth", credentials: {...} }' },
            scan_policy: { type: 'string', enum: ['quick', 'standard', 'full'] }
        },
        required: ['target_url']
    }
}
```

**New pipeline: DastPipeline**
1. ZAP Spider (discover endpoints)
2. ZAP Ajax Spider (discover JS-rendered endpoints)
3. ZAP Active Scan (test all discovered endpoints)
4. Normalize ZAP alerts to Heroes Finding format

**Deployment:** Add to `docker/security/docker-compose.yml`:
```yaml
zap:
  image: ghcr.io/zaproxy/zaproxy:stable
  command: zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=YOUR_KEY -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
  ports:
    - "8090:8080"
```

**Effort:** 5-7 days. ZAP API is well-documented. The main complexity is mapping ZAP alert confidence/risk to Heroes severity and handling long-running scans (ZAP active scans can take 30-60 minutes).

---

### 3.2 OpenVAS / Greenbone

**Repository:** https://github.com/greenbone
**License:** AGPL-3.0
**Stars:** 8,000+ (across repos)

#### What it is

OpenVAS (Open Vulnerability Assessment Scanner), now part of Greenbone Community Edition, is an enterprise-grade network vulnerability scanner. It maintains 80,000+ Network Vulnerability Tests (NVTs) -- far more comprehensive than nmap scripts or nuclei network templates.

#### What it adds

| Capability | Heroes Today | With OpenVAS |
|-----------|-------------|-------------|
| Network vuln tests | nmap scripts (~600) + nuclei network templates (~500) | 80,000+ NVTs, updated daily |
| Compliance scanning | None | CIS benchmarks, PCI-DSS, DISA STIG built-in |
| Authenticated scanning | None (network) | SSH/SMB/WMI credential scanning for patch-level checks |
| SCAP/OVAL | None | Full SCAP integration for compliance |
| CVE coverage | Nuclei templates (community-driven) | Direct CVE-to-NVT mapping, comprehensive coverage |

OpenVAS dramatically deepens network scanning. Where nmap + nuclei might find 20 issues on a network, OpenVAS finds 200 -- including missing patches, weak configurations, and compliance violations.

#### Integration approach

Greenbone Vulnerability Manager (GVM) exposes a REST API (via `gvmd` or the Greenbone Management Protocol over TLS). The newer Greenbone Community Edition also has a REST API.

**Pattern: API Client + Docker Service**

```typescript
class OpenVasRunner {
    constructor(private config: { host: string; username: string; password: string }) {}

    async createTarget(name: string, hosts: string): Promise<string> {
        // POST /api/targets/ -- returns target_id
    }

    async createTask(targetId: string, configId: string): Promise<string> {
        // POST /api/tasks/ -- returns task_id
        // configId maps to scan configs: "Full and fast", "Full and deep", etc.
    }

    async startTask(taskId: string): Promise<void> {
        // POST /api/tasks/{id}/start
    }

    async getReport(taskId: string): Promise<ScanResult> {
        // GET /api/tasks/{id} -- poll until status="Done"
        // GET /api/reports/{id}?report_format=json
        // Normalize to Heroes Finding format
    }
}
```

**Deployment:** Greenbone Community Edition Docker setup is substantial (postgres, gvmd, ospd-openvas, redis, notus-scanner). Best run on a dedicated VM, not alongside the main Heroes stack.

```yaml
# Separate docker-compose for Greenbone
# See: https://greenbone.github.io/docs/latest/22.4/container/
services:
  vulnerability-tests:
    image: greenbone/vulnerability-tests
  notus-data:
    image: greenbone/notus-data
  gvmd:
    image: greenbone/gvmd
  # ... 8+ containers total
```

**Effort:** 2-3 weeks. The GVM API is complex, scans are very long-running (hours for full network scans), and deployment requires a dedicated VM. High value but high effort.

---

### 3.3 Trivy

**Repository:** https://github.com/aquasecurity/trivy
**License:** Apache-2.0
**Stars:** 24,000+

#### What it is

Trivy is a comprehensive security scanner for containers, IaC (Infrastructure as Code), SBOM (Software Bill of Materials), Kubernetes, and filesystem/repository scanning. It is the most popular open-source scanner in the cloud-native security space.

#### What it adds

| Capability | Heroes Today | With Trivy |
|-----------|-------------|-----------|
| Container scanning | None | Image vulnerabilities, misconfigs, secrets, licenses |
| IaC scanning | None | Terraform, CloudFormation, Kubernetes YAML, Dockerfile |
| SBOM | None | CycloneDX/SPDX generation, dependency vulnerability analysis |
| Kubernetes | None | Cluster scanning, RBAC analysis, network policies |
| Supply chain | APKLeaks (mobile only) | Full dependency tree analysis for any language ecosystem |

Trivy opens an entirely new scanning domain: **supply chain and infrastructure security**. Heroes currently focuses on runtime/network; Trivy covers the build and deploy pipeline.

#### Integration approach

**Pattern: Binary Runner (like nuclei) -- Camada 1**

Trivy is a single static Go binary. It fits perfectly into the ProcessExecutor pattern already used for nuclei, httpx, etc.

```typescript
class TrivyRunner {
    constructor(private executor: ProcessExecutor) {}

    async scanImage(image: string): Promise<ScanResult> {
        // trivy image --format json --severity CRITICAL,HIGH,MEDIUM image:tag
        const result = await this.executor.run('trivy', [
            'image', '--format', 'json', '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
            image
        ])
        return this.normalize(JSON.parse(result.stdout))
    }

    async scanFilesystem(path: string): Promise<ScanResult> {
        // trivy fs --format json --scanners vuln,secret,misconfig path
        const result = await this.executor.run('trivy', [
            'fs', '--format', 'json', '--scanners', 'vuln,secret,misconfig',
            path
        ])
        return this.normalize(JSON.parse(result.stdout))
    }

    async scanIaC(path: string): Promise<ScanResult> {
        // trivy config --format json path
        const result = await this.executor.run('trivy', [
            'config', '--format', 'json', path
        ])
        return this.normalize(JSON.parse(result.stdout))
    }

    async generateSBOM(image: string): Promise<string> {
        // trivy image --format cyclonedx image:tag
        const result = await this.executor.run('trivy', [
            'image', '--format', 'cyclonedx', image
        ])
        return result.stdout
    }
}
```

**New tool definitions:**
```typescript
{
    name: 'security_container_scan',
    description: 'Scan container images for OS/library vulnerabilities, misconfigurations, and embedded secrets.',
    inputSchema: {
        type: 'object',
        properties: {
            image: { type: 'string', description: 'Docker image (e.g., nginx:latest, ghcr.io/org/app:v1.2)' },
            severity: { type: 'string', description: 'Filter: CRITICAL,HIGH,MEDIUM,LOW (default: all)' }
        },
        required: ['image']
    }
},
{
    name: 'security_iac_scan',
    description: 'Scan Infrastructure-as-Code files (Terraform, CloudFormation, Kubernetes YAML, Dockerfiles) for misconfigurations and security issues.',
    inputSchema: {
        type: 'object',
        properties: {
            path: { type: 'string', description: 'Path to IaC files or directory' }
        },
        required: ['path']
    }
}
```

**Dockerfile addition:**
```dockerfile
# Add to existing Dockerfile alongside nuclei, httpx, etc.
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

**Effort:** 3-4 days. Trivy outputs clean JSON, is a single binary, and follows the exact same pattern as nuclei. The lowest-effort integration in this document.

---

### 3.4 Semgrep

**Repository:** https://github.com/semgrep/semgrep
**License:** LGPL-2.1
**Stars:** 11,000+

#### What it is

Semgrep is a fast, open-source SAST (Static Application Security Testing) engine. It analyzes source code for security vulnerabilities, bugs, and anti-patterns using a pattern-matching syntax that is more intuitive than traditional AST-based tools.

#### What it adds

| Capability | Heroes Today | With Semgrep |
|-----------|-------------|-------------|
| Source code analysis | None -- all scanning is runtime/network | Multi-language SAST (Python, JS/TS, Java, Go, Ruby, PHP, C#, etc.) |
| Custom rules | Nuclei templates (network) | Semgrep rules (code patterns) -- easy to write org-specific rules |
| Taint tracking | None | Data flow analysis for injection vulnerabilities |
| Secrets in code | None | Regex + entropy-based secret detection in source |
| OWASP coverage | Runtime detection only | Code-level detection of OWASP Top 10 (hardcoded creds, insecure deserialization, etc.) |

Semgrep fills the **SAST gap**. Heroes only finds vulnerabilities at runtime (deployed apps, network services). Semgrep finds them in the source code before deployment -- catching issues like hardcoded credentials, insecure crypto usage, SQL concatenation, and SSRF patterns.

#### Integration approach

**Pattern: Binary Runner (Camada 1)**

Semgrep is a Python package but also available as a standalone binary. It outputs JSON and fits the ProcessExecutor pattern.

```typescript
class SemgrepRunner {
    constructor(private executor: ProcessExecutor) {}

    async scan(targetPath: string, opts?: { config?: string; severity?: string }): Promise<ScanResult> {
        const args = [
            'scan', '--json',
            '--config', opts?.config ?? 'p/security-audit',  // curated ruleset
            targetPath
        ]
        if (opts?.severity) {
            args.push('--severity', opts.severity)
        }
        const result = await this.executor.run('semgrep', args, { timeout: 600_000 })
        return this.normalize(JSON.parse(result.stdout))
    }
}
```

Built-in rulesets relevant to Heroes:
- `p/security-audit` -- comprehensive security rules
- `p/owasp-top-ten` -- OWASP Top 10 code patterns
- `p/secrets` -- hardcoded secrets and credentials
- `p/ci` -- CI/CD-optimized ruleset

**New tool definition:**
```typescript
{
    name: 'security_sast_scan',
    description: 'Static Application Security Testing -- analyze source code for vulnerabilities, insecure patterns, and hardcoded secrets. Supports 30+ languages.',
    inputSchema: {
        type: 'object',
        properties: {
            path: { type: 'string', description: 'Path to source code directory or repository' },
            ruleset: { type: 'string', description: 'Ruleset: security-audit (default), owasp-top-ten, secrets, or custom path' },
            language: { type: 'string', description: 'Filter by language (e.g., python, javascript, java)' }
        },
        required: ['path']
    }
}
```

**Effort:** 3-4 days. Clean JSON output, well-documented. The complexity is in handling large repositories (Semgrep can be slow on monorepos) and mapping Semgrep rule metadata to Heroes Finding fields.

---

### 3.5 Gitleaks

**Repository:** https://github.com/gitleaks/gitleaks
**License:** MIT
**Stars:** 18,000+

#### What it is

Gitleaks scans git repositories for hardcoded secrets (API keys, passwords, tokens, private keys) by analyzing the entire commit history. It catches secrets that were committed and then "removed" -- they still exist in git history.

#### What it adds

| Capability | Heroes Today | With Gitleaks |
|-----------|-------------|-------------|
| Git history scanning | None | Full commit history analysis for leaked secrets |
| Secret detection | APKLeaks (mobile APKs only) | Git repos, any language, any file type |
| Pre-commit hook | None | Prevent secrets from being committed |
| Baseline support | None | `.gitleaksignore` for known/accepted secrets |
| Custom patterns | None | Regex-based custom secret patterns |

Gitleaks complements APKLeaks (which only scans compiled Android APKs). Together they cover secrets in both source repositories and compiled artifacts.

#### Integration approach

**Pattern: Binary Runner (Camada 1)**

Gitleaks is a single static Go binary -- identical pattern to nuclei.

```typescript
class GitleaksRunner {
    constructor(private executor: ProcessExecutor) {}

    async scanRepo(repoPath: string): Promise<ScanResult> {
        // gitleaks detect --source /path/to/repo --report-format json --report-path /tmp/report.json
        const reportPath = `/tmp/gitleaks-${Date.now()}.json`
        const result = await this.executor.run('gitleaks', [
            'detect', '--source', repoPath,
            '--report-format', 'json',
            '--report-path', reportPath
        ])
        // Gitleaks exits with code 1 when leaks found (not an error)
        const report = JSON.parse(await fs.readFile(reportPath, 'utf-8'))
        return this.normalize(report)
    }
}
```

**New tool definition:**
```typescript
{
    name: 'security_secret_scan',
    description: 'Scan git repositories for leaked secrets (API keys, passwords, tokens, private keys) across the full commit history.',
    inputSchema: {
        type: 'object',
        properties: {
            repo_path: { type: 'string', description: 'Path to cloned git repository' },
            repo_url: { type: 'string', description: 'Git URL to clone and scan (alternative to repo_path)' }
        },
        required: []
    }
}
```

**Dockerfile addition:**
```dockerfile
RUN curl -sfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_arm64.tar.gz | tar xz -C /usr/local/bin gitleaks
```

**Effort:** 2-3 days. Simplest integration -- single binary, clean JSON output, straightforward mapping.

---

## 4. Reporting and Compliance

### 4.1 Pentest Report Generation

Heroes currently exports findings as CSV/JSON. For a security platform, PDF/HTML pentest reports are essential -- they are the deliverable clients pay for.

#### Open-source options

**WeasyPrint** (https://github.com/Moi/WeasyPrint)
- Python library that converts HTML/CSS to PDF
- Approach: Create Jinja2/Handlebars templates for pentest reports, render to HTML, convert to PDF
- Heroes could generate reports server-side via a report generation service

**Pandoc + LaTeX**
- Markdown-to-PDF pipeline
- Approach: Generate Markdown report from findings, convert via Pandoc
- More complex but produces higher-quality PDFs

**Recommended approach for Heroes:**

Create a `ReportService` that:
1. Queries findings for a target/engagement
2. Aggregates statistics (severity distribution, OWASP breakdown, timeline)
3. Renders an HTML template with findings, executive summary, methodology, and remediation priorities
4. Converts to PDF via a headless Chrome/Puppeteer or WeasyPrint
5. Exposes via `GET /api/security/reports/:targetId?format=pdf|html`

This is not strictly an "integration" but rather a feature built on top of existing data. Listed here because open-source report templates from DefectDojo and Faraday can be adapted.

**Effort:** 5-7 days for a basic report template. Phase 2 priority.

### 4.2 OpenSCAP / CIS Benchmarks

**Repository:** https://github.com/OpenSCAP/openscap
**License:** LGPL-2.1

#### What it is

OpenSCAP is the reference implementation of SCAP (Security Content Automation Protocol). It evaluates systems against CIS Benchmarks, DISA STIGs, and PCI-DSS controls.

#### What it adds

- **Compliance scanning** -- Evaluate servers/containers against specific compliance frameworks
- **CIS Benchmarks** -- Hardening checks for Linux, Docker, Kubernetes, cloud platforms
- **Machine-readable results** -- XCCDF/ARF output that feeds into compliance dashboards

#### Integration approach

OpenSCAP requires agent-based scanning (runs on the target system). This is architecturally different from Heroes' remote scanning model. Best integrated via:
1. Deploy `oscap` on target systems
2. Heroes triggers scans via SSH and collects results
3. Parse XCCDF results into Heroes Finding format

**Effort:** 2-3 weeks. Requires agent deployment model that Heroes does not have today. Phase 3.

---

## 5. Threat Intelligence

### 5.1 MISP

**Repository:** https://github.com/MISP/MISP
**License:** AGPL-3.0
**Stars:** 5,500+

#### What it is

MISP (Malware Information Sharing Platform) is the de facto standard for threat intelligence sharing. Organizations use it to share, store, and correlate Indicators of Compromise (IOCs), malware samples, and attack patterns.

#### What it adds

| Capability | Heroes Today | With MISP |
|-----------|-------------|----------|
| IOC enrichment | None | Correlate finding IPs/domains with known threat intel |
| CVE context | CVE ID from scanner output | Full CVE details, exploit availability, affected products |
| Threat attribution | None | Link findings to known threat actors/campaigns |
| IOC sharing | None | Share/receive IOCs with industry peers |
| EPSS scores | None | Exploit Prediction Scoring for prioritization |

#### Integration approach

**Pattern: API Client (enrichment service)**

MISP has a comprehensive REST API. Heroes integrates as a consumer -- enriching findings with threat context after scans complete.

```typescript
class MispEnricher {
    constructor(private config: { host: string; apiKey: string }) {}

    async enrichFinding(finding: Finding): Promise<EnrichedFinding> {
        const enrichments = {}

        // Check if any IPs/domains in finding are known IOCs
        if (finding.metadata?.ip) {
            const iocResult = await this.searchAttribute(finding.metadata.ip, 'ip-dst')
            enrichments.iocMatch = iocResult.response?.Attribute?.length > 0
            enrichments.threatEvents = iocResult.response?.Attribute?.map(a => a.Event)
        }

        // Enrich CVE with threat intel
        if (finding.cve) {
            const cveResult = await this.searchAttribute(finding.cve, 'vulnerability')
            enrichments.exploitAvailable = cveResult.response?.Attribute?.some(a =>
                a.Tag?.some(t => t.name.includes('exploit'))
            )
        }

        return { ...finding, enrichments }
    }

    private async searchAttribute(value: string, type: string) {
        // POST /attributes/restSearch { value, type_attribute: type }
    }
}
```

This enrichment would run as a post-processing step after `FindingsService.persistFromScan()`, adding threat context to findings before they are displayed in the UI.

**Effort:** 3-5 days for basic IOC/CVE enrichment. MISP deployment itself is complex (requires its own stack), but many organizations already run MISP instances. Heroes connects to an existing deployment.

### 5.2 Nuclei Templates -- Advanced Usage

Heroes already uses nuclei with community templates. Here is how to deepen that integration:

#### Custom template repositories

```typescript
// In NucleiRunner, support custom template sources
async updateTemplates(sources?: string[]): Promise<void> {
    // Default: nuclei -update-templates (official community)
    await this.executor.run('nuclei', ['-update-templates'])

    // Custom repos: nuclei -t /path/to/custom-templates/
    // Clone org-specific template repos to a known path
    for (const repo of sources ?? []) {
        await this.executor.run('git', ['clone', '--depth', '1', repo, `/opt/nuclei-templates-custom/${repoName}`])
    }
}
```

#### Auto-update schedule

Add a `Schedule` that runs `nuclei -update-templates` daily. This ensures Heroes always has the latest vulnerability checks.

#### Organization-specific templates

Allow organizations to create custom nuclei templates via the Heroes UI:
1. Template editor (YAML) in Settings
2. Store in DB or mounted volume
3. Pass to nuclei via `-t /custom/templates/` flag

**Effort:** 2-3 days for custom template support, 1 day for auto-update scheduling.

---

## 6. Integration Priority Matrix

| Platform | Value Add | Effort | Priority | Category | Recommendation |
|----------|:---------:|:------:|:--------:|----------|---------------|
| **Trivy** | 5 | 1 | **P1** | Scanning | Single binary, new scanning domain (containers/IaC), minimal effort |
| **Gitleaks** | 4 | 1 | **P1** | Scanning | Single binary, fills secret detection gap, 2-3 days |
| **DefectDojo** | 5 | 2 | **P1** | Management | Solves reporting, dedup, compliance in one shot |
| **OWASP ZAP** | 5 | 3 | **P2** | Scanning | Fills the biggest scanning gap (authenticated DAST) |
| **Semgrep** | 4 | 2 | **P2** | Scanning | SAST coverage, new scanning domain |
| **Nuclei Templates (advanced)** | 3 | 1 | **P2** | Scanning | Already integrated, just needs custom repo support |
| **MISP** | 3 | 3 | **P3** | Intelligence | High value for mature teams, requires MISP deployment |
| **OpenVAS** | 4 | 4 | **P3** | Scanning | Deep network scanning but complex deployment |
| **Report Generation** | 4 | 3 | **P2** | Reporting | Essential for consulting use case |
| **Faraday** | 3 | 2 | **P4** | Management | Overlaps with DefectDojo, better for manual pentest teams |
| **OpenSCAP** | 3 | 4 | **P4** | Compliance | Requires agent model Heroes does not have |

**Scoring:**
- **Value (1-5):** Impact on Heroes Security capability. 5 = opens entirely new domain or solves critical gap.
- **Effort (1-5):** Integration complexity. 1 = drop-in binary with JSON output, 5 = complex deployment + custom API + data model changes.
- **Priority:** P1 = do first, P4 = do last.

---

## 7. Recommended Integration Roadmap

### Phase 1: Quick Wins (2-3 weeks)

**Goal:** Expand scanning coverage with minimal effort. All three are single-binary integrations following the existing ProcessExecutor pattern.

| Integration | Days | What it unlocks |
|------------|------|----------------|
| Trivy | 3-4 | Container image scanning, IaC misconfig detection, SBOM generation |
| Gitleaks | 2-3 | Git repository secret scanning across full commit history |
| DefectDojo (Option A) | 3-5 | Export findings to DefectDojo for reporting, dedup, Jira sync |

**After Phase 1, Heroes has:**
- 13 tool runners (up from 11)
- 3 new scanning domains: container security, IaC security, secret detection
- External vulnerability management platform for professional reporting
- Tool count in README: "11 security tools" becomes "13 security tools + DefectDojo integration"

**New Heroes capability:**
- Guardian gains container and IaC scanning powers
- Watcher can monitor container images for new CVEs (schedule `trivy image` scans)

### Phase 2: Core Platform (4-6 weeks)

**Goal:** Fill the two biggest remaining gaps -- authenticated web scanning (ZAP) and source code analysis (Semgrep). Plus report generation for the consulting use case.

| Integration | Days | What it unlocks |
|------------|------|----------------|
| OWASP ZAP | 5-7 | Authenticated DAST, browser-based crawling, active injection |
| Semgrep | 3-4 | SAST for 30+ languages, code-level vulnerability detection |
| Report Generation | 5-7 | PDF/HTML pentest reports from Finding data |
| Nuclei custom templates | 2-3 | Org-specific vulnerability checks, auto-updates |

**After Phase 2, Heroes has:**
- 15 tool runners
- Full DAST + SAST coverage (the two industry-standard scanning categories Heroes was missing)
- Professional report generation
- Scanning coverage: network, web (template + DAST), mobile, container, IaC, source code, secrets

**New Heroes:**
- Consider a 5th Hero: **Auditor** -- Code Security Analyst specializing in SAST + secret scanning for repository assessments

### Phase 3: Enterprise (6-8 weeks)

**Goal:** Threat intelligence enrichment, deep network scanning, and compliance frameworks. These require more infrastructure and are relevant for enterprise/regulated customers.

| Integration | Days | What it unlocks |
|------------|------|----------------|
| MISP | 3-5 | Threat intel enrichment, IOC correlation, EPSS scores |
| OpenVAS | 10-15 | 80,000+ NVTs, compliance scanning (PCI-DSS, CIS) |
| DefectDojo (Option C) | 5-7 | Bidirectional sync, DefectDojo as source of truth for finding status |
| OpenSCAP | 10-15 | CIS Benchmark compliance scanning |

**After Phase 3, Heroes has:**
- Enterprise-grade vulnerability and compliance platform
- Threat-intel-enriched findings with prioritization based on exploit availability
- Compliance scanning and reporting for regulated industries

---

## 8. Technical Integration Patterns

Heroes uses four patterns for integrating external tools. New integrations should follow the pattern that matches the tool's architecture.

### Pattern 1: Binary Runner (ProcessExecutor)

**Used by:** nuclei, httpx, katana, subfinder, dalfox
**New candidates:** Trivy, Gitleaks, Semgrep

**How it works:**
- Static binary installed in the Docker image (Dockerfile `RUN curl ... | tar xz`)
- Executed via `ProcessExecutor.run(binary, args)` which wraps `execFile()`
- No shell -- no command injection risk
- JSON output parsed and normalized to `ScanResult`

**When to use:** Tool is a standalone binary (especially Go binaries), outputs JSON/structured data, runs as a one-shot process (start, scan, exit).

**Template:**
```typescript
class NewToolRunner {
    constructor(private executor: ProcessExecutor) {}

    async run(target: string, opts?: ToolOptions): Promise<ScanResult> {
        const args = this.buildArgs(target, opts)
        const result = await this.executor.run('tool-binary', args, {
            timeout: 300_000,  // 5 min default
            maxBuffer: 50 * 1024 * 1024  // 50 MB
        })

        if (result.exitCode !== 0 && !this.isExpectedNonZero(result.exitCode)) {
            return { tool: 'tool-name', status: 'error', findings: [], rawOutput: result.stderr, executionTimeMs: result.durationMs, error: result.stderr }
        }

        const findings = this.parseOutput(result.stdout)
        return { tool: 'tool-name', status: 'success', findings, rawOutput: result.stdout, executionTimeMs: result.durationMs }
    }

    private parseOutput(stdout: string): Finding[] {
        const raw = JSON.parse(stdout)
        return raw.map(item => ({
            id: item.id ?? crypto.randomUUID(),
            tool: 'tool-name',
            type: this.mapType(item),
            severity: this.mapSeverity(item),
            title: item.title,
            description: item.description,
            evidence: item.evidence ?? '',
            remediation: item.remediation ?? '',
            target: item.target,
            metadata: item
        }))
    }
}
```

**Checklist for new Binary Runner:**
- [ ] Add binary download to Dockerfile
- [ ] Create `runners/new-tool-runner.ts` following the template above
- [ ] Add tool definition to `SecurityService.getToolDefinitions()`
- [ ] Add `case 'security_new_tool':` to `SecurityService.executeTool()`
- [ ] Add binary availability check to `SecurityService.healthCheck()` (optional)
- [ ] Create pipeline if tool is part of a multi-step scan (optional)

### Pattern 2: API Client (HTTP service)

**Used by:** MobSF
**New candidates:** OWASP ZAP, DefectDojo, MISP, OpenVAS

**How it works:**
- External service runs as a persistent process (Docker container or remote server)
- Heroes communicates via HTTP REST API
- Often requires polling for long-running scans (start scan, poll status, get results)
- Configuration: host URL + API key stored in environment variables

**When to use:** Tool runs as a server/daemon, exposes REST/GraphQL API, scans are long-running (minutes to hours), tool needs persistent state.

**Template:**
```typescript
class NewServiceClient {
    private baseUrl: string
    private apiKey: string

    constructor(config: { host: string; apiKey: string }) {
        this.baseUrl = config.host
        this.apiKey = config.apiKey
    }

    async startScan(target: string, opts?: ScanOptions): Promise<string> {
        const response = await fetch(`${this.baseUrl}/api/scan`, {
            method: 'POST',
            headers: {
                'Authorization': `Token ${this.apiKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target, ...opts })
        })
        const data = await response.json()
        return data.scanId
    }

    async pollUntilComplete(scanId: string, timeoutMs = 600_000): Promise<ScanResult> {
        const start = Date.now()
        while (Date.now() - start < timeoutMs) {
            const status = await this.getScanStatus(scanId)
            if (status.state === 'completed') {
                return this.getResults(scanId)
            }
            if (status.state === 'failed') {
                throw new Error(`Scan failed: ${status.error}`)
            }
            await new Promise(r => setTimeout(r, 5000))  // poll every 5s
        }
        throw new Error(`Scan timed out after ${timeoutMs}ms`)
    }

    async getResults(scanId: string): Promise<ScanResult> {
        const response = await fetch(`${this.baseUrl}/api/scan/${scanId}/results`, {
            headers: { 'Authorization': `Token ${this.apiKey}` }
        })
        const data = await response.json()
        return this.normalize(data)
    }
}
```

**Checklist for new API Client:**
- [ ] Add service to `docker/security/docker-compose.yml` (or document external deployment)
- [ ] Create `runners/new-service-runner.ts` with HTTP client
- [ ] Add config vars: `NEW_SERVICE_HOST`, `NEW_SERVICE_API_KEY`
- [ ] Handle polling/async for long-running scans
- [ ] Add tool definition and executeTool case
- [ ] Add health check (ping the service API)

### Pattern 3: Docker Service (persistent container)

**Used by:** MobSF (via docker-compose), nmap/sqlmap/hydra/nikto (via DockerExecutor)
**New candidates:** OWASP ZAP (daemon mode), OpenVAS (GVM stack)

**How it works:**
- Service runs in Docker alongside Heroes (or on a dedicated VM)
- Managed via `docker-compose` in `docker/security/`
- Heroes communicates via API Client pattern (Pattern 2) or DockerExecutor (ephemeral containers)

**When to use:** Tool requires persistent state, needs multiple processes, or has complex runtime dependencies that are not a single binary.

**Two sub-patterns:**

**(a) Persistent daemon** (MobSF, ZAP, OpenVAS): Runs continuously, Heroes talks to it via HTTP API. Use Pattern 2 for the client code.

**(b) Ephemeral container** (nmap, sqlmap): Heroes spawns a container per scan via DockerExecutor, waits for it to finish, collects output. Use for tools that need OS-level capabilities (raw sockets for nmap) or have complex dependencies.

### Pattern 4: Export/Import (data sync)

**Used by:** (new pattern)
**New candidates:** DefectDojo, Faraday, MISP (enrichment)

**How it works:**
- Heroes pushes data to an external platform after scans complete
- Optionally pulls data back (bidirectional sync)
- Runs as a post-processing step, not part of the scan pipeline

**When to use:** External platform is a management/reporting layer, not a scanner. Heroes owns scan execution; the external platform owns finding lifecycle, reporting, or enrichment.

**Template:**
```typescript
class ExternalPlatformSync {
    constructor(private client: ExternalPlatformClient) {}

    // Called after FindingsService.persistFromScan()
    async pushScanResults(scanId: string, findings: Finding[], target: Target): Promise<void> {
        // Map Heroes entities to external platform entities
        const externalProduct = await this.client.ensureProduct(target.name)
        const externalEngagement = await this.client.createEngagement(externalProduct.id, {
            name: `Heroes Scan ${scanId}`,
            targetStart: new Date()
        })
        await this.client.importFindings(externalEngagement.id, findings)
    }

    // Optional: pull status changes back
    async syncStatusChanges(since: Date): Promise<StatusUpdate[]> {
        const updated = await this.client.getUpdatedFindings(since)
        return updated.map(f => ({
            externalId: f.id,
            status: this.mapStatus(f.status),
            notes: f.notes
        }))
    }
}
```

**Checklist for new Export/Import:**
- [ ] Create sync service in `apps/api/src/security/integrations/`
- [ ] Add to `FindingsService.persistFromScan()` as optional post-step
- [ ] Add config flags (`PLATFORM_ENABLED`, `PLATFORM_URL`, `PLATFORM_API_KEY`)
- [ ] Handle failures gracefully (sync failure should not block scan results)
- [ ] Add background job for bidirectional sync (if needed)

---

## Appendix: Comparison with Heroes Current Scanning Coverage

```
                        Heroes Today          After Full Integration
                        ============          ======================
Web (template-based)    nuclei, nikto         nuclei, nikto
Web (DAST)              -                     OWASP ZAP
Web (XSS)               dalfox                dalfox, ZAP
Web (SQLi)              sqlmap                sqlmap, ZAP
Web (crawling)          katana, httpx         katana, httpx, ZAP Spider
Network scanning        nmap                  nmap, OpenVAS (80K+ NVTs)
Subdomain discovery     subfinder             subfinder
Mobile (Android)        MobSF, APKLeaks       MobSF, APKLeaks
Container security      -                     Trivy
IaC security            -                     Trivy
SBOM generation         -                     Trivy
SAST (source code)      -                     Semgrep
Secret detection        APKLeaks (mobile)     Gitleaks (git), Semgrep, Trivy
Compliance scanning     -                     OpenVAS, OpenSCAP
Threat intelligence     -                     MISP
Vuln management         Basic (Finding model) DefectDojo (150+ scanner import, dedup, SLA, reports)
Reporting               CSV/JSON export       PDF/HTML reports, DefectDojo dashboards
```

This progression takes Heroes from a scanning tool with 11 runners to a comprehensive security platform covering network, web, mobile, container, infrastructure, source code, and compliance -- with professional vulnerability management and reporting.
