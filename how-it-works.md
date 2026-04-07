# Heroes Security Platform -- Technical Documentation

## 1. Overview

Heroes Security is an integrated security scanning platform built into the Heroes AI agent system. It enables AI heroes (agents) to autonomously execute security scans against web applications, networks, and mobile apps, then persist, deduplicate, and manage the resulting findings.

The platform operates on **two execution layers**:

- **Camada 1 (Process Execution)**: Go binaries installed directly on the host. Used in production (Cloud Run) where no Docker socket is available. Tools: nuclei, httpx, katana, subfinder, dalfox.
- **Camada 2 (Docker Execution)**: Containerized tools run via the Docker socket. Used in local development or environments with Docker available. Tools: sqlmap, nmap, nikto, hydra, apkleaks.
- **API-based**: MobSF communicates via HTTP REST API to a running MobSF instance, using neither executor.

Security tools are exposed to heroes as **Powers** using the `internal://security` URL scheme, allowing them to be resolved and invoked through the same tool-resolution pipeline as MCP-based powers.

---

## 2. Execution Engines

### 2.1 ProcessExecutor

**File**: `apps/api/src/security/process-executor.ts`

ProcessExecutor wraps Node.js `child_process.execFile` (promisified) to run locally installed binaries.

**How it works**:
1. Calls `execFileAsync(binary, args, options)` with configurable timeout, maxBuffer, env, and cwd.
2. On success, returns `{ stdout, stderr, exitCode: 0, timedOut: false, executionTimeMs }`.
3. On error (non-zero exit or timeout), captures partial stdout/stderr from the error object.
4. Timeout detection: if `error.killed === true` and `error.signal === 'SIGTERM'`, the command timed out.

**Defaults**:
- `timeout`: 300,000 ms (5 minutes)
- `maxBuffer`: 10 MB (`10 * 1024 * 1024`)

**isAvailable check**: Runs `which <binary>` to determine if a binary exists on PATH. Returns `true` if the command succeeds, `false` otherwise.

**When used**: Camada 1 tools (nuclei, httpx, katana, subfinder, dalfox) in production on Cloud Run where binaries are installed in the Dockerfile. Also used locally if the binary is on PATH.

### 2.2 DockerExecutor

**File**: `apps/api/src/security/docker-executor.ts`

DockerExecutor uses the `dockerode` library to run tools in isolated containers via the Docker socket at `/var/run/docker.sock`.

**Container lifecycle**:
1. **Pull if needed**: Checks if the image exists locally via `docker.getImage(image).inspect()`. If not found, pulls it with `docker.pull()` and waits for completion via `followProgress`.
2. **Create container**: `docker.createContainer()` with:
   - `Image`, `Cmd`, `Tty: false`
   - Memory limit: default 512 MB (`512 * 1024 * 1024`)
   - CPU limit: default 1 CPU (`1_000_000_000` NanoCpus)
   - Tmpfs: `/tmp` mounted as `rw,noexec,nosuid,size=100m`
   - Network: configurable, default `bridge`
   - Volumes: host paths mounted as read-only (`:ro`)
   - WorkingDir: default `/scan`
   - `AutoRemove: false` (manual cleanup in finally block)
3. **Start**: `container.start()`
4. **Collect logs**: `container.logs({ follow: true, stdout: true, stderr: true })` with `demuxStream` to separate stdout/stderr.
5. **Timeout**: A `setTimeout` races against the log stream. If timeout fires first, the container is stopped with `container.stop({ t: 5 })` (5-second grace period).
6. **Inspect**: After completion, `container.inspect()` retrieves the exit code from `State.ExitCode`.
7. **Cleanup**: In the `finally` block, `container.remove({ force: true })` ensures the container is always removed, even on error.

**Default timeout**: 300,000 ms (5 minutes).

**healthCheck**: Calls `docker.ping()` to verify the Docker daemon is reachable.

**When used**: Camada 2 tools (sqlmap, nmap, nikto, hydra, apkleaks) and as a fallback in local development.

### 2.3 Auto-detection

`SecurityService` does not perform runtime auto-detection. Instead, the executor assignment is **hardcoded at construction time** in the constructor:

- **Camada 1 (ProcessExecutor)**: `nuclei`, `httpx`, `katana`, `subfinder`, `dalfox` -- all receive the `ProcessExecutor` instance.
- **Camada 2 (DockerExecutor)**: `sqlmap`, `nmap`, `nikto`, `hydra`, `apkleaks` -- all receive the `DockerExecutor` instance.
- **API-based**: `mobsf` -- receives configuration options (host, apiKey) and communicates via HTTP fetch.

Each runner's `run()` method uses `instanceof` to determine which executor API to call (`this.executor.run()` for ProcessExecutor, `this.executor.exec()` for DockerExecutor). Runners that only support one executor type (e.g., SqlmapRunner only accepts DockerExecutor) enforce this at the type level.

---

## 3. Security Tools -- Runner by Runner

### 3.1 Nuclei

**File**: `apps/api/src/security/runners/nuclei-runner.ts`

**Purpose**: Template-based vulnerability scanner with 6500+ community templates covering CVEs, misconfigurations, exposures, and default credentials.

**Executor**: ProcessExecutor (Camada 1) | **Binary**: `nuclei` | **Docker image**: `projectdiscovery/nuclei:latest`

**Command construction**:
```
nuclei -u <target> -jsonl -silent -no-color -rate-limit <100> -timeout <10>
  [-severity critical,high,medium]
  [-tags cve,rce,sqli]
  [-exclude-tags dos]
  [-t /path/to/templates]
```

| Flag | Purpose |
|------|---------|
| `-u` | Target URL |
| `-jsonl` | JSON Lines output format |
| `-silent` | Suppress banner and progress |
| `-no-color` | Disable ANSI colors |
| `-rate-limit` | Max requests/second (default: 100) |
| `-timeout` | Per-request timeout in seconds (default: 10) |
| `-severity` | Comma-separated severity filter |
| `-tags` | Comma-separated template tags |
| `-exclude-tags` | Tags to exclude |
| `-t` | Custom template path |

**Options** (`NucleiOptions`):
- `severity`: `Severity[]` -- filter templates by severity level
- `tags`: `string[]` -- filter by template tags
- `excludeTags`: `string[]` -- exclude template tags
- `templates`: `string` -- custom template path
- `rateLimit`: `number` -- max requests/sec (default 100)
- `requestTimeout`: `number` -- per-request timeout in seconds (default 10)
- `timeout`: `number` -- overall execution timeout in ms (default 600,000)

**Output parsing**: JSON Lines. Each line is parsed as JSON. Fields extracted:
- `id` from `template-id`
- `severity` from `info.severity`
- `title` from `info.name`
- `description` from `info.description`
- `evidence` assembled from `matched`, `extracted-results`, and `curl-command`
- `cve` from `info.classification.cve_id[0]`
- `cvss` from `info.classification.cvss_score`
- `remediation` from `info.remediation`

**Type inference**: Maps template tags to finding types:
- `sqli` -> `sqli`, `xss` -> `xss`, `ssrf` -> `ssrf`, `lfi` -> `lfi`, `rce` -> `rce`
- `cve` -> `cve`, `misconfig` -> `misconfig`, `exposure` -> `exposure`
- `default-login` -> `weak-credential`
- Fallback: `unknown`

**OWASP mapping**:
- Tags `sqli`, `xss`, `injection`, `cmdi` -> `A03:2021` (Injection)
- Tag `misconfig` -> `A05:2021` (Security Misconfiguration)
- Tags `auth`, `default-login` -> `A07:2021` (Identification and Authentication Failures)
- Tag `exposure` -> `A01:2021` (Broken Access Control)

**Example finding**:
```json
{
  "id": "cve-2021-44228",
  "tool": "nuclei",
  "type": "cve",
  "severity": "critical",
  "title": "Apache Log4j RCE (CVE-2021-44228)",
  "description": "Apache Log4j2 <=2.14.1 JNDI features...",
  "evidence": "Matched: https://example.com/api\nExtracted: ${jndi:ldap://...}",
  "remediation": "Upgrade to Log4j 2.17.0 or later.",
  "target": "https://example.com",
  "cve": "CVE-2021-44228",
  "cvss": 10.0,
  "owasp": "A03:2021"
}
```

---

### 3.2 httpx

**File**: `apps/api/src/security/runners/httpx-runner.ts`

**Purpose**: HTTP fingerprinting -- discovers technology stack, server headers, TLS configuration, status codes, CDN detection, and IP resolution.

**Executor**: ProcessExecutor (Camada 1) | **Binary**: `httpx` | **Docker image**: `projectdiscovery/httpx:latest`

**Command construction**:
```
httpx -u <target> -json -silent -tech-detect -status-code -title -server
  -tls-grab -content-length -content-type -method -websocket -ip -cname -cdn
  -threads <10> [-follow-redirects]
```

| Flag | Purpose |
|------|---------|
| `-u` | Target URL |
| `-json` | JSON output |
| `-silent` | Suppress progress |
| `-tech-detect` | Detect technologies (Wappalyzer) |
| `-status-code` | Include HTTP status code |
| `-title` | Extract page title |
| `-server` | Extract Server header |
| `-tls-grab` | Grab TLS certificate info |
| `-content-length` | Include Content-Length |
| `-content-type` | Include Content-Type |
| `-method` | Include HTTP method |
| `-websocket` | Detect WebSocket |
| `-ip` | Resolve IP address |
| `-cname` | Resolve CNAME records |
| `-cdn` | Detect CDN |
| `-threads` | Concurrency (default: 10) |
| `-follow-redirects` | Follow HTTP redirects (default: enabled) |

**Options** (`HttpxOptions`):
- `timeout`: `number` -- execution timeout (default 60,000 ms)
- `followRedirects`: `boolean` -- follow redirects (default true)
- `threads`: `number` -- concurrency (default 10)

**Output parsing**: JSON Lines. Produces findings of two types:

1. **`tech-fingerprint`** (severity: `info`): Always generated. Contains status code, title, server, technologies, content-type, CDN, IP, CNAME, and TLS data.
2. **`outdated-software`** (severity: `medium`): Generated when the Server header matches known outdated versions (Apache 2.2.x, nginx 1.0-1.8, IIS 6-8, OpenSSL 1.0).

**OWASP mapping**: Outdated software -> `A06:2021` (Vulnerable and Outdated Components).

**Example finding**:
```json
{
  "id": "httpx-fingerprint-example.com",
  "tool": "httpx",
  "type": "tech-fingerprint",
  "severity": "info",
  "title": "HTTP Fingerprint: https://example.com",
  "description": "Status: 200\nTitle: Example Domain\nServer: nginx/1.18.0\nTechnologies: jQuery, Bootstrap",
  "target": "https://example.com"
}
```

---

### 3.3 Katana

**File**: `apps/api/src/security/runners/katana-runner.ts`

**Purpose**: Web crawler and endpoint discovery. Crawls target URLs including JavaScript rendering to discover endpoints, parameters, and forms.

**Executor**: ProcessExecutor (Camada 1) | **Binary**: `katana` | **Docker image**: `projectdiscovery/katana:latest`

**Command construction**:
```
katana -u <target> -json -silent -depth <3> -js-crawl -known-files all
```

| Flag | Purpose |
|------|---------|
| `-u` | Target URL |
| `-json` | JSON output |
| `-silent` | Suppress progress |
| `-depth` | Crawl depth (default: 3) |
| `-js-crawl` | Enable JavaScript crawling |
| `-known-files all` | Check for known files (robots.txt, sitemap.xml, etc.) |

**Options** (`KatanaOptions`):
- `depth`: `number` -- crawl depth (default 3)
- `jsCrawl`: `boolean` -- enable JS crawling (always enabled via flag)
- `timeout`: `number` -- execution timeout (default 300,000 ms)

**Output parsing**: JSON Lines. Each line produces an `endpoint` finding (severity: `info`). Extracts:
- URL from `request.endpoint` / `endpoint` / `url`
- HTTP method from `request.method` / `method`
- Source page from `request.source` / `source`
- URL parameters via `URL.searchParams` or regex fallback

The finding `id` is generated from a hash of the endpoint URL to deduplicate.

**OWASP mapping**: None (informational findings).

**Example finding**:
```json
{
  "id": "katana-a1b2c3",
  "tool": "katana",
  "type": "endpoint",
  "severity": "info",
  "title": "Discovered endpoint: GET https://example.com/api/users?id=1",
  "description": "URL: https://example.com/api/users?id=1\nParameters: id",
  "target": "https://example.com/api/users?id=1"
}
```

---

### 3.4 Sqlmap

**File**: `apps/api/src/security/runners/sqlmap-runner.ts`

**Purpose**: Automated SQL injection detection and exploitation with proof-of-concept payloads and DBMS fingerprinting.

**Executor**: DockerExecutor (Camada 2) | **Docker image**: `paoloo/sqlmap:latest`

**Command construction**:
```
sqlmap -u <target> --batch --level=<3> --risk=<2> --forms --output-dir=/tmp/sqlmap
```

| Flag | Purpose |
|------|---------|
| `-u` | Target URL with parameters |
| `--batch` | Non-interactive mode (auto-accept defaults) |
| `--level` | Test level 1-5 (default: 3). Higher = more payload variations |
| `--risk` | Risk level 1-3 (default: 2). Higher = more aggressive payloads |
| `--forms` | Parse and test HTML forms |
| `--output-dir` | Output directory inside container |

**Options** (`SqlmapOptions`):
- `level`: `number` -- aggressiveness 1-5 (default 3)
- `risk`: `number` -- risk level 1-3 (default 2)
- `forms`: `boolean` -- test forms (always enabled)
- `timeout`: `number` -- execution timeout (default 600,000 ms)

**Output parsing**: Text-based (sqlmap outputs human-readable text, not JSON). The parser uses regex to extract:
- `Parameter: <name> (GET|POST|Cookie|Header)` -- identifies the vulnerable parameter
- `Type: <injection-type>` -- the injection technique (boolean-based blind, time-based blind, UNION query, etc.)
- `Payload: <payload>` -- the proof-of-concept payload
- `back-end DBMS: <name>` -- the identified database system

Each confirmed injection produces a `critical` severity finding. If no confirmed injections are found but heuristic indicators exist (e.g., "might be injectable", "possible DBMS"), a `high` severity finding is generated.

**Finding types**: `sqli`

**OWASP mapping**: `A03:2021` (Injection)

**Example finding**:
```json
{
  "id": "sqlmap-sqli-id-boolean-based-blind",
  "tool": "sqlmap",
  "type": "sqli",
  "severity": "critical",
  "title": "SQL Injection in parameter: id",
  "description": "Confirmed SQL injection vulnerability in parameter 'id'. Type: boolean-based blind. Backend DBMS: MySQL >= 5.0.",
  "evidence": "Parameter: id\nInjection type: boolean-based blind\nPayload: id=1 AND 1=1\nBackend DBMS: MySQL >= 5.0",
  "owasp": "A03:2021"
}
```

---

### 3.5 DalFox

**File**: `apps/api/src/security/runners/dalfox-runner.ts`

**Purpose**: Cross-Site Scripting (XSS) vulnerability scanner with payload generation, PoC URL output, and detection of reflected, stored, and DOM-based XSS.

**Executor**: ProcessExecutor (Camada 1) | **Binary**: `dalfox` | **Docker image**: `hahwul/dalfox:latest`

**Command construction**:
```
dalfox url <target> --silence --format json [--blind <callback>]
```

| Flag | Purpose |
|------|---------|
| `url` | Subcommand for URL mode |
| `--silence` | Suppress banner |
| `--format json` | JSON output |
| `--blind` | Blind XSS callback URL |

**Options** (`DalfoxOptions`):
- `timeout`: `number` -- execution timeout (default 300,000 ms)
- `blind`: `string` -- blind XSS callback URL

**Output parsing**: JSON (single object or array, or JSON Lines). Extracts:
- `param` / `parameter` -- vulnerable parameter
- `payload` / `evidence` -- XSS payload
- `poc_url` / `proof_url` / `url` -- proof-of-concept URL
- `type` / `inject_type` -- injection type (reflected, stored, dom)

**Severity mapping**:
- Stored/persistent XSS -> `critical`
- DOM-based XSS -> `high`
- Reflected XSS -> `high`

**Finding types**: `xss`

**OWASP mapping**: `A03:2021` (Injection)

**Example finding**:
```json
{
  "id": "dalfox-xss-q",
  "tool": "dalfox",
  "type": "xss",
  "severity": "high",
  "title": "Reflected XSS in parameter: q",
  "description": "Detected reflected Cross-Site Scripting (XSS) vulnerability. Vulnerable parameter: q.",
  "evidence": "Payload: <script>alert(1)</script>\nPoC URL: https://example.com/search?q=<script>alert(1)</script>\nParameter: q",
  "owasp": "A03:2021"
}
```

---

### 3.6 Nmap

**File**: `apps/api/src/security/runners/nmap-runner.ts`

**Purpose**: Port scanning, service detection, version identification, and NSE script-based vulnerability checks.

**Executor**: DockerExecutor (Camada 2) | **Docker image**: `instrumentisto/nmap:latest`

**Command construction**:
```
# Quick scan (top 1000 ports)
nmap -sV -sC --open -T4 -oX - <target>

# Full scan (all 65535 ports)
nmap -sV -sC -p- --open -oX - <target>
```

| Flag | Purpose |
|------|---------|
| `-sV` | Service/version detection |
| `-sC` | Run default NSE scripts |
| `-p-` | Scan all 65535 ports (full only) |
| `--open` | Show only open ports |
| `-T4` | Aggressive timing (quick only) |
| `-oX -` | XML output to stdout |
| `-p` | Custom port range (optional) |

**Options** (`NmapOptions`):
- `scanType`: `'quick' | 'full'` -- scan scope (default: `quick`)
- `ports`: `string` -- custom port specification
- `timeout`: `number` -- execution timeout (quick: 300,000 ms, full: 900,000 ms)

**Output parsing**: XML (parsed with `fast-xml-parser`). Produces three types of findings per open port:

1. **`open-port`** (severity: `info`): Port number, protocol, service name, product, version.
2. **`service-detected`** (severity: `low`): Generated when version information is present. Maps to `A06:2021`.
3. **NSE script findings** (severity varies): Generated from NSE script output. Type and severity are classified by script name:
   - Scripts containing `vuln` -> type `vulnerability`, severity `high`
   - Scripts containing `ssl`/`tls` -> type `tls-issue`, severity `medium`
   - Scripts containing `auth`/`brute` -> type `auth-issue`
   - Scripts containing `http` -> type `http-issue`, severity `medium`

**OWASP mapping**:
- SSL/TLS scripts -> `A02:2021` (Cryptographic Failures)
- Vulnerability scripts -> `A06:2021` (Vulnerable and Outdated Components)
- Auth/brute scripts -> `A07:2021` (Identification and Authentication Failures)
- Service detected -> `A06:2021`

**Example finding**:
```json
{
  "id": "nmap-open-port-tcp-22",
  "tool": "nmap",
  "type": "open-port",
  "severity": "info",
  "title": "Open port 22/tcp -- ssh",
  "description": "Port 22/tcp is open running ssh (OpenSSH 8.9p1).",
  "target": "192.168.1.1"
}
```

---

### 3.7 Nikto

**File**: `apps/api/src/security/runners/nikto-runner.ts`

**Purpose**: Web server misconfiguration scanner. Checks for outdated software, dangerous files, directory listings, missing security headers, and server configuration issues.

**Executor**: DockerExecutor (Camada 2) | **Docker image**: `secfigo/nikto:latest`

**Command construction**:
```
nikto -h <target> -Format json -output /dev/stdout [-Tuning <tuning>]
```

| Flag | Purpose |
|------|---------|
| `-h` | Target host/URL |
| `-Format json` | JSON output |
| `-output /dev/stdout` | Write output to stdout |
| `-Tuning` | Test tuning categories (optional) |

**Options** (`NiktoOptions`):
- `tuning`: `string` -- Nikto test tuning categories
- `timeout`: `number` -- execution timeout (default 600,000 ms)

**Output parsing**: JSON (may require extraction from surrounding text). Extracts from `vulnerabilities` or `items` array:
- OSVDB ID for cross-referencing
- HTTP method and URL
- Message/description text

**Type inference** (from message text):
- Keywords `outdated`, `version`, `appears to be` -> `outdated-software`
- Keywords `directory`, `index`, `listing` -> `misconfig`
- Keywords `header`, `x-frame`, `x-content-type`, `x-xss` -> `misconfig`
- Keywords `default`, `install`, `readme`, `changelog` -> `misconfig`
- Fallback: `misconfig`

**Severity inference** (from message text):
- `remote code`, `rce`, `arbitrary` -> `critical`
- `sql injection`, `xss`, `file inclusion` -> `high`
- `directory listing`, `default file`, `information disclosure` -> `medium`
- `outdated`, `version` -> `medium`
- `header`, `banner` -> `low`
- Fallback: `medium`

**OWASP mapping**:
- Type `misconfig` -> `A05:2021` (Security Misconfiguration)
- Type `outdated-software` -> `A06:2021` (Vulnerable and Outdated Components)

**Example finding**:
```json
{
  "id": "nikto-3092",
  "tool": "nikto",
  "type": "misconfig",
  "severity": "medium",
  "title": "OSVDB-3092: /admin/: Directory indexing found (/.admin/)",
  "description": "Directory indexing found.",
  "evidence": "GET /.admin/\nOSVDB-3092\nTarget: example.com:443",
  "owasp": "A05:2021"
}
```

---

### 3.8 Subfinder

**File**: `apps/api/src/security/runners/subfinder-runner.ts`

**Purpose**: Passive subdomain enumeration using OSINT sources (certificate transparency logs, search engines, DNS datasets).

**Executor**: ProcessExecutor (Camada 1) | **Binary**: `subfinder` | **Docker image**: `projectdiscovery/subfinder:latest`

**Command construction**:
```
subfinder -d <domain> -json -silent [-sources shodan,censys,crtsh]
```

| Flag | Purpose |
|------|---------|
| `-d` | Target domain |
| `-json` | JSON output |
| `-silent` | Suppress banner |
| `-sources` | Comma-separated OSINT sources (optional) |

The target is sanitized to extract just the domain: `new URL(target).hostname` with fallback regex stripping.

**Options** (`SubfinderOptions`):
- `timeout`: `number` -- execution timeout (default 300,000 ms)
- `sources`: `string[]` -- specific OSINT sources to use

**Output parsing**: JSON Lines. Each line produces a `subdomain` finding (severity: `info`). Extracts:
- `host` / `subdomain` -- the discovered subdomain
- `source` / `sources` -- which OSINT source found it

**Finding types**: `subdomain`

**OWASP mapping**: None (informational).

**Example finding**:
```json
{
  "id": "subfinder-api.example.com",
  "tool": "subfinder",
  "type": "subdomain",
  "severity": "info",
  "title": "Subdomain discovered: api.example.com",
  "description": "Found subdomain api.example.com for domain example.com. Discovered via: crtsh.",
  "target": "api.example.com"
}
```

---

### 3.9 Hydra

**File**: `apps/api/src/security/runners/hydra-runner.ts`

**Purpose**: Credential brute-forcing against network services. Tests for default and weak credentials.

**Executor**: DockerExecutor (Camada 2) | **Docker image**: `vanhauser/hydra:latest`

**Allowed services**: `ssh`, `ftp`, `mysql`, `postgres`, `rdp`, `smb`, `http-get`, `http-post-form`

**Default wordlists**:
- Users: `admin`, `root`, `user`, `test`, `guest`
- Passwords: `admin`, `password`, `123456`, `root`, `test`, `guest`, `changeme`, `default`

**Command construction**:
```sh
printf '%s\n' '<users>' > /tmp/users.txt && \
printf '%s\n' '<passwords>' > /tmp/passes.txt && \
hydra -L /tmp/users.txt -P /tmp/passes.txt -t <4> -o /dev/stdout -b jsonv1 <service>://<target>
```

| Flag | Purpose |
|------|---------|
| `-L` | Username list file |
| `-P` | Password list file |
| `-t` | Number of parallel tasks (default: 4) |
| `-o /dev/stdout` | Output to stdout |
| `-b jsonv1` | JSON output format |

**Security validations**:
- **Target validation**: Only allows hostnames, IPv4, IPv6, and CIDR ranges. Regex: `/^[a-zA-Z0-9._:\-\/\[\]]+$/`. Max length 255 characters. Rejects shell metacharacters.
- **Wordlist sanitization**: Removes control characters, backslashes, quotes, dollar signs, and backticks from wordlist entries.
- **Shell quoting**: Uses single-quote wrapping with proper escape handling.

**Options** (`HydraOptions`):
- `service`: `HydraService` -- target service (required)
- `userlist`: `string[]` -- custom username list
- `passwordlist`: `string[]` -- custom password list
- `tasks`: `number` -- parallel tasks (default 4)
- `timeout`: `number` -- execution timeout (default 300,000 ms)

**Output parsing**: JSON. Extracts `login`/`username`, `password`, `port`, `host` from results array.

**Finding types**: `weak-credential` (severity: always `critical`)

**OWASP mapping**: `A07:2021` (Identification and Authentication Failures)

**Example finding**:
```json
{
  "id": "hydra-weak-cred-ssh-admin-192.168.1.1",
  "tool": "hydra",
  "type": "weak-credential",
  "severity": "critical",
  "title": "Weak credential found for ssh on 192.168.1.1",
  "description": "Hydra successfully authenticated to ssh://192.168.1.1 with username \"admin\" and password \"admin\".",
  "evidence": "{\"service\":\"ssh\",\"host\":\"192.168.1.1\",\"username\":\"admin\",\"password\":\"admin\"}",
  "owasp": "A07:2021"
}
```

---

### 3.10 MobSF

**File**: `apps/api/src/security/runners/mobsf-runner.ts`

**Purpose**: Mobile application static analysis. Analyzes APK files for security vulnerabilities, hardcoded secrets, insecure storage, exported components, and trackers.

**Executor**: HTTP API (not ProcessExecutor or DockerExecutor) | **Docker image** (for reference): `opensecurity/mobile-security-framework-mobsf:latest`

**API workflow**:
1. **Upload**: `POST /api/v1/upload` with the APK file as multipart form data. Returns `{ hash, scan_type, file_name }`.
2. **Scan**: `POST /api/v1/scan` with `{ hash, scan_type, file_name }` as URL-encoded form data.
3. **Report**: `POST /api/v1/report_json` with `{ hash }`. Returns the full JSON report.

All requests include the `Authorization: <apiKey>` header. An `AbortController` with configurable timeout cancels the entire flow if it takes too long.

**Options** (`MobsfOptions`):
- `apiKey`: `string` -- MobSF API key (falls back to `MOBSF_API_KEY` env var)
- `host`: `string` -- MobSF host URL (default: `http://localhost:8000`)
- `timeout`: `number` -- execution timeout (default 600,000 ms)

**Output parsing**: JSON report. Extracts findings from:
- `report.appsec.high` -> severity `high`
- `report.appsec.warning` -> severity `medium`
- `report.appsec.info` -> severity `low`
- `report.secrets` -> severity `high`, type `secret`, OWASP `A02:2021`
- `report.trackers` -> severity `info`, type `tracker`

**Finding types**: `appsec`, `secret`, `tracker`

**OWASP mapping**: Secrets -> `A02:2021` (Cryptographic Failures)

**Example finding**:
```json
{
  "id": "mobsf-secret-3",
  "tool": "mobsf",
  "type": "secret",
  "severity": "high",
  "title": "Hardcoded secret found: AWS_SECRET_KEY=AKIA...",
  "description": "AWS_SECRET_KEY=AKIA...",
  "owasp": "A02:2021"
}
```

---

### 3.11 APKLeaks

**File**: `apps/api/src/security/runners/apkleaks-runner.ts`

**Purpose**: Extract URLs, endpoints, and hardcoded secrets from APK files using regex pattern matching against decompiled resources.

**Executor**: DockerExecutor (Camada 2) | **Docker image**: `dwisiswant0/apkleaks:latest`

**Command construction**:
```
apkleaks -f /scan/app.apk --json
```

The APK file is mounted into the container as a read-only volume: `{ [target]: '/scan/app.apk' }`.

| Flag | Purpose |
|------|---------|
| `-f` | APK file path (inside container) |
| `--json` | JSON output |

**Options** (`ApkleaksOptions`):
- `timeout`: `number` -- execution timeout (default 300,000 ms)

**Output parsing**: JSON array of `{ name, matches[] }` objects. Each match is classified:
- If `name` contains `key`, `token`, `secret`, or `password` -> type `secret`, severity `high`
- Otherwise -> type `endpoint`, severity `info`

**OWASP mapping**: Secrets -> `A02:2021` (Cryptographic Failures)

**Example finding**:
```json
{
  "id": "apkleaks-Google_API_Key-0",
  "tool": "apkleaks",
  "type": "secret",
  "severity": "high",
  "title": "Secret found: Google_API_Key",
  "description": "APKLeaks detected a hardcoded secret matching pattern \"Google_API_Key\": AIzaSyD...",
  "owasp": "A02:2021"
}
```

---

## 4. Scan Pipelines

All pipelines extend `BasePipeline` (`apps/api/src/security/pipelines/base-pipeline.ts`), which provides sequential step execution and deduplication.

### BasePipeline

**Step execution**: Steps run sequentially via `runSteps()`. Each step is an object `{ name, run: () => Promise<ScanResult> }`. If a step throws, an error result is recorded and execution continues with the next step.

**Status logic**:
- All steps errored -> `error`
- Some steps errored -> `partial`
- No errors -> `success`

**Deduplication**: `deduplicate()` removes findings with the same composite key: `${type}:${title}:${target}`. First occurrence wins.

**Result type** (`PipelineResult`):
```typescript
{
  pipeline: string
  status: 'success' | 'partial' | 'error'
  steps: { name: string; result: ScanResult }[]
  allFindings: Finding[]    // deduplicated
  totalTimeMs: number
}
```

---

### 4.1 Web Recon Pipeline

**File**: `apps/api/src/security/pipelines/web-recon-pipeline.ts`
**Tool name**: `security_web_recon`

**Purpose**: Full web application reconnaissance -- fingerprint, crawl, and vulnerability scan.

**Steps** (in order):
1. **httpx-fingerprint**: `HttpxRunner.run(target, { followRedirects: true })` -- technology detection, server headers, TLS info
2. **katana-crawl**: `KatanaRunner.run(target, { depth })` -- endpoint and parameter discovery
3. **nuclei-scan**: `NucleiRunner.run(target, { severity, tags, timeout })` -- template-based vulnerability scanning

**Depth configurations**:

| Depth | Katana Depth | Nuclei Severity | Nuclei Tags | Nuclei Timeout |
|-------|-------------|-----------------|-------------|----------------|
| `quick` | 2 | critical, high | cve | 120s |
| `standard` | 3 | critical, high, medium | (all) | 300s |
| `deep` | 5 | all five levels | (all) | 600s |

**Data flow**: Steps are independent -- each receives the original target URL. httpx provides technology context, katana discovers endpoints, and nuclei scans for known vulnerabilities. Findings from all three are merged and deduplicated.

---

### 4.2 SQLi Pipeline

**File**: `apps/api/src/security/pipelines/sqli-pipeline.ts`
**Tool name**: `security_sqli_scan`

**Purpose**: SQL injection detection with parameter discovery.

**Steps** (in order):
1. **katana-param-discovery**: `KatanaRunner.run(target, { depth: 3 })` -- discover endpoints with parameters
2. **sqlmap-injection-test**: `SqlmapRunner.run(target, { level, risk: 1 })` -- test for SQL injection

**Options**:
- `level`: sqlmap aggressiveness 1-5 (default: 2 in pipeline, vs. 3 direct)

**Data flow**: Katana discovers parameterized URLs first, then sqlmap tests the target for injection. Both receive the same target URL. In practice, the katana step provides contextual endpoint information while sqlmap does the actual injection testing.

---

### 4.3 XSS Pipeline

**File**: `apps/api/src/security/pipelines/xss-pipeline.ts`
**Tool name**: `security_xss_scan`

**Purpose**: Cross-Site Scripting detection with form/parameter discovery.

**Steps** (in order):
1. **katana-form-discovery**: `KatanaRunner.run(target, { depth: 3 })` -- discover forms and input points
2. **dalfox-xss-scan**: `DalfoxRunner.run(target)` -- XSS payload testing

**Data flow**: Similar to SQLi pipeline. Katana discovers input points, DalFox tests for XSS. Both receive the original target URL.

---

### 4.4 Network Pipeline

**File**: `apps/api/src/security/pipelines/network-pipeline.ts`
**Tool name**: `security_network_scan`

**Purpose**: Network-level reconnaissance -- port scanning, service detection, and network vulnerability scanning.

**Steps** (in order):
1. **nmap-port-scan**: `NmapRunner.run(target, { scanType })` -- port and service discovery
2. **nuclei-network-scan**: `NucleiRunner.run(target, { tags, severity, timeout })` -- network-specific template scanning

**Options**:
- `scanType`: `'quick' | 'full'` (default: `quick`)

**Nuclei configuration by scan type**:

| Scan Type | Tags | Severity | Timeout |
|-----------|------|----------|---------|
| `quick` | network, dns, ssl, tls, ftp, ssh, smtp, rdp | critical, high | 120s |
| `full` | Same as quick | critical, high, medium, low | 600s |

---

### 4.5 Subdomain Pipeline

**File**: `apps/api/src/security/pipelines/subdomain-pipeline.ts`
**Tool name**: `security_subdomain_scan`

**Purpose**: Subdomain enumeration, alive-host probing, and vulnerability scanning of discovered subdomains.

This pipeline has **custom step orchestration** (does not use `runSteps()`):

**Steps** (in order):
1. **subfinder-enum**: `SubfinderRunner.run(domain)` -- passive subdomain enumeration
2. **httpx-probe**: For each discovered subdomain (max 20), `HttpxRunner.run(subdomain, { followRedirects: true, timeout: 30000 })` -- probe for alive HTTP services
3. **nuclei-scan**: For each alive host (max 20), `NucleiRunner.run(host, { severity: ['critical', 'high', 'medium'], timeout: 120000 })` -- vulnerability scan

**Data flow**: This is the only pipeline with actual data dependencies between steps:
- Step 1 output (subdomains) feeds into Step 2 (probing)
- Step 2 output (alive hosts with HTTP status codes) feeds into Step 3 (scanning)

**Limits**: Maximum 20 subdomains probed, maximum 20 alive hosts scanned (`MAX_SUBDOMAINS = 20`).

**Subdomain extraction**: Reads from finding `metadata.subdomain` or `target` field. Falls back to parsing raw output lines.

**Alive host extraction**: Reads from findings with `metadata.status_code`. Falls back to raw output lines starting with `http`.

**Deduplication**: Uses the same `type:title:target` key as BasePipeline.

---

### 4.6 Mobile Pipeline

**File**: `apps/api/src/security/pipelines/mobile-pipeline.ts`
**Tool name**: `security_mobile_scan`

**Purpose**: Mobile application security analysis combining static analysis with secrets extraction.

**Steps** (in order):
1. **mobsf-analysis**: `MobsfRunner.run(filePath)` -- full static analysis (vulnerabilities, trackers, exported components)
2. **apkleaks-secrets**: `ApkleaksRunner.run(filePath)` -- focused secret and endpoint extraction

**Data flow**: Both steps receive the same APK file path. MobSF provides broad application security analysis while APKLeaks focuses specifically on hardcoded secrets and embedded URLs.

---

### 4.7 Credential Audit (Direct Runner)

**Tool name**: `security_credential_audit`

This is not a pipeline but a direct runner invocation. `SecurityService.executeTool()` calls `HydraRunner.run(target, { service })` directly without any pipeline wrapper.

---

## 5. Integration with Heroes Platform

### 5.1 Security Powers

Security tools are registered as **Powers** in the database using the special URL scheme `internal://security`. The seed file (`packages/db/prisma/seed.ts`) creates three built-in security powers:

| Power Name | Slug | Tools Included |
|-----------|------|----------------|
| Web Security Scanner | `web-security-scanner` | nuclei, httpx, katana, sqlmap, dalfox, nikto |
| Network Security Scanner | `network-security-scanner` | nmap, subfinder, hydra, nuclei |
| Mobile Security Scanner | `mobile-security-scanner` | MobSF, APKLeaks |

These powers use `mcpServerUrl: 'internal://security'` to signal that they are handled internally, not via MCP protocol.

### 5.2 Tool Resolution (`tool-resolver.ts`)

When `resolveHeroPowers()` is called, it:

1. **Fetches powers** from the database via `powersService.findByIds(powerIds)`.
2. **Separates** powers into two groups:
   - `securityPowers`: where `mcpServerUrl === 'internal://security'`
   - `mcpPowers`: everything else
3. **MCP tools** go through the normal cache/connect/filter pipeline.
4. **Security tools**: If any security powers are present and `securityService` is provided, `createSecurityTools(securityService)` is called.

### 5.3 `createSecurityTools()`

This function:
1. Calls `securityService.getToolDefinitions()` to get all 9 tool definitions.
2. For each definition, creates a `DynamicStructuredTool` with:
   - `name`: e.g., `security_web_recon`
   - `description`: prefixed with `[Security Scanner]`
   - `schema`: converted from JSON Schema to Zod via `jsonSchemaToZod(sanitizeToolSchema(...))`
   - `func`: calls `securityService.executeTool(name, input)` and returns the JSON result string

All security tools are added to the tool list after MCP tools, with deduplication by name.

### 5.4 MissionExecutorService

The `MissionExecutorService` (`apps/api/src/missions/mission-executor/mission-executor.service.ts`) receives `SecurityService` via dependency injection and passes it to `resolveHeroPowers()`:

```typescript
constructor(
    ...
    private readonly securityService: SecurityService
) {}

// In executeMission():
const { tools, title } = await resolveHeroPowers(
    powerIds,
    powersService,
    mcpClientService,
    lastUserMessage,
    needsTitle,
    organizationId,
    this.securityService   // <-- passed here
)
```

### 5.5 Full Execution Flow

```
User Message
    |
    v
Hero (has Powers including internal://security)
    |
    v
MissionExecutorService.executeMission()
    |
    v
resolveHeroPowers() --> createSecurityTools()
    |                        |
    v                        v
LLM receives tools      DynamicStructuredTool[]
    |
    v
LLM emits tool_use (e.g., security_web_recon)
    |
    v
DynamicStructuredTool.func(input)
    |
    v
SecurityService.executeTool('security_web_recon', input)
    |
    v
WebReconPipeline.run({ target, depth })
    |
    v
httpx -> katana -> nuclei (sequential)
    |
    v
PipelineResult { allFindings, steps, totalTimeMs }
    |
    v
normalizeForAgent(result) --> truncate evidence, count by severity
    |
    v
JSON string returned to LLM
    |
    v
LLM interprets findings and responds to user
```

### 5.6 Finding Normalization

`normalizeForAgent()` (`apps/api/src/security/finding-normalizer.ts`) transforms raw scan results into a compact format for the LLM:

- Truncates `evidence` to 500 characters
- Counts findings by severity (`bySeverity`)
- Includes `status`, `totalFindings`, `executionTimeMs`
- Strips heavy metadata (rawOutput, full metadata objects)

### 5.7 Finding Persistence

If `executeTool()` is called with `opts.scanId`, `opts.targetId`, and `opts.organizationId`, it calls `findingsService.persistFromScan()` after the scan completes. This persists findings to the database with deduplication (see Section 7).

---

## 6. Data Model

### 6.1 Target

**Table**: `targets`

| Field | Type | Description |
|-------|------|-------------|
| `id` | String (cuid) | Primary key |
| `name` | String | Display name |
| `type` | String | Target type: `web`, `network`, `mobile`, `api` |
| `value` | String | Target address (URL, IP, domain) |
| `status` | String | Status (default: `new`) |
| `lastScanAt` | DateTime? | Last scan timestamp |
| `findingsCount` | Json? | Cached severity counts: `{ critical: N, high: N, ... }` |
| `tags` | Json? | User-defined tags |
| `organizationId` | String | FK to Organization |
| `createdDate` | DateTime | Auto-set |
| `updatedDate` | DateTime | Auto-updated |

**Unique constraint**: `@@unique([organizationId, value])` -- prevents duplicate targets within an organization.

**findingsCount maintenance**: Updated by `FindingsService.persistFromScan()` after every scan. Groups findings by severity and stores the counts as JSON.

### 6.2 Finding

**Table**: `findings`

| Field | Type | Description |
|-------|------|-------------|
| `id` | String (cuid) | Primary key |
| `scanId` | String | FK to SecurityScan |
| `targetId` | String? | FK to Target |
| `organizationId` | String | FK to Organization |
| `externalId` | String? | Tool-generated ID (e.g., `nuclei-template-id`) |
| `tool` | String | Tool name (nuclei, httpx, etc.) |
| `type` | String | Finding type (sqli, xss, misconfig, etc.) |
| `severity` | String | critical, high, medium, low, info |
| `title` | String | Finding title |
| `description` | String | Detailed description |
| `evidence` | String? | Proof/reproduction evidence |
| `remediation` | String? | Fix recommendation |
| `cve` | String? | CVE identifier |
| `owasp` | String? | OWASP Top 10 category |
| `cvss` | Float? | CVSS score |
| `metadata` | Json? | Tool-specific metadata |
| `status` | String | Workflow status (default: `open`) |
| `assignedTo` | String? | Assigned user |
| `notes` | String? | User notes |
| `statusChangedAt` | DateTime? | Last status change |
| `resolvedAt` | DateTime? | When resolved |
| `firstSeenAt` | DateTime | First detection time |
| `lastSeenAt` | DateTime | Most recent detection |
| `createdDate` | DateTime | Auto-set |
| `updatedDate` | DateTime | Auto-updated |

**Unique constraint**: `@@unique([externalId, targetId, organizationId])` -- enables deduplication by tool-generated ID.

**Indexes**: `organizationId`, `scanId`, `targetId`, `severity`.

### 6.3 SecurityScan

**Table**: `security_scans`

| Field | Type | Description |
|-------|------|-------------|
| `id` | String (uuid) | Primary key |
| `organizationId` | String | FK to Organization |
| `missionId` | String? | FK to Mission (links scan to conversation) |
| `heroId` | String? | FK to Hero that triggered the scan |
| `target` | String | Scan target string |
| `scanType` | String | Type of scan performed |
| `status` | String | running, completed, failed (default: `running`) |
| `findingsCount` | Json? | Summary counts |
| `findings` | Json? | Raw findings data |
| `startedAt` | DateTime | Scan start time |
| `completedAt` | DateTime? | Scan completion time |
| `durationMs` | Int? | Duration in milliseconds |
| `targetId` | String? | FK to Target |
| `createdAt` | DateTime | Auto-set |

### 6.4 Entity Relationships

```
Organization
    |
    +--< Target >--< Finding
    |       |           |
    |       +--< SecurityScan >--+
    |               |
    +--< Hero >-----+
    |       |
    |       +--< Mission >--< SecurityScan
    |
    +--< Hook
```

- Organization 1:N Target, Finding, SecurityScan, Hero, Hook
- Target 1:N SecurityScan, Finding
- SecurityScan 1:N Finding
- Hero 1:N SecurityScan
- Mission 1:N SecurityScan

---

## 7. Finding Workflow

### 7.1 Status Lifecycle

```
open --> in_progress --> fixed
                    --> accepted_risk
                    --> false_positive
```

Valid statuses: `open`, `in_progress`, `fixed`, `accepted_risk`, `false_positive`.

When status changes:
- `statusChangedAt` is always updated.
- `resolvedAt` is set when status becomes `fixed`, `accepted_risk`, or `false_positive`.

### 7.2 Deduplication

`FindingsService.persistFromScan()` uses a two-tier deduplication strategy:

**Primary key** (when `externalId` is present):
- Unique constraint: `(externalId, targetId, organizationId)`
- Example: nuclei template IDs like `cve-2021-44228`

**Fallback** (when no `externalId`):
- Match on: `(type, title, targetId, organizationId)` using `findFirst`
- Example: nikto findings where OSVDB ID is embedded in the finding ID but not reliably unique

### 7.3 Re-appearing Findings

When a finding already exists in the database and appears again in a new scan:
- `lastSeenAt` is updated to the current timestamp
- `scanId` is updated to the new scan
- `description`, `evidence`, `remediation`, `cvss`, and `metadata` are updated with the latest values
- **Status is preserved** -- a finding marked `false_positive` stays that way even if the tool detects it again

### 7.4 Stale Detection

The `firstSeenAt` and `lastSeenAt` fields enable stale detection. If a finding's `lastSeenAt` is significantly older than the most recent scan of its target, it may have been resolved. This is a concept available for the Watcher hero to reason about ("findings that DISAPPEARED"), but no automatic staleness marking is implemented in the service layer.

### 7.5 Bulk Operations

`FindingsService.bulkUpdateStatus()` accepts an array of finding IDs and applies the same status/notes update to all of them. Uses `prisma.finding.updateMany()` with organization scoping.

### 7.6 Export

`FindingsService.exportData()` supports two formats:

**JSON**: Returns the raw Prisma finding objects with target relation included.

**CSV**: Generates a CSV string with these columns:
```
id, tool, type, severity, title, description, cve, owasp, cvss,
status, assignedTo, target, firstSeenAt, lastSeenAt, createdDate
```

Values containing commas, quotes, or newlines are properly escaped with double-quoting.

---

## 8. API Reference

All endpoints require session authentication. Scoped by organization.

### 8.1 Security Tools & Health

#### `GET /security/tools`
**Scope**: `powers:read`

Returns the list of available security scanning tools with their input schemas.

**Response**: `SecurityToolDefinition[]`
```json
[
  {
    "name": "security_web_recon",
    "description": "Run web reconnaissance...",
    "inputSchema": {
      "type": "object",
      "properties": {
        "target_url": { "type": "string", "description": "Target URL" },
        "depth": { "type": "string", "enum": ["quick", "standard", "deep"] }
      },
      "required": ["target_url"]
    }
  }
]
```

#### `GET /security/health`
**Scope**: `powers:read`

Checks Docker availability for security scanning.

**Response**:
```json
{
  "docker": true,
  "status": "ready"
}
```

#### `GET /security/dashboard`
**Scope**: `security:read`

Returns aggregated security statistics for the organization.

**Response**:
```json
{
  "findingsStats": {
    "bySeverity": { "critical": 3, "high": 12, "medium": 25, "low": 40, "info": 100 },
    "byStatus": { "open": 150, "in_progress": 10, "fixed": 20 }
  },
  "recentScans": [ { "id": "...", "target": "...", "status": "completed" } ],
  "topTargets": [ { "id": "...", "name": "...", "findingsCount": {} } ],
  "totalTargets": 15,
  "totalScans": 42
}
```

### 8.2 Targets CRUD

#### `GET /security/targets`
**Scope**: `security:read`

List all targets for the organization.

**Query parameters**:
- `type` (optional): Filter by type (`web`, `network`, `mobile`, `api`)
- `status` (optional): Filter by status

**Response**: `Target[]`

#### `GET /security/targets/:id`
**Scope**: `security:read`

Get a single target by ID.

**Response**: `Target`

#### `POST /security/targets`
**Scope**: `security:write`

Create a new target.

**Request body**:
```json
{
  "name": "Production Web App",
  "type": "web",
  "value": "https://app.example.com",
  "tags": ["production", "critical"]
}
```

**Response**: `Target`

**Error**: `409 Conflict` if a target with the same `value` already exists in the organization.

#### `PUT /security/targets/:id`
**Scope**: `security:write`

Update a target.

**Request body**: Partial `CreateTargetDto`

#### `DELETE /security/targets/:id`
**Scope**: `security:delete`

Delete a target and cascade.

### 8.3 Findings CRUD & Operations

#### `GET /security/findings`
**Scope**: `security:read`

List findings with pagination and filters.

**Query parameters**:
- `page` (default: `1`): Page number
- `limit` (default: `50`, max: `200`): Items per page
- `severity`: Filter by severity
- `type`: Filter by finding type
- `targetId`: Filter by target
- `owasp`: Filter by OWASP category
- `status`: Filter by workflow status
- `dateFrom`: Filter findings created after this date
- `dateTo`: Filter findings created before this date

**Response**:
```json
{
  "data": [ { "id": "...", "tool": "nuclei", "severity": "high" } ],
  "total": 180,
  "page": 1,
  "limit": 50,
  "totalPages": 4
}
```

#### `GET /security/findings/:id`
**Scope**: `security:read`

Get a single finding with target and scan relations.

#### `GET /security/findings/stats`
**Scope**: `security:read`

Get aggregated finding statistics.

**Response**:
```json
{
  "bySeverity": { "critical": 3, "high": 12, "medium": 25, "low": 40, "info": 100 },
  "byStatus": { "open": 150, "in_progress": 10, "fixed": 20, "false_positive": 5 }
}
```

#### `GET /security/findings/export`
**Scope**: `security:read`

Export findings as CSV or JSON.

**Query parameters**: Same filters as `GET /security/findings` plus:
- `format`: `csv` or `json` (default: `json`)

#### `PATCH /security/findings/:id`
**Scope**: `security:write`

Update a finding's status, assignedTo, or notes.

**Request body**:
```json
{
  "status": "in_progress",
  "assignedTo": "security-engineer@example.com",
  "notes": "Investigating this SQLi finding"
}
```

#### `PATCH /security/findings/bulk`
**Scope**: `security:write`

Bulk update multiple findings.

**Request body**:
```json
{
  "ids": ["finding-1", "finding-2", "finding-3"],
  "status": "false_positive",
  "notes": "These are test environment artifacts"
}
```

**Response**:
```json
{
  "updated": 3
}
```

---

## 9. Security Heroes

Four pre-configured heroes are seeded via `packages/db/prisma/seed.ts`. All use `claude-sonnet-4-20250514` as the LLM model.

### 9.1 Guardian -- Web Application Security Analyst

**Slug**: `guardian`
**Powers**: Web Security Scanner

**System prompt methodology**:
1. Always start with `security_web_recon` to fingerprint the target
2. Based on findings, run targeted deep scans (SQLi, XSS) on discovered attack surfaces
3. Use `security_nikto_scan` for web server misconfiguration checks
4. Categorize all findings by OWASP Top 10 (2021)

**Rules**: Never scan without authorization, present by severity, include remediation, explain what was tested if no vulns found, note scan depth and limitations.

**Example flow**:
```
User: "Scan https://example.com for vulnerabilities"
Guardian: Runs security_web_recon (standard depth)
  -> Discovers tech stack, endpoints, vulns
  -> If parameterized URLs found, runs security_sqli_scan
  -> If forms found, runs security_xss_scan
  -> Presents organized report by OWASP category
```

### 9.2 Sentinel -- Network Security Analyst

**Slug**: `sentinel`
**Powers**: Network Security Scanner

**System prompt methodology**:
1. Start with `security_network_scan` (quick) to discover open ports and services
2. For web-facing targets, run `security_subdomain_scan` to enumerate attack surface
3. If login services found (SSH, FTP, MySQL), offer `security_credential_audit` with explicit authorization
4. Map risk by host, prioritize internet-facing services with known CVEs

**Rules**: Never scan without authorization, distinguish info from actual vulns, warn before credential audit, present network topology summary with risk ratings, note services that should not be internet-facing.

### 9.3 Shield -- Mobile Security Analyst

**Slug**: `shield`
**Powers**: Mobile Security Scanner

**System prompt methodology**:
1. Run `security_mobile_scan` with the provided APK file
2. Analyze MobSF report for insecure storage, exported components, hardcoded secrets, trackers
3. Categorize findings by OWASP Mobile Top 10
4. Highlight hardcoded API keys, tokens, and credentials from APKLeaks

**Rules**: Organize by severity with remediation, flag trackers and privacy implications, note insecure network configs, provide security score summary.

### 9.4 Watcher -- Continuous Security Monitor

**Slug**: `watcher`
**Powers**: Web Security Scanner + Network Security Scanner

**System prompt methodology**:
1. When scanning, ALWAYS compare results with previous scan
2. Highlight NEW findings not in last scan
3. Note findings that DISAPPEARED (potentially fixed)
4. Escalate if severity increased
5. Notify via Slack/Jira about critical/high new findings (if integrated)

**Output format**:
- Summary: "X new findings, Y resolved, Z unchanged"
- New findings with full details
- Resolved findings
- Trend: "Target security posture: improving/stable/degrading"

**Rules**: Never scan without authorization, focus on CHANGES not repeating known findings, concise actionable language.

---

## 10. Continuous Security

### 10.1 Schedules

The `Schedule` model stores cron-based triggers:

| Field | Description |
|-------|-------------|
| `heroId` | Which hero to trigger |
| `cronExpression` | Standard cron format (e.g., `0 2 * * *` for daily at 2 AM) |
| `timezone` | Timezone for cron (default: `UTC`) |
| `prompt` | The message to send the hero |
| `isActive` | Enable/disable toggle |

Typical presets for security scanning:
- **Daily**: `0 2 * * *` -- full scan at 2 AM
- **Weekly**: `0 2 * * 1` -- Monday at 2 AM
- **Monthly**: `0 2 1 * *` -- first of month at 2 AM

When a schedule fires, it creates a Mission with the configured prompt, triggering the assigned hero to execute its workflow.

### 10.2 Webhook Scan-on-Push

The `HooksService` (`apps/api/src/hooks/hooks.service.ts`) enables scan-on-push via webhooks (GitHub, GitLab, generic).

**Cooldown logic** (in `handleDelivery()`):

1. **Cooldown timer**: Configurable via `hook.config.cooldownMinutes` (default: 60 minutes). If the time since `lastDeliveryAt` is less than the cooldown period, the delivery is silently throttled.

2. **Daily cap**: Configurable via `hook.config.maxScansPerDay` (default: 5). Counts missions triggered today (where `triggerType: 'webhook'` and `heroId` matches, created after midnight).

3. **Mission creation**: If neither throttle triggers:
   - Updates `lastDeliveryAt` on the hook
   - Creates a Mission with `triggerType: 'webhook'`
   - The mission message is: `${hook.prompt}\n\nWebhook payload:\n${JSON.stringify(payload)}` (or a default prompt if none configured)
   - Mission metadata includes `hookId`, `hookType`, and `repository`

**Example**: A GitHub push webhook configured with `cooldownMinutes: 30` and `maxScansPerDay: 10` will:
- Ignore pushes within 30 minutes of the last scan
- Stop scanning after 10 scans in a calendar day
- Create a mission that triggers the assigned hero (e.g., Guardian) with the push payload

### 10.3 Watcher Comparison

The Watcher hero is designed to compare findings between scans. Its system prompt instructs it to:
- Identify NEW findings (present now, absent before)
- Identify RESOLVED findings (present before, absent now)
- Detect severity escalation
- Assess trend: improving / stable / degrading

This comparison is performed at the LLM reasoning level using `firstSeenAt` and `lastSeenAt` timestamps on findings, not via a dedicated diff algorithm in the code.

---

## 11. Deployment

### 11.1 Local Development

- **Database**: PostgreSQL 16 via Docker Compose (`docker/`)
- **Cache/Sessions**: Redis via Docker Compose
- **Camada 1 tools**: Install Go binaries locally (nuclei, httpx, katana, subfinder, dalfox) or let them fail gracefully
- **Camada 2 tools**: Docker Desktop provides the `/var/run/docker.sock` for DockerExecutor
- **MobSF**: Run via Docker Compose (`docker/security/docker-compose.security.yml`) on port 8000
- **API**: `BYPASS_AUTH=true npx nest start --watch` on port 3000
- **Frontend**: Vite dev server on port 8080

### 11.2 Cloud Run (Production)

The `Dockerfile` installs Camada 1 binaries as static Go executables:

```dockerfile
RUN apk add --no-cache curl unzip \
    && ARCH=$(uname -m | sed 's/aarch64/arm64/' | sed 's/x86_64/amd64/') \
    && OS=$(uname -s | tr '[:upper:]' '[:lower:]') \
    && curl -sL ".../nuclei_${OS}_${ARCH}.zip" -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ nuclei \
    && curl -sL ".../httpx_${OS}_${ARCH}.zip" -o /tmp/httpx.zip \
    && unzip -o /tmp/httpx.zip -d /usr/local/bin/ httpx \
    && curl -sL ".../katana_${OS}_${ARCH}.zip" -o /tmp/katana.zip \
    && unzip -o /tmp/katana.zip -d /usr/local/bin/ katana \
    && curl -sL ".../subfinder_${OS}_${ARCH}.zip" -o /tmp/subfinder.zip \
    && unzip -o /tmp/subfinder.zip -d /usr/local/bin/ subfinder \
    && curl -sL ".../dalfox_${OS}_${ARCH}.tar.gz" -o /tmp/dalfox.tar.gz \
    && tar -xzf /tmp/dalfox.tar.gz -C /usr/local/bin/ dalfox \
    && chmod +x /usr/local/bin/nuclei /usr/local/bin/httpx \
        /usr/local/bin/katana /usr/local/bin/subfinder /usr/local/bin/dalfox
```

- **Camada 1 tools only**: nuclei, httpx, katana, subfinder, dalfox run as native processes
- **No Docker socket**: Cloud Run does not provide `/var/run/docker.sock`, so Camada 2 tools (sqlmap, nmap, nikto, hydra, apkleaks) are unavailable
- **MobSF**: Requires a separate MobSF instance accessible via `MOBSF_HOST`
- **Non-root**: Container runs as the `node` user for security
- **Base image**: `node:20-alpine`

### 11.3 Environment Variables

See Section 12 for the complete reference.

---

## 12. Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `BYPASS_AUTH` | `false` | Skip session authentication in non-production. Set to `true` for local dev. |
| `DEV_USER_ID` | `dev-user` | User ID for bypass auth sessions |
| `DEV_ORG_ID` | `dev-org` | Organization ID for bypass auth sessions |
| `MOBSF_HOST` | `http://localhost:8000` | MobSF API server URL |
| `MOBSF_API_KEY` | (empty) | MobSF API authentication key |
| `WEBHOOK_BASE_URL` | `http://localhost:3000` | Public base URL for webhook callback URLs |
| `VITE_BYPASS_AUTH` | `false` | Frontend: auto-login without credentials in dev |
| `NODE_ENV` | (unset) | When not `production`, enables `BYPASS_AUTH` |

**Docker Compose security variables** (from `docker/security/docker-compose.security.yml`):

| Variable | Description |
|----------|-------------|
| `MOBSF_API_KEY` | Passed to MobSF container |

**ProcessExecutor constants** (hardcoded, not env vars):

| Constant | Value | Description |
|----------|-------|-------------|
| `DEFAULT_TIMEOUT` | 300,000 ms | Default process execution timeout |
| `DEFAULT_MAX_BUFFER` | 10 MB | Maximum stdout/stderr buffer size |

**DockerExecutor defaults** (hardcoded):

| Setting | Value | Description |
|---------|-------|-------------|
| Memory limit | 512 MB | Per-container memory cap |
| CPU limit | 1 CPU | Per-container CPU cap |
| Tmpfs size | 100 MB | `/tmp` filesystem size |
| Network | `bridge` | Default Docker network mode |
| WorkingDir | `/scan` | Container working directory |
| Timeout | 300,000 ms | Default container timeout |
