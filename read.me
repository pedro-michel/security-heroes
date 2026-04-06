<div align="center">

# 🛡️ Heroes Security

### Pesquisa de Mercado & Plano de Construção

*Vertente de segurança ofensiva da plataforma [Heroes](https://github.com/) — AI agents para pentesting automatizado*

---

![Status](https://img.shields.io/badge/status-research-blue?style=flat-square)
![Phase](https://img.shields.io/badge/phase-planning-yellow?style=flat-square)
![Updated](https://img.shields.io/badge/updated-abril%202026-green?style=flat-square)

</div>

<br>

## 📋 Índice

- [Cenário Atual](#-cenário-atual-ia-em-pentesting-20252026)
- [Ferramentas no Mercado](#-ferramentas-relevantes-no-mercado)
- [Arquitetura Multi-Agent](#-arquitetura-dominante-multi-agent)
- [Plano de Construção](#-como-cada-funcionalidade-pode-ser-construída)
- [Prompt Injection](#-prompt-injection--o-elefante-na-sala)
- [Roadmap de Implementação](#-recomendação-de-implementação-no-heroes)
- [Monetização](#-modelo-de-monetização-sugerido)
- [Conclusão](#-conclusão)

---

## 🌍 Cenário Atual: IA em Pentesting (2025–2026)

### O que mudou de verdade

O mercado de AI pentesting explodiu nos últimos 12 meses. A grande mudança não é "IA fazendo scan" (isso Nessus e ZAP já faziam com heurísticas), mas sim **agentes autônomos que raciocinam sobre a aplicação**.

| | Scanner Tradicional | AI Pentesting Agent |
|---|---|---|
| **Abordagem** | Regras determinísticas pré-definidas | Raciocina sobre comportamento da app |
| **Adaptação** | Mesmos testes sempre | Adapta estratégia em tempo real |
| **Vulnerabilidades** | Conhecidas (signature-based) | Encadeia findings em attack paths |
| **Business Logic** | ❌ Não detecta | ✅ BOLA, IDOR, privilege escalation |
| **Custo** | $15–30k / engagement | $2–10 por scan (tokens) |
| **Tempo** | 2–4 semanas | Horas |

> **IBM 2025 Cost of a Data Breach Report:** Organizações usando IA em segurança economizaram ~**US$1.9M por breach**.

### Consenso da comunidade (Reddit r/netsec, r/pentesting)

A comunidade técnica tem um sentimento misto, mas cada vez mais positivo:

✅ **O que funciona bem:**
Reconhecimento automatizado, fuzzing, detecção de low-hanging fruits (SQLi, XSS, config issues), documentação e report generation, correlação de CVEs

❌ **O que ainda falha:**
Business logic flaws complexas, contexto específico de cada organização, falsos positivos em blind SQLi (timing-based), manter estado de autenticação em apps com MFA/SSO

> *"AI handles reconnaissance, repetition, and scale. Humans handle creativity, context, and judgment."*
> — Consenso geral da comunidade

---

## 🔧 Ferramentas Relevantes no Mercado

### Tier 1 — Plataformas Comerciais Líderes

| Ferramenta | Foco | Diferencial |
|:---|:---|:---|
| **[XBOW](https://xbow.com)** | Offensive security autônomo | Validado no HackerOne com resultados reais. Cada finding confirmado via exploração real |
| **[Aikido](https://www.aikido.dev)** | Dev-first AppSec | Combina SAST, DAST, e ataque com POC. Relatórios audit-ready (SOC2/ISO27001) |
| **[NodeZero](https://horizon3.ai)** | Network/infra pentesting | Mais maduro para rede interna. Full Domain Admin em 60s. Find-Fix-Verify |
| **[Terra Security](https://terrasecurity.com)** | Web app pentesting | Swarm de agentes + humano. Priorização por impacto de negócio |
| **[Escape](https://escape.tech)** | API & business logic | Forte em GraphQL, BOLA, IDOR. CI/CD native |
| **[Penligent](https://penligent.ai)** | Autonomous red team | 200+ tools Kali integrados. Zero-setup. Scan CVE + POC automático |
| **[Novee](https://novee.ai)** | LLM/AI app security | Focado em prompt injection e vulns específicas de IA. Raised **$51.5M** |

### Tier 2 — Open Source Relevantes

| Ferramenta | O que faz | Limitação |
|:---|:---|:---|
| **Shannon** (Keygraph) | White-box AI pentester. Analisa código + app rodando. **96% no benchmark XBOW** | Precisa acesso ao source code |
| **PentAGI** | Multi-agente autônomo. Docker sandbox. 20+ tools (nmap, metasploit, sqlmap) | Setup complexo, docs fraca |
| **CAI** | Evolução do PentestGPT. Multi-agent, modelos locais. Bug bounty ready | Config trabalhosa, loops infinitos |
| **BugTrace-AI** | Discovery-focused. Analisa URLs, JS, headers. Flags SQLi, XSS, JWT | Não faz POC — só detecção |
| **PentestGPT** | O OG. Assistente interativo para raciocínio de pentest | Não executa scans diretamente |
| **HexStrike AI** | MCP server que conecta LLMs a 150+ security tools | Infra-level, não end-user |
| **BlacksmithAI** | Multi-agent hierárquico (recon → scan → vuln → exploit → post-exploit) | Novo (março 2026) |

### Mobile-Specific

| Ferramenta | O que faz |
|:---|:---|
| **MobSF** | Framework open-source all-in-one para análise estática/dinâmica de APK/IPA |
| **Oversecured** | SaaS comercial. CI/CD integrado. Baixo false positive rate |
| **AutoSecT** | Upload APK → decompila → OWASP Mobile Top 10 → fuzza APIs → valida com IA |
| **APKLeaks** | Scanning de APK para URIs, endpoints e secrets |
| **Frida** | Runtime instrumentation para bypass de RASP, SSL pinning, etc |

---

## 🧠 Arquitetura Dominante: Multi-Agent

O padrão que **todas** as ferramentas sérias usam é multi-agente hierárquico. Ninguém mais faz "um LLM que faz tudo":

```
┌──────────────────────────────┐
│        ORCHESTRATOR          │ ← Coordena tudo, decompõe tarefas
│       (Planning Agent)       │
└──────────────┬───────────────┘
               │
   ┌───────────┼───────────┬─────────────┬──────────────┐
   ▼           ▼           ▼             ▼              ▼
┌───────┐ ┌────────┐ ┌─────────┐ ┌──────────┐ ┌────────────┐
│ Recon │ │ Scan & │ │  Vuln   │ │ Exploit  │ │   Post-    │
│ Agent │ │  Enum  │ │Analysis │ │  Agent   │ │  Exploit   │
│       │ │ Agent  │ │  Agent  │ │          │ │   Agent    │
└───────┘ └────────┘ └─────────┘ └──────────┘ └────────────┘
   │          │           │           │              │
  nmap     whatweb     análise     sqlmap        lateral
 subfinder  banner    de vulns   metasploit     movement
```

**Cada agente tem:**
- Seu próprio system prompt especializado
- Acesso a ferramentas específicas
- Memória isolada mas compartilhável com o orchestrator
- Budget de tokens/tool calls (para evitar loops infinitos)

> **Paper de fev/2026** *("What Makes a Good LLM Agent for Real-world Penetration Testing?")* analisou 28 sistemas e concluiu: existem falhas de engineering (resolvíveis com melhor tooling) e falhas de planning (onde o agente não sabe alocar esforço). **Escalar o modelo sozinho não resolve.**

---

## 🏗️ Como Cada Funcionalidade Pode Ser Construída

### 4.1 Web Scan — Injection (SQLi, Command Injection, XSS)

> **Complexidade:** Média · **Custo estimado:** $2–10 em tokens por scan

Cadeia padrão: `Crawl → Identify injection points → Generate payloads → Test → Validate (POC)`

```
Mission Pipeline:

1. RECON AGENT
   └─ Crawla o target, mapeia endpoints, params, forms, headers
   └─ Output: lista de injection points (URL + param + método)

2. PAYLOAD AGENT
   └─ Gera payloads específicos por tipo:
      • SQLi: error-based, blind, time-based
      • XSS: reflected, stored, DOM-based
      • Command injection: OS-specific payloads
   └─ Banco de payloads conhecidos + variações geradas pelo LLM

3. TESTER AGENT
   └─ Dispara os payloads contra cada injection point
   └─ Analisa respostas: error messages, timing, DOM changes
   └─ Classifica: "suspeito" vs "confirmado"

4. POC AGENT
   └─ Para findings "suspeitos", escala para POC real
   └─ Ex: SQLi → extrair versão do DB
   └─ Gera request completa reproduzível + screenshot/log

5. REPORTER AGENT
   └─ Classifica por CVSS/OWASP
   └─ Gera recomendação de fix
```

**Tools que fazem o trabalho pesado:** sqlmap, commix, XSSer. A IA orquestra e interpreta.

---

### 4.2 Web Scan — Business Logic (IDOR, BOLA, Mass Assignment)

> **Complexidade:** Alta · Esta é a parte MAIS difícil e onde as ferramentas de IA se diferenciam

```
Mission Pipeline:

1. DISCOVERY AGENT
   └─ Mapeia a aplicação como usuário
   └─ Identifica roles (admin, user, guest)
   └─ Mapeia endpoints por role
   └─ Identifica IDs em URLs/params (user_id, order_id, etc)

2. LOGIC ANALYZER AGENT
   └─ Horizontal privilege: troca IDs mantendo mesmo token
   └─ Vertical privilege: acessa endpoints de admin com token de user
   └─ Mass assignment: envia campos extras no JSON (role, is_admin, price)

3. VALIDATION AGENT
   └─ Confirma se acesso indevido retorna dados sensíveis
   └─ Diferencia "200 OK vazio" de "200 OK com dados do outro usuário"
```

Precisa de autenticação funcional, múltiplas sessions, e entendimento de contexto. **É aqui que o valor do produto aparece.**

---

### 4.3 Web Scan — Version/CVE Detection

> **Complexidade:** Baixa · Low-hanging fruit perfeito para começar

```
Mission Pipeline:

1. FINGERPRINT AGENT
   └─ Headers HTTP (Server, X-Powered-By)
   └─ HTML/JS (meta generators, known paths: /wp-admin, /administrator)
   └─ CMS: WordPress, Joomla, Drupal
   └─ Frameworks: Rails, Django, Laravel

2. CVE LOOKUP AGENT
   └─ Consulta NVD/NIST API ou Sploitus
   └─ Filtra por versão detectada
   └─ Prioriza por CVSS score e exploitability

3. ADVISORY AGENT
   └─ "Aplique patch X" ou "Atualize para versão Y"
   └─ Se exploit público existir, referencia e classifica como crítico
```

---

### 4.4 Mobile Scan — RASP Analysis (Com proteção)

> **Complexidade:** Alta na infra (ambiente Android/emulador), Média na IA

```
Mission Pipeline:

0. PRÉ-PROCESSAMENTO (não é IA)
   └─ Upload do APK
   └─ Decompile automático: apktool / jadx
   └─ Extração: AndroidManifest.xml, smali code, classes.dex

1. RASP DETECTION AGENT
   └─ Root detection patterns (Magisk, SuperSU checks)
   └─ SSL pinning (OkHttp CertificatePinner, Network Security Config)
   └─ Emulator detection (Build.FINGERPRINT, IMEI checks)
   └─ Tampering detection (signature verification, checksum)
   └─ Debug detection (Debug.isDebuggerConnected())

2. BYPASS ANALYSIS AGENT
   └─ Consulta banco de bypasses conhecidos
   └─ Frida scripts catalogados por tipo de proteção
   └─ Analisa se bypass padrão funciona ou se tem customização

3. REPORT AGENT
   └─ Lista proteções: classifica efetividade (weak/medium/strong)
   └─ Sugere melhorias
```

---

### 4.5 Mobile Scan — Sem proteção (Config & Hardcoded Secrets)

> **Complexidade:** Baixa-Média · "As palavras-chave já são muito usadas, o prompt fica bem menor"

```
Mission Pipeline:

0. PRÉ-PROCESSAMENTO
   └─ Decompile APK (apktool + jadx)
   └─ Extrai: strings.xml, AndroidManifest.xml, source Java/Kotlin

1. STATIC ANALYSIS AGENT — Busca por:
   ├─ API keys hardcoded (AWS, Firebase, Google Maps, Stripe)
   ├─ URLs de staging/dev
   ├─ Credenciais em SharedPreferences sem encryption
   ├─ allowBackup=true / debuggable=true
   ├─ Exported activities/providers sem proteção
   ├─ WebView com JS enabled + file access
   ├─ HTTP connections inseguras
   └─ Certificate pinning ausente

2. VALIDATION AGENT
   └─ "Este API key realmente dá acesso a algo?"
   └─ Testa endpoints encontrados
   └─ Diferencia key de produção vs exemplo

3. REPORT com classificação OWASP Mobile Top 10
```

**Tools wrappáveis:** MobSF (open source, Python), APKLeaks (Python), jadx (Java)

---

### 4.6 Infra Scan — Network & Services

> **Complexidade:** IA simples (orquestra ferramentas existentes). **Infra de deployment é o desafio real.**

#### Modelos de deployment

| Opção | Como funciona | Trade-off |
|:---|:---|:---|
| **A — Docker Agent** | Cliente roda container na rede interna. Comunica com Heroes via WebSocket. IA orquestra remotamente | Melhor cobertura, requer setup no cliente |
| **B — VPN** | Cliente configura VPN, Heroes se conecta de dentro | Simples mas requer confiança |
| **C — External-only** | Scan apenas do perímetro externo | Mais fácil, menos valor |

```
Mission Pipeline (assumindo acesso):

1. DISCOVERY      → nmap full port scan, service detection
2. ENUMERATION    → Versões, banners, painéis admin
3. BRUTE FORCE    → Credenciais padrão (admin/admin) via hydra
4. CVE MATCHING   → Cruzar serviços/versões com CVEs conhecidos
5. LATERAL MOVE   → Se credencial funcionar, testar até onde vai
6. REPORT         → Mapa de rede com criticidade por host
```

---

## ⚠️ Prompt Injection — O Elefante na Sala

A plataforma recebe input potencialmente malicioso (código de apps, respostas HTTP), joga num prompt de LLM, e o LLM toma ações. **Cenário perfeito para prompt injection.**

| Mitigação | Implementação |
|:---|:---|
| **Sandboxing completo** | Todo processamento de dados externos em ambiente isolado |
| **Separação de contexto** | Dados do target NUNCA no system prompt — sempre em user message com delimitadores claros |
| **Validação de output** | IA nunca executa comandos diretamente — sempre passa por validador intermediário |
| **Rate limiting** | Qualquer ação que modifique o target precisa de confirmação |
| **Modelos locais** | Para dados sensíveis demais para API cloud, usar Qwen/Mistral local |

---

## 🗺️ Recomendação de Implementação no Heroes

```
Fase 1 (MVP)          Fase 2                Fase 3              Fase 4
4–6 semanas           4–6 semanas           6–8 semanas         8–10 semanas
─────────────         ─────────────         ─────────────       ─────────────
Web Scan Básico       Business Logic        Mobile              Infra
• SQLi + XSS + CMDi   • IDOR / BOLA         • Android static    • Port scan
• Version/CVE detect  • Mass Assignment     • RASP analysis     • Brute force
• POC generation      • Priv escalation     • Secrets scan      • CVE matching
                      • Auth bypass                             • Lateral movement
```

### Fase 1 — MVP ✨

**Foco:** Web Scan básico

Criar 2 Hero templates:
1. **"Web Vulnerability Scanner"** — SQLi + XSS + Command Injection com POC
2. **"Tech Stack Auditor"** — Version detection + CVE lookup

**Powers necessários:** Web Browsing, Python, Vulnerability Research *(todos já planejados)*

**Diferencial:** Integrar com a plataforma Heroes existente. O usuário configura o target, o Hero roda a Mission, e o resultado aparece como conversa com findings categorizados.

### Fase 2 — Expansão Web

**Foco:** Business Logic

3. **"Access Control Auditor"** — IDOR, BOLA, privilege escalation
4. **"API Security Tester"** — Mass assignment, rate limiting, auth bypass

### Fase 3 — Mobile

**Foco:** Android primeiro

5. **"Mobile App Analyzer"** — Análise estática (sem proteção)
6. **"RASP Tester"** — Análise de proteções (com proteção)

*Infra necessária: Pipeline de decompilação de APK (apktool + jadx), storage para arquivos grandes.*

### Fase 4 — Infra

**Foco:** External scan primeiro

7. **"Network Scanner"** — Port scan + service enum + CVE matching
8. **"Credential Auditor"** — Default passwords + weak configs

*Requer: Docker agent ou modelo de deployment para rede interna.*

### 🚫 O que NÃO fazer

- **Não tentar fazer tudo ao mesmo tempo** — erro clássico
- **Não competir diretamente com Burp Suite ou XBOW** — eles têm anos de vantagem
- **Não prometer "zero false positives"** — ninguém consegue, a comunidade ridiculariza quem promete

> O diferencial do Heroes não é ser "mais um scanner" — é ser a plataforma que **orquestra** scanners + IA + reporting numa experiência unificada.

---

## 💰 Modelo de Monetização Sugerido

**Referências de preço do mercado:**

| Modelo | Preço |
|:---|:---|
| Pentests tradicionais | $15–30k por engagement |
| Ferramentas AI SaaS | $500–5k/mês |
| Open source + API tokens | $2–10 por scan |

**Para Heroes:**

- **Tier Pro** — Incluir Web Scan básico (version/CVE)
- **Add-on Enterprise** — Business Logic + Mobile + Infra
- **Security Missions** — Pricing mais alto por mission (usa mais tokens, mais tempo de execução)

---

## 🎯 Conclusão

O timing é bom. O mercado está em plena explosão, as ferramentas open-source já mostram que IA + pentesting funciona na prática, e o custo por scan é baixo o suficiente para ser viável como SaaS.

A jogada inteligente é usar a **infraestrutura do Heroes como vantagem competitiva**: orquestração de agentes, UI, billing, multi-tenancy — tudo isso já existe. O que precisa ser construído são os **Powers específicos de segurança** e os **Hero templates** que usam esses Powers.

<div align="center">

### Comece pelo web scan básico. Valide. Expanda.

</div>

---

<div align="center">
<sub>Documento interno — Heroes Platform · Abril 2026</sub>
</div>
