# 🔐 VAPT Framework

<div align="center">

**Automated Vulnerability Assessment & Penetration Testing Platform**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104%2B-009688.svg)](https://fastapi.tiangolo.com)
[![Celery](https://img.shields.io/badge/Celery-5.3%2B-green.svg)](https://docs.celeryq.dev)
[![Tests](https://img.shields.io/badge/Tests-47%20Passing-brightgreen.svg)](backend/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## 📖 Overview

A production-grade, modular cybersecurity framework that automates the entire vulnerability assessment lifecycle — from reconnaissance to professional report generation. Built with modern Python async patterns, microservice architecture, and enterprise security practices.

```
┌─────────────────────────────────────────────────────────────┐
│                     VAPT FRAMEWORK                          │
├───────────┬───────────┬───────────┬───────────┬────────────┤
│  RECON    │  SCANNER  │   RISK    │  REPORT   │    API     │
│  Module 1 │  Module 2 │  Module 3 │  Module 4 │  Module 5  │
├───────────┼───────────┼───────────┼───────────┼────────────┤
│ DNS Enum  │ HTTP Sec  │ CVSS 3.1  │ Executive │ FastAPI    │
│ WHOIS     │ Port Scan │ Scoring   │ Summary   │ Celery     │
│ Subdomain │ CVE Match │ A-F Grade │ Findings  │ Redis      │
│ Reverse   │ Service   │ Risk Calc │ HTML/PDF  │ Swagger    │
│ DNS       │ Detection │ Env Mod   │ Remediate │ Auth       │
└───────────┴───────────┴───────────┴───────────┴────────────┘
```

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/vapt-framework.git
cd vapt-framework

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run full pipeline
cd backend
python full_pipeline_demo.py
```

**Output:** Complete security assessment with HTML report saved to `reports/` directory.

---

## 🧩 Modules

### 📡 Module 1 — Reconnaissance
Passive information gathering — no direct target contact.

| Feature | Description |
|---------|-------------|
| DNS Enumeration | A, AAAA, MX, NS, TXT, CNAME, SOA records |
| WHOIS Lookup | Registrar, creation/expiration dates, nameservers (with TTL cache) |
| Subdomain Discovery | Certificate Transparency logs (crt.sh) + fallback sources |
| Reverse DNS | IP to hostname resolution |
| Data Normalization | Standardized output format across all sub-modules |

### 🔍 Module 2 — Unified Scanner
Active scanning with intelligent decision tree.

| Feature | Description |
|---------|-------------|
| HTTP Security Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Cookie Analysis | Secure, HttpOnly, SameSite flag verification |
| CORS Detection | Wildcard origin misconfiguration identification |
| SSL/TLS Validation | Certificate expiry, issuer, validity checks |
| Port Scanning | Top 20/100 TCP ports with async concurrent execution |
| Service Detection | Banner grabbing for SSH, FTP, SMTP, HTTP, MySQL, and more |
| CVE Matching | 100+ entries covering Apache, nginx, OpenSSH, MySQL, PostgreSQL, IIS, PHP, Redis, etc. |

### 📊 Module 3 — Risk Scoring Engine
CVSS 3.1-based scoring with environmental context.

| Feature | Description |
|---------|-------------|
| Base CVSS Scoring | Default scores mapped to header issues, open ports, services |
| Environmental Modifiers | Public exposure, sensitive data, exploit availability adjustments |
| Severity Classification | Critical (9.0+) to High (7.0+) to Medium (4.0+) to Low (0.1+) to Info |
| Security Grade | A (90-100), B (70-89), C (50-69), D (30-49), F (0-29) |
| Finding Prioritization | Sorted by severity level, then CVSS score |

### 📄 Module 4 — Report Generator
Professional, recruiter-ready security reports.

| Feature | Description |
|---------|-------------|
| Executive Summary | Management-friendly overview with risk level |
| Detailed Findings | Per-issue CVSS score, description, affected asset, remediation |
| Visual Score Card | Color-coded grade circle with severity breakdown |
| Ports and Services Table | Open ports with detected services and versions |
| DNS Records Table | Complete DNS enumeration results |
| HTML Output | Responsive, print-ready, modern design with CSS gradients |

### 🌐 Module 5 — REST API
Production backend with enterprise-grade security.

| Feature | Description |
|---------|-------------|
| FastAPI Server | Async Python web framework with auto-generated OpenAPI docs |
| Celery Tasks | Background scan processing with progress tracking |
| Redis Broker | Message queue and result backend |
| API Key Authentication | Constant-time comparison to prevent timing attacks |
| Rate Limiting | Configurable request limits per IP |
| Security Headers | X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, CSP |
| Input Sanitization | Blocks shell injection characters in user input |
| CORS Protection | Whitelisted origins only |

---

## 🏗️ Architecture

```
                    ┌──────────────┐
                    │   Client     │
                    │ (Browser/CLI)│
                    └──────┬───────┘
                           │ HTTP Request
                    ┌──────▼───────┐
                    │   FastAPI    │
                    │  Port :8000  │
                    └──────┬───────┘
                           │ Task Queue
                    ┌──────▼───────┐
                    │    Redis     │
                    │  Port :6379  │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │   Celery     │
                    │   Worker     │
                    └──────┬───────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    ┌────▼────┐      ┌─────▼─────┐     ┌─────▼─────┐
    │ Recon   │──────│  Scanner  │─────│   Risk    │
    │ Module 1│      │  Module 2 │     │  Module 3 │
    └─────────┘      └───────────┘     └─────┬─────┘
                                             │
                                       ┌─────▼─────┐
                                       │  Report   │
                                       │  Module 4 │
                                       └───────────┘
```

### Data Flow

```
Target → [Recon] → scan_context
                       ↓
                  [Scanner] → scan_context (updated)
                       ↓
                  [Risk Scorer] → scan_context (updated)
                       ↓
                  [Report Gen] → HTML Report + JSON
```

---

## 🧪 Testing

```bash
cd backend
pytest modules/ -v
```

**Test Results:**

```
modules/recon/tests/                   21 passed
modules/scanner/tests/                 12 passed
modules/risk_scorer/tests/              8 passed
modules/report_generator/tests/         6 passed
─────────────────────────────────────────────────
TOTAL                                  47 passed
```

Run with coverage:

```bash
pytest modules/ -v --cov=modules --cov-report=html
```

---

## 📡 API Documentation

### Base URL: `http://localhost:8000`

### Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/health` | No | Health check |
| `GET` | `/health/ready` | No | Redis/Celery connection status |
| `POST` | `/scans` | Yes | Start a new VAPT scan |
| `GET` | `/scans/{scan_id}` | Yes | Get scan status and progress |
| `GET` | `/scans/{scan_id}/report` | Yes | Get scan report (JSON/HTML) |
| `GET` | `/scans` | Yes | List all scans (paginated) |

### Authentication

All scan endpoints require an API key:

```
Header: X-API-Key: vapt_sk_your_api_key_here
```

### Example Request

```bash
curl -X POST http://localhost:8000/scans \
  -H "X-API-Key: vapt_sk_0123456789abcdef0123456789abcdef" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "scan_type": "full"}'
```

### Example Response

```json
{
  "scan_id": "0aa7695c-ca68-4304-8a25-bc2f8b8a1908",
  "status": "pending",
  "target": "example.com",
  "message": "Scan started for example.com. Check status with GET /scans/0aa7695c-ca68-4304-8a25-bc2f8b8a1908"
}
```

### Interactive Docs

Visit `http://localhost:8000/docs` for the Swagger UI where you can test all endpoints directly from the browser.

---

## 🔒 Security Features

| Feature | Implementation |
|---------|---------------|
| API Key Authentication | Constant-time comparison via `secrets.compare_digest()` |
| CORS Protection | Whitelisted origins only |
| Rate Limiting | Configurable via environment variable (default: 10 req/min) |
| Security Headers | X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy |
| Input Sanitization | Blocks semicolons, pipes, ampersands, dollar signs, backticks, parentheses, braces, angle brackets, newlines in user input |
| Server Header Masking | Custom server header, X-Powered-By removed |
| Request Logging | IP, method, path, status, duration logged (no API keys in logs) |
| Error Handling | Graceful degradation across all modules |

---

## 📦 Tech Stack

| Category | Technology | Version |
|----------|-----------|---------|
| Language | Python | 3.11+ |
| Web Framework | FastAPI | 0.104+ |
| ASGI Server | Uvicorn | 0.24+ |
| Task Queue | Celery | 5.3+ |
| Message Broker | Redis | 7.0+ |
| HTTP Client | httpx | 0.25+ |
| DNS | dnspython | 2.4+ |
| WHOIS | python-whois | 0.8+ |
| Testing | pytest | 7.4+ |
| Async Testing | pytest-asyncio | 0.21+ |
| PDF (optional) | weasyprint | 60+ |

---

## 📁 Project Structure

```
vapt-framework/
│
├── backend/
│   ├── modules/
│   │   ├── recon/                    # Module 1: Reconnaissance
│   │   │   ├── __init__.py
│   │   │   ├── data_normalizer.py
│   │   │   ├── dns_enumerator.py
│   │   │   ├── whois_lookup.py
│   │   │   ├── subdomain_finder.py
│   │   │   ├── reverse_dns.py
│   │   │   ├── recon_orchestrator.py
│   │   │   └── tests/
│   │   │
│   │   ├── scanner/                  # Module 2: Unified Scanner
│   │   │   ├── __init__.py
│   │   │   ├── data_contracts.py
│   │   │   ├── http_scanner.py
│   │   │   ├── port_scanner.py
│   │   │   ├── service_detector.py
│   │   │   ├── vuln_matcher.py
│   │   │   ├── cve_database.json
│   │   │   ├── scan_orchestrator.py
│   │   │   └── tests/
│   │   │
│   │   ├── risk_scorer/              # Module 3: Risk Scoring
│   │   │   ├── __init__.py
│   │   │   ├── data_contracts.py
│   │   │   ├── cvss_scorer.py
│   │   │   ├── risk_calculator.py
│   │   │   ├── risk_orchestrator.py
│   │   │   └── tests/
│   │   │
│   │   └── report_generator/         # Module 4: Report Generation
│   │       ├── __init__.py
│   │       ├── data_contracts.py
│   │       ├── html_templates.py
│   │       ├── report_builder.py
│   │       ├── pdf_generator.py
│   │       ├── report_orchestrator.py
│   │       └── tests/
│   │
│   ├── api/                          # Module 5: REST API
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── middleware/
│   │   │   ├── __init__.py
│   │   │   ├── auth.py
│   │   │   └── security.py
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   └── schemas.py
│   │   └── routes/
│   │       ├── __init__.py
│   │       ├── health.py
│   │       └── scan.py
│   │
│   ├── tasks/                        # Celery Tasks
│   │   ├── __init__.py
│   │   ├── celery_app.py
│   │   └── scan_task.py
│   │
│   ├── full_pipeline_demo.py         # CLI demo script
│   └── reports/                      # Generated reports
│
├── requirements.txt                  # Python dependencies
├── .env.example                      # Environment template
├── .gitignore                        # Git ignore rules
├── LICENSE                           # MIT License
└── README.md                         # This file
```

---

## 🎯 Use Cases

- **Security Researchers** — Automate reconnaissance and scanning workflows
- **Penetration Testers** — Generate professional assessment reports
- **Bug Bounty Hunters** — Quick initial target assessment
- **DevOps Teams** — Integrate as CI/CD security gate
- **Students** — Learn cybersecurity automation and tool building

---

## 📊 Sample Report Output

When you run a scan, the HTML report includes:

- **Executive Summary** — Risk level, score, top recommendations
- **Security Score Card** — Visual grade circle (A+ to F) with color coding
- **Severity Breakdown** — Critical, High, Medium, Low counts
- **Detailed Findings** — Each issue with CVSS score, description, affected asset, remediation steps
- **Open Ports Table** — Port number, protocol, state, service, version
- **DNS Records Table** — All enumerated record types with values
- **Discovered Subdomains** — From Certificate Transparency logs

---

## ⚠️ Disclaimer

This tool is designed for **authorized security testing only**. Always obtain written permission before scanning any target you do not own. The author assumes no liability for misuse or damage caused by this tool.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with dedication for the security community**

⭐ Star this repo if you find it useful!

</div>
