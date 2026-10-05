# 🛡️ Security Header Checker

> Powerful CLI tool for analyzing website security headers

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/Version-0.0.4-orange.svg)](ROADMAP.md)

[Русский](README.ru.md) | [English](Readme.md)

## ✨ Features

- 🔒 **Security Header Analysis** - Check 15+ critical security headers
- 🚀 **Bulk Checking** - Parallel processing of multiple sites
- 🔐 **SSL/TLS Analysis** - Detailed certificate and encryption analysis
- 📡 **Response Analysis** - HTTP status codes and server information
- 🎨 **Beautiful Output** - Colorful terminal interface
- 💾 **Export Results** - TXT, JSON, CSV formats

## 🚀 Quick Start

```bash
# Installation
pip install -r requirements.txt

# Check single site
python main.py https://example.com

# Bulk checking
python main.py --file urls.txt --parallel 5

# Full analysis
python main.py https://example.com --ssl-check --response-analysis
```

## v0.0.4: installation and behavior

Target support: Python 3.10–3.14. Use an isolated environment:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py --version
```

On Linux use `.venv/bin/python -m pip install -r requirements.txt`.

`--ssl-only` and `--response-only` select only that module and are mutually exclusive.
`--batch-size` bounds each group of sites; `--parallel` bounds worker threads.
Timeout and numeric limits must be positive. Redirects are disabled by default;
use `--follow-redirects` to enable them. `--no-verify-ssl` affects HTTP requests
only; TLS analysis always validates certificate trust and hostname independently.

TXT displays enabled checks, JSON preserves the entire composed report, and CSV
uses URL, Module, Check, Value, Status, Score, Error columns. Partial reports
are exported even when one module fails. Exit codes: 0 for successful checks
and export, 1 for check/export failures, 2 for invalid arguments.

Scores are project heuristics, not an industry standard or a full audit.
CSP/HSTS/cookies use structured rules; other headers still use basic matching. UNKNOWN TLS probes are inconclusive;
only the negotiated cipher suite is inspected. Untrusted certificate details
may be displayed without granting verified status.

Tests, pytest configuration and the test CI workflow were removed at the
user's request. Automated checks are not included in the current checkout.

## Changes in 0.0.4

- **HSTS: 0/5/10 points.** Invalid, repeated or zero max-age and HSTS over
  HTTP earn 0; less than one year earns 5; at least one year earns 10.
  includeSubDomains and preload are optional, independently reported settings.
- **CSP: up to 15 points.** Up to 9 for script restrictions, plus 3 each
  for object-src and base-uri. Evaluation considers directive fallback,
  nonce/hash and strict-dynamic, without verifying page content or nonce entropy.
  Report-only is diagnostic. Multiple enforced policies are parsed separately;
  their combined effect is not assessed, so CSP becomes INFO and is excluded
  from the denominator. Individual policy findings are not conclusions about
  combined protection.
- **Cookies: up to 4 points.** Each Set-Cookie field is assessed separately;
  the worst applicable cookie determines the score. Missing Secure earns 0;
  missing/invalid SameSite caps the score at 2; missing HttpOnly caps it at 3.
  SameSite=None with Secure is valid. JavaScript-readable cookies may intentionally
  omit HttpOnly. Missing cookies and valid deletion cookies are not penalised.

GOOD means compliance with these rules; WARNING indicates a weakness or contextual
warning; BAD identifies invalid configuration or dangerous/insufficient permissions;
INFO provides an explanation or indicates no overall assessment. Inapplicable
checks are excluded from max_score; a zero denominator displays N/A. Scores across
versions or applicability sets are not directly comparable.

Existing JSON fields are retained, with final_url, header_values, percentage and findings /
parsed / applicable metadata added; cookie results include a cookies list.
CLI, TXT and CSV display reasons and recommendations. CSV columns are unchanged;
individual cookie rows contain names and ordinal numbers. No new CLI flags.

Example:

```bash
python main.py https://example.com --follow-redirects --verbose --output report.json
```

Only changes, links, version references and diff formatting were reviewed for
v0.0.4. Automated tests and runtime checks were not run at the user's request.

## 📋 Supported Headers

| Header | Description | Score |
|--------|-------------|-------|
| **Strict-Transport-Security** | Enforces HTTPS usage | 10 |
| **Content-Security-Policy** | XSS and injection protection | 15 |
| **X-Frame-Options** | Clickjacking protection | 8 |
| **X-Content-Type-Options** | Prevents MIME-sniffing | 5 |
| **X-XSS-Protection** | XSS attack protection | 5 |
| **Referrer-Policy** | Controls referrer information | 3 |
| **Permissions-Policy** | Browser features access control | 4 |
| **Server** | Web server information | 2 |
| **X-Powered-By** | Site technologies | 2 |
| **Cache-Control** | Caching policy | 3 |
| **Set-Cookie** | Cookie security | 4 |
| **Clear-Site-Data** | Data clearing policy | 3 |
| **Cross-Origin-Embedder-Policy** | Cross-origin embedder policy | 3 |
| **Cross-Origin-Opener-Policy** | Cross-origin opener policy | 3 |
| **Cross-Origin-Resource-Policy** | Cross-origin resource policy | 3 |

## 📖 Documentation

- [Development Roadmap](ROADMAP.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Submit a Pull Request


