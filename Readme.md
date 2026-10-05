# 🛡️ Security Header Checker

> Powerful CLI tool for analyzing website security headers

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/Version-0.0.5-orange.svg)](ROADMAP.md)

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

## v0.0.5: installation and behavior

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


Example:

```bash
python main.py https://example.com --follow-redirects --verbose --output report.json
```

Only changes, links, version references and diff formatting were reviewed for
v0.0.5. Automated tests and runtime checks were not run at the user's request.

## Changes in 0.0.5

**Framing protection:** the existing X-Frame-Options record now assesses enforced
CSP frame-ancestors or fallback XFO. Its original value is retained; parsed.source
identifies the effective control. The maximum remains 8: empty lists/none/self
and specific HTTP(S) sources earn 8, broad schemes/wildcards earn 4, and invalid
values earn 0. Another policy cannot weaken a restrictive enforced policy; the
complete intersection is not computed. Report-Only and default-src do not replace
frame-ancestors. XFO cannot bypass an enforced frame-ancestors directive.

Without enforced frame-ancestors, only exact DENY/SAMEORIGIN values earn credit.
Identical repeated values are accepted; conflicting values receive no credit.

**Informational headers:** X-Requested-With, X-UA-Compatible and X-XSS-Protection
remain in reports as INFO, with zero score and applicable=false. Presence and
absence have no rating impact. Their former combined weight of 7 is removed
from the denominator. X-XSS-Protection: 0 is not a weakness; the tool no longer
recommends enabling the deprecated browser XSS filter.

**Shared HTTP response:** header and response analysis use one detached snapshot
with separate repeated values, final URL, status, time to receive headers and
redirect chain. One GET operation can include allowed redirects; the final body
is not read. Transport failures are recorded in each selected HTTP module without
fetching again. Analysis failures and TLS remain independent. Response results
now include final_url; existing CLI options and CSV columns are preserved.

Rule-set/scoring-model versioning was not added. Percentages across releases
are not directly comparable. Only source, links, version references and diff
formatting were reviewed; the program and tests were not run for v0.0.5 at the
user's request.

## 📋 Supported Headers

| Header | Description | Score |
|--------|-------------|-------|
| **Strict-Transport-Security** | Enforces HTTPS usage | 10 |
| **Content-Security-Policy** | XSS and injection protection | 15 |
| **X-Frame-Options** | Effective CSP or XFO framing protection | 8 |
| **X-Content-Type-Options** | Prevents MIME-sniffing | 5 |
| **X-XSS-Protection** | Deprecated filter, informational only | — |
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


