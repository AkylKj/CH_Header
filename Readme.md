# 🛡️ Security Header Checker

> Powerful CLI tool for analyzing website security headers

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-0.0.1-orange.svg)]()

[Русский](README.ru.md) | [English](README.md)

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


