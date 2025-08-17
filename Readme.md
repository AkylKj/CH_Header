# 🛡️ Security Header Checker

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-0.0.1-orange.svg)]()
[![Wiki](https://img.shields.io/badge/Wiki-Roadmap-brightgreen.svg)](https://github.com/AkylKj/CH_Header/wiki/Roadmap)

**A powerful CLI tool for analyzing website security headers and providing detailed security assessments**

[Русский](README.ru.md) | [English](README.md)

</div>

---

## 🚀 Features

- ✅ **Security Header Analysis** - Check 7+ critical security headers
- ✅ **Colorful CLI Output** - Beautiful terminal interface with colors
- ✅ **Multiple Export Formats** - Save results in TXT, JSON, CSV
- ✅ **Advanced CLI Options** - Custom timeout, User-Agent, SSL verification
- ✅ **Verbose Mode** - Detailed information and recommendations
- ✅ **Security Scoring** - Percentage-based security assessment
- ✅ **Error Handling** - Robust error handling and validation

## 📋 Supported Security Headers

| Header | Description | Score |
|--------|-------------|-------|
| **Strict-Transport-Security** | Enforces HTTPS usage | 10 |
| **Content-Security-Policy** | Prevents XSS and data injection | 15 |
| **X-Frame-Options** | Protection against clickjacking | 8 |
| **X-Content-Type-Options** | Prevents MIME-sniffing | 5 |
| **X-XSS-Protection** | Protection against XSS attacks | 5 |
| **Referrer-Policy** | Controls referrer information | 3 |
| **Permissions-Policy** | Controls browser features access | 4 |

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup
```bash
# Clone the repository
git clone https://github.com/AkylKj/CH_Header
cd security-header-checker

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## 🎯 Usage

### Basic Usage
```bash
# Check a website
python main.py https://example.com

# Verbose output
python main.py https://example.com --verbose

# Save results to file
python main.py https://example.com --output report.txt
```

### Advanced Options
```bash
# Custom timeout and User-Agent
python main.py https://example.com --timeout 30 --user-agent "MyBot/1.0"

# Disable redirects and SSL verification
python main.py https://example.com --no-redirects --no-verify-ssl

# Export to different formats
python main.py https://example.com --output report.json
python main.py https://example.com --output report.csv
```

### All Available Options
```bash
python main.py --help
```

## 📊 Example Output

```
🔍 Checking the security of the site: https://google.com

📊 Security Check Results:
URL: https://google.com
Total Score: 35/50
Security Percentage: 70.0%

📋 Detailed Report:
------------------------------------------------------------
Strict-Transport-Security:
  Value: max-age=31536000; includeSubDomains; preload
  Status: ✅ GOOD
  Description: ✅ Enforces the use of HTTPS
  Score: 10

Content-Security-Policy:
  Value: object-src 'none';base-uri 'self';script-src 'nonce-...
  Status: ✅ GOOD
  Description: ✅ Content security policy to prevent XSS and data injection attacks
  Score: 15

📈 Summary:
✅ Well configured: 5
❌ Issues: 2
ℹ️ Info: 0

⚠️ Average security
```

## 🔧 CLI Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--verbose` | `-v` | Verbose output | False |
| `--output` | `-o` | Output file path | None |
| `--timeout` | `-t` | Request timeout (seconds) | 10 |
| `--user-agent` | `-u` | Custom User-Agent | Chrome 120.0.0.0 |
| `--follow-redirects` | `-f` | Follow HTTP redirects | True |
| `--no-redirects` | `-n` | Disable redirects | False |
| `--max-redirects` | | Max redirects to follow | 5 |
| `--verify-ssl` | | Verify SSL certificates | True |
| `--no-verify-ssl` | | Disable SSL verification | False |
| `--version` | `-V` | Show version | - |

## 📁 Project Structure

```
security-header-checker/
├── main.py                 # Main CLI application
├── requirements.txt        # Python dependencies
├── README.md              # This file (English)
├── README.ru.md           # Russian documentation
├── [📋 Roadmap Wiki](https://github.com/AkylKj/CH_Header/wiki/Roadmap)  # Development roadmap
└── src/
    ├── __init__.py
    ├── header_checker.py  # Security header analysis
    └── exporter.py        # Export functionality
```

## 🎨 Export Formats

### TXT Format
Human-readable text report with detailed analysis and recommendations.

### JSON Format
Structured data for programmatic processing and integration.

### CSV Format
Tabular data suitable for spreadsheet analysis and reporting.

## 🚀 Roadmap

See our [📋 Development Roadmap](https://github.com/AkylKj/CH_Header/wiki/Roadmap) for detailed development plans and upcoming features.

### Upcoming Features
- 🔄 Mass website checking
- 📈 HTML reports with charts
- 🔔 Monitoring and notifications
- 🌐 Web interface
- 🔌 Plugin system

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">


</div>
